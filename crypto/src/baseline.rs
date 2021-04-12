pub use ark_bls12_381::Bls12_381;
pub use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
pub use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
pub use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};
pub use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{error::Error, fmt};

pub type Scalar = <Bls12_381 as PairingEngine>::Fr;
pub type Polynomial = DensePolynomial<Scalar>;
pub type G1 = <Bls12_381 as PairingEngine>::G1Affine;
pub type G2 = <Bls12_381 as PairingEngine>::G2Affine;
pub type G1P = <Bls12_381 as PairingEngine>::G1Projective;
pub type G2P = <Bls12_381 as PairingEngine>::G2Projective;
pub type GT = <Bls12_381 as PairingEngine>::Fqk;

pub type SecretKey = Scalar;
pub type PublicKey = G1;
pub type Secret = GT;
pub type Share = G1;
pub type Proof = G2;

pub fn std_rng() -> StdRng {
    StdRng::from_entropy()
}

pub fn generate_keypair<R>(rng: &mut R) -> (SecretKey, PublicKey)
where
    R: Rng + ?Sized,
{
    let secret = Scalar::rand(rng);
    (
        secret,
        G1::prime_subgroup_generator().mul(secret).into_affine(), //pk = g^s
    )
}

pub fn generate_shares<R>(
    n: usize,
    t: usize,
    public_keys: &[PublicKey],
    rng: &mut R,
) -> (Secret, Vec<Share>, Vec<Proof>)
where
    R: Rng + ?Sized,
{
    let secret_scalar = Scalar::rand(rng);
    let vec: Vec<Scalar> = (0..t)
        .map(|i| {
            if i == 0 {
                secret_scalar
            } else {
                Scalar::rand(rng)
            }
        })
        .collect();
    let polynomial = Polynomial::from_coefficients_vec(vec);
    let evaluations: Vec<Scalar> = (0..n)
        .map(|i| polynomial.evaluate(&Scalar::from(i as u64 + 1))) // Can be parallelized
        .collect();
    (
        Bls12_381::pairing(
            G1::prime_subgroup_generator().mul(secret_scalar),
            G2::prime_subgroup_generator(),
        ),
        (0..n)
            .map(|i| public_keys[i].mul(evaluations[i]).into_affine())
            .collect(),
        (0..n)
            .map(|i| {
                G2::prime_subgroup_generator()
                    .mul(evaluations[i])
                    .into_affine()
            })
            .collect(),
    )
}

pub fn generate_rand_shares<R>(
    n: usize,
    t: usize,
    public_keys: &[PublicKey],
    rng: &mut R,
) -> (Vec<Share>, Vec<Proof>)
where
    R: Rng + ?Sized,
{
    let vec: Vec<Scalar> = (0..t)
        .map(|_i| {
            Scalar::rand(rng)
        })
        .collect();
    let polynomial = Polynomial::from_coefficients_vec(vec);
    let evaluations: Vec<Scalar> = (0..n)
        .map(|i| polynomial.evaluate(&Scalar::from(i as u64 + 1)))
        .collect();
    (
        (0..n)
            .map(|i| public_keys[i].mul(evaluations[i]).into_affine())
            .collect(),// pk_i^{p(i)} for i in [n]
        (0..n)
            .map(|i| {
                G2::prime_subgroup_generator()
                    .mul(evaluations[i])
                    .into_affine()
            })
            .collect(), // g^p(i) for i in [n]
    )
}

#[derive(Debug)]
pub enum VerifyError {
    PairingDoesNotMatch,
    CodewordCheckFailed,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl Error for VerifyError {
    fn description(&self) -> &str {
        match self {
            VerifyError::PairingDoesNotMatch => "Pairing does not match",
            VerifyError::CodewordCheckFailed => "Codeword check failed",
        }
    }
}

pub fn pverify<R>(
    n: usize,
    t: usize,
    public_key: &[PublicKey],
    share: &[Share],
    proof: &[Proof],
    rng: &mut R,
) -> Result<(), VerifyError>
where
    R: Rng + ?Sized,
{
    for id in 0..n {
        if Bls12_381::pairing(share[id], G2::prime_subgroup_generator())
        != Bls12_381::pairing(public_key[id], proof[id]) // e(c_j, h) != e(pk, v_j)
        {
            return Result::Err(VerifyError::PairingDoesNotMatch);
        }
    }
    let vec: Vec<Scalar> = (0..n - t - 1).map(|_| Scalar::rand(rng)).collect();
    let polynomial = Polynomial::from_coefficients_vec(vec);
    let indices: Vec<_> = (0..n).map(|i| (i, Scalar::from(i as u64 + 1))).collect();
    let codeword: Vec<Scalar> = indices
        .iter()
        .map(|&(i, scalar_i)| {
            indices
                .iter()
                .map(|&(j, scalar_j)| {
                    if j == i {
                        Scalar::one()
                    } else {
                        (scalar_i - scalar_j).inverse().unwrap()
                    }
                })
                .fold(Scalar::one(), |v, x| v * x)
                * polynomial.evaluate(&scalar_i)
        })
        .collect();
    if (0..n)
        .map(|i| proof[i].mul(codeword[i]))
        .fold(G2P::zero(), |acc, c| acc + c)
        != G2P::zero()
    {
        return Result::Err(VerifyError::CodewordCheckFailed);
    }
    Result::Ok(())
}

pub fn decrypt_share(secret_key: SecretKey, share: Share) -> Share {
    share.mul(secret_key.inverse().unwrap()).into_affine()
}

pub fn verify_share(decrypted_share: Share, proof: Proof) -> Result<(), VerifyError> {
    if Bls12_381::pairing(decrypted_share, G2::prime_subgroup_generator())
        == Bls12_381::pairing(G1::prime_subgroup_generator(), proof)
    {
        Result::Ok(())
    } else {
        Result::Err(VerifyError::PairingDoesNotMatch)
    }
}

pub fn reconstruct(n: usize, decrypted_shares: &[Option<Share>]) -> Secret {
    let valid_share_indices: Vec<_> = (0..n)
        .filter(|&i| decrypted_shares[i].is_some())
        .map(|i| (i, Scalar::from(i as u64 + 1)))
        .collect();
    let secret = valid_share_indices
        .iter()
        .map(|&(i, scalar_i)| {
            decrypted_shares[i].unwrap().mul(
                valid_share_indices
                    .iter()
                    .map(|&(j, scalar_j)| {
                        if j == i {
                            Scalar::one()
                        } else {
                            scalar_j * (scalar_j - scalar_i).inverse().unwrap()
                        }
                    })
                    .fold(Scalar::one(), |lambda, x| lambda * x),
            )
        })
        .fold(G1::zero().into_projective(), |acc, x| acc + x)
        .into_affine();
    Bls12_381::pairing(secret, G2::prime_subgroup_generator())
}

#[cfg(test)]
mod tests {

    use crate::baseline::*;

    const N: usize = 16;
    const T: usize = 12;

    #[test]
    fn test_verify() {
        let rng = &mut std_rng();
        let keys: Vec<(SecretKey, PublicKey)> = (0..N).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..N).map(|i| keys[i].1).collect();
        let (_, shares, proof) = generate_shares(N, T, &public_keys, rng);
        pverify(N, T, &public_keys, &shares, &proof, rng).unwrap()
    }

    #[test]
    fn test_verify_failure() {
        let rng = &mut std_rng();
        let keys: Vec<(SecretKey, PublicKey)> = (0..N).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..N).map(|i| keys[i].1).collect();
        let (_, _, proof) = generate_shares(N, T, &public_keys, rng);
        let shares:Vec<_> = (0..N).map(|_i| {
            G1::prime_subgroup_generator()
            .mul(Scalar::rand(rng))
            .into_affine()
        }).collect();
        let _: VerifyError = pverify(
                    N,
                    T,
                    &public_keys,
                    &shares,
                    &proof,
                    rng,
                )
                .err()
                .unwrap();
    }

    #[test]
    fn test_verify_share() {
        let rng = &mut std_rng();
        let keys: Vec<(SecretKey, PublicKey)> = (0..N).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..N).map(|i| keys[i].1).collect();
        let (_, shares, proof) = generate_shares(N, T, &public_keys, rng);
        let decrypted_shares: Vec<Share> = (0..N)
            .map(|i| decrypt_share(keys[i].0, shares[i]))
            .collect();
        let _: Vec<()> = (0..N)
            .map(|i| verify_share(decrypted_shares[i], proof[i]).unwrap())
            .collect();
        let _: Vec<VerifyError> = (1..N)
            .map(|i| verify_share(decrypted_shares[i], proof[0]).err().unwrap())
            .collect();
    }

    #[test]
    fn test_reconstruct() {
        let rng = &mut std_rng();
        let keys: Vec<(SecretKey, PublicKey)> = (0..N).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..N).map(|i| keys[i].1).collect();
        let (secret, shares, _) = generate_shares(N, T, &public_keys, rng);
        let mut decrypted_shares: Vec<_> = (0..N)
            .map(|i| Some(decrypt_share(keys[i].0, shares[i])))
            .collect();
        for i in 0..N - T {
            decrypted_shares[i] = None;
        }
        assert_eq!(reconstruct(N, &decrypted_shares), secret);
    }
}
