use crate::ark_serde::{canonical_deserialize, canonical_serialize, ArkToSerde};
use crate::hash::ser_and_hash;
pub use ark_bls12_381::Bls12_381;
pub use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
pub use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
pub use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};
pub use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
pub use std::{error::Error, fmt};

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
pub type Commitment = G2;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Proof {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub a: G2,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub r: Scalar,
}

pub struct Keypair (pub SecretKey, pub PublicKey);

pub fn std_rng() -> StdRng {
    StdRng::from_entropy()
}

pub fn generate_keypair<R>(rng: &mut R) -> Keypair
where
    R: Rng + ?Sized,
{
    let secret = Scalar::rand(rng);
    Keypair
    (
        secret,
        G1::prime_subgroup_generator().mul(secret).into_affine(),
    )
}

pub fn generate_proof<R>(s: Scalar, gs: G2, rng: &mut R) -> Proof
where
    R: Rng + ?Sized,
{
    let w = Scalar::rand(rng);
    let a = G2::prime_subgroup_generator().mul(w).into_affine();
    let mut rngs: StdRng = SeedableRng::from_seed(ser_and_hash(&(ArkToSerde(gs), ArkToSerde(a))));
    let c = Scalar::rand(&mut rngs);
    Proof { a, r: s + c * w }
}

pub fn verify_proof(gs: G2, proof: Proof) -> bool {
    let mut rng: StdRng =
        SeedableRng::from_seed(ser_and_hash(&(ArkToSerde(gs), ArkToSerde(proof.a))));
    let c = Scalar::rand(&mut rng);
    G2::prime_subgroup_generator().mul(proof.r).into_affine() == gs + proof.a.mul(c).into_affine()
}

pub fn generate_shares<R>(
    n: usize,
    t: usize,
    public_keys: &[PublicKey],
    rng: &mut R,
) -> (Secret, Vec<Share>, Vec<Commitment>, Vec<Proof>)
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
        .map(|i| polynomial.evaluate(&Scalar::from(i as u64 + 1)))
        .collect();
    let commitments: Vec<G2> = (0..n)
        .map(|i| {
            G2::prime_subgroup_generator()
                .mul(evaluations[i])
                .into_affine()
        })
        .collect();
    let proof: Vec<Proof> = (0..n)
        .map(|i| generate_proof(evaluations[i], commitments[i], rng))
        .collect();
    (
        Bls12_381::pairing(
            G1::prime_subgroup_generator().mul(secret_scalar),
            G2::prime_subgroup_generator(),
        ),
        (0..n)
            .map(|i| public_keys[i].mul(evaluations[i]).into_affine())
            .collect(),
        commitments,
        proof,
    )
}

pub fn aggregate(
    n: usize,
    t: usize,
    shares: &Vec<Vec<Share>>,
    commitments: &Vec<Vec<Commitment>>,
    proof: &Vec<Vec<Proof>>,
) -> (Vec<Share>, Vec<Commitment>, Vec<Vec<Proof>>) {
    (
        (0..n)
            .map(|i| (0..t).fold(G1::zero(), |acc, j| acc + shares[j][i]))
            .collect(),
        (0..n)
            .map(|i| (0..t).fold(G2::zero(), |acc, j| acc + commitments[j][i]))
            .collect(),
        (0..n)
            .map(|i| (0..t).map(|j| proof[j][i]).collect())
            .collect(),
    )
}

pub fn verify<R>(
    n: usize,
    t: usize,
    public_keys: &[PublicKey],
    shares: &[Share],
    commitments: &[Commitment],
    private_commitments: &[Commitment],
    private_proof: &[Proof],
    rng: &mut R,
) -> bool
where
    R: Rng + ?Sized,
{
    for i in 0..n {
        if Bls12_381::pairing(shares[i], G2::prime_subgroup_generator())
            != Bls12_381::pairing(public_keys[i], commitments[i])
        {
            return false;
        }
    }
    let vec: Vec<Scalar> = (0..n - t - 1).map(|_| Scalar::rand(rng)).collect();
    let polynomial = Polynomial::from_coefficients_vec(vec);
    let ind: Vec<_> = (0..n).map(|i| (i, Scalar::from(i as u64 + 1))).collect();
    let codeword: Vec<Scalar> = ind
        .iter()
        .map(|&(i, scalar_i)| {
            ind.iter()
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
        .map(|i| commitments[i].mul(codeword[i]))
        .fold(G2P::zero(), |acc, c| acc + c)
        != G2P::zero()
    {
        return false;
    }
    for i in 0..t {
        if !verify_proof(private_commitments[i], private_proof[i]) {
            return false;
        }
    }
    true
}

pub fn decrypt_share(secret_key: SecretKey, share: Share) -> Share {
    share.mul(secret_key.inverse().unwrap()).into_affine()
}

pub fn verify_share(decrypted_share: Share, commitment: Commitment) -> bool {
    Bls12_381::pairing(decrypted_share, G2::prime_subgroup_generator())
        == Bls12_381::pairing(G1::prime_subgroup_generator(), commitment)
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
    use crate::fsbp::*;

    const N: usize = 16;
    const T: usize = 12;

    #[test]
    fn verify_proof_test() {
        let rng = &mut std_rng();
        let s = Scalar::rand(rng);
        let gs = G2::prime_subgroup_generator().mul(s).into_affine();
        assert!(verify_proof(gs, generate_proof(s, gs, rng)));
    }

    #[test]
    fn fsbp_test() {
        let rng = &mut std_rng();
        let keys: Vec<_> = (0..N).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..N).map(|i| keys[i].1).collect();
        let messages: Vec<_> = (0..T)
            .map(|_| generate_shares(N, T, &public_keys, rng))
            .collect();
        let aggr = aggregate(
            N,
            T,
            &messages.iter().map(|m| m.1.clone()).collect(),
            &messages.iter().map(|m| m.2.clone()).collect(),
            &messages.iter().map(|m| m.3.clone()).collect(),
        );
        for i in 0..N {
            assert!(verify(
                N,
                T,
                &public_keys,
                &aggr.0,
                &aggr.1,
                &messages.iter().map(|m| m.2[i]).collect::<Vec<_>>(),
                &aggr.2[i],
                rng
            ));
        }
    }
}
