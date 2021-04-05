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
        G1::prime_subgroup_generator().mul(secret).into_affine(),
    )
}

pub fn generate_proof<R>(s: Scalar, gs: G2, rng: &mut R) -> Proof
where
    R: Rng + ?Sized,
{
    let w = Scalar::rand(rng);
    let a = G2::prime_subgroup_generator().mul(w).into_affine();
    let c = Scalar::from_random_bytes(&ser_and_hash(&(ArkToSerde(gs), ArkToSerde(a)))).unwrap();
    Proof { a: a, r: s + c * w }
}

pub fn verify_proof(gs: G2, proof: Proof) -> bool {
    let c = Scalar::from_random_bytes(&ser_and_hash(&(ArkToSerde(gs), ArkToSerde(proof.a)))).unwrap();
    G2::prime_subgroup_generator().mul(proof.r).into_affine() == gs + proof.a.mul(c).into_affine()
}

pub fn generate_shares<R>(
    n: usize,
    t: usize,
    public_keys: &[PublicKey],
    rng: &mut R,
) -> (Secret, Vec<Share>, Vec<Commitment>)
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
