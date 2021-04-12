use crate::{Commitment, Encryptions, G1, G2, Scalar, DbsError, ark_serde::{
    canonical_deserialize, 
    canonical_serialize, 
}};
use crate::hash::ser_and_hash;
pub use ark_bls12_381::Bls12_381;
pub use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
pub use ark_ff::{Field, One, PrimeField, UniformRand, Zero, FromBytes};
pub use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};
pub use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
pub use std::{error::Error, fmt};
use ark_ff::to_bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DleqProof {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub a1: Encryptions,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub a2: Commitment,
    /// Multiple Challenges for every discrete log
    /// We can use a single puzzle if only puzzle is required
    /// But for our case, we need to combine the shares, so a single challenge cannot be used.
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub c: Scalar,
    /// Responses
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub r: Scalar,
    /// Signatures
    /// These are used to pin the proof to the node creating the sharing
    /// This is necessary for the decomposition checks to go through
    pub sig: Vec<u8>, 
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DleqProofSameG1 {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub a1: G1,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub a2: G1,
    /// Multiple Challenges for every discrete log
    /// We can use a single puzzle if only puzzle is required
    /// But for our case, we need to combine the shares, so a single challenge cannot be used.
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub c: Scalar,
    /// Responses
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub r: Scalar,
    /// Signatures
    /// These are used to pin the proof to the node creating the sharing
    /// This is necessary for the decomposition checks to go through
    pub sig: Vec<u8>, 
}


pub struct Dleq{}

impl Dleq {
    pub fn prove<R>(knowledge: &Scalar,
        g: &G1,
        x: &G1,
        h: &G2,
        y: &G2,
        my_key: &crypto_lib::Keypair,
        rng: &mut R
    ) -> DleqProof
    where
        R: Rng + ?Sized,
    {
        let w = Scalar::rand(rng);
        let (a1,a2) = (g.mul(w).into_affine(), h.mul(w).into_affine());
        let mut buf = Vec::new();
        buf.append(&mut to_bytes!(a1).unwrap()); // a1
        buf.append(&mut to_bytes!(a2).unwrap()); // a2
        buf.append(&mut to_bytes!(x).unwrap()); // x
        buf.append(&mut to_bytes!(y).unwrap()); // y
        let hash = ser_and_hash(&buf);
        let mut rngs: StdRng = SeedableRng::from_seed(hash);
        let c = Scalar::rand(&mut rngs);
        let r = w - c * knowledge;
        let sig = my_key.sign(&hash).unwrap();
        DleqProof {
            a1, a2, r, c, sig,
        }
    }

    /// prove_same generates discrete log equality proofs for elements of the same group
    pub fn prove_same_g1<R>(knowledge: &Scalar,
        g: &G1,
        x: &G1,
        h: &G1,
        y: &G1,
        my_key: &crypto_lib::Keypair,
        rng: &mut R
    ) -> DleqProofSameG1
    where
        R: Rng + ?Sized,
    {
        let w = Scalar::rand(rng);
        let (a1,a2) = (g.mul(w).into_affine(), h.mul(w).into_affine());
        let mut buf = Vec::new();
        buf.append(&mut to_bytes!(a1).unwrap()); // a1
        buf.append(&mut to_bytes!(a2).unwrap()); // a2
        buf.append(&mut to_bytes!(x).unwrap()); // x
        buf.append(&mut to_bytes!(y).unwrap()); // y
        let hash = ser_and_hash(&buf);
        let mut rngs: StdRng = SeedableRng::from_seed(hash);
        let c = Scalar::rand(&mut rngs);
        let r = w - c * knowledge;
        let sig = my_key.sign(&hash).unwrap();
        DleqProofSameG1 {
            a1, a2, r, c, sig,
        }
    }

    pub fn verify(
        pi: &DleqProof,
        g: &G1,
        x: &G1,
        h: &G2,
        y: &G2,
        dss_pk: &crypto_lib::PublicKey,
    ) -> Option<DbsError>
    {
        // Check if the challenge is correct
        let mut buf = Vec::new();
        buf.append(&mut to_bytes!(pi.a1).unwrap());
        buf.append(&mut to_bytes!(pi.a2).unwrap());
        buf.append(&mut to_bytes!(x).unwrap());
        buf.append(&mut to_bytes!(y).unwrap());
        let hash = ser_and_hash(&buf);
        let mut rngs: StdRng = SeedableRng::from_seed(hash);
        let c = Scalar::rand(&mut rngs);
        if c != pi.c {
            return Some(DbsError::InvalidChallenge);
        }
        // Check if the response is correct
        if !dss_pk.verify(&hash, &pi.sig) {
            return Some(DbsError::InvalidSignature);
        }
        if pi.a1 != g.mul(pi.r) + x.mul(c) {
            return Some(DbsError::LeftCheckFailed);
        }
        if pi.a2 != h.mul(pi.r) + y.mul(c) {
            return Some(DbsError::RightCheckFailed);
        }
        None
    }

    pub fn verify_same_g1(
        pi: &DleqProofSameG1,
        g: &G1,
        x: &G1,
        h: &G1,
        y: &G1,
        dss_pk: &crypto_lib::PublicKey,
    ) -> Option<DbsError>
    {
        // Check if the challenge is correct
        let mut buf = Vec::new();
        buf.append(&mut to_bytes!(pi.a1).unwrap());
        buf.append(&mut to_bytes!(pi.a2).unwrap());
        buf.append(&mut to_bytes!(x).unwrap());
        buf.append(&mut to_bytes!(y).unwrap());
        let hash = ser_and_hash(&buf);
        let mut rngs: StdRng = SeedableRng::from_seed(hash);
        let c = Scalar::rand(&mut rngs);
        if c != pi.c {
            return Some(DbsError::InvalidChallenge);
        }
        // Check if the response is correct
        if !dss_pk.verify(&hash, &pi.sig) {
            return Some(DbsError::InvalidSignature);
        }
        if pi.a1 != g.mul(pi.r) + x.mul(c) {
            return Some(DbsError::LeftCheckFailed);
        }
        if pi.a2 != h.mul(pi.r) + y.mul(c) {
            return Some(DbsError::RightCheckFailed);
        }
        None
    }
}