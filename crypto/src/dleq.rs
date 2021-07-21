use crate::{DbsError, ark_serde::{
    canonical_deserialize, 
    canonical_serialize, 
}};
use crate::hash::ser_and_hash;
pub use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
pub use ark_ff::{Field, One, PrimeField, UniformRand, Zero, FromBytes};
pub use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
pub use std::{error::Error, fmt};
use ark_ff::to_bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DleqProof<G1, G2, S> 
where 
    G1: CanonicalSerialize + CanonicalDeserialize,
    G2: CanonicalSerialize + CanonicalDeserialize,
    S: CanonicalSerialize + CanonicalDeserialize
{
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub a1: G1,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub a2: G2,
    /// Multiple Challenges for every discrete log
    /// We can use a single puzzle if only puzzle is required
    /// But for our case, we need to combine the shares, so a single challenge cannot be used.
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub c: S,
    /// Responses
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub r: S,
    /// Signatures
    /// These are used to pin the proof to the node creating the sharing
    /// This is necessary for the decomposition checks to go through
    pub sig: Vec<u8>, 
}

pub struct Dleq<G1, G2, S>
{
    _x: PhantomData<G1>,
    _y: PhantomData<G2>,
    _z: PhantomData<S>,
}

impl<G1, G2, S> Dleq<G1, G2, S> 
where 
    G1: ProjectiveCurve,
    G2: ProjectiveCurve
        + Copy,
    S: PrimeField 
        + Into<G1::ScalarField>
        + Into<G2::ScalarField>,
{
    pub fn prove<R>(knowledge: &S,
        g: &G1,
        x: &G1,
        h: &G2,
        y: &G2,
        my_key: &crypto_lib::Keypair,
        rng: &mut R
    ) -> DleqProof<G1, G2, S>
    where
        R: Rng + ?Sized,
    {
        let w = S::rand(rng);
        let a1: G1 = g.mul(w.into_repr());
        let a2: G2 = h.mul(w.into_repr());

        let mut buf = Vec::new();
        buf.append(&mut to_bytes!(a1).unwrap()); // a1
        buf.append(&mut to_bytes!(a2).unwrap()); // a2
        buf.append(&mut to_bytes!(x.into_affine()).unwrap()); // x
        buf.append(&mut to_bytes!(y.into_affine()).unwrap()); // y
        let hash = ser_and_hash(&buf);

        let mut rngs: StdRng = SeedableRng::from_seed(hash);
        let c = S::rand(&mut rngs);
        let r = w - c * knowledge;

        let sig = my_key
            .sign(&hash)
            .expect("Failed to sign the DLEQ Proof");
        DleqProof::<G1, G2, S> {
            a1, 
            a2, 
            r, 
            c, 
            sig,
        }
    }

    pub fn verify(
        pi: &DleqProof<G1, G2, S>,
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
        buf.append(&mut to_bytes!(x.into_affine()).unwrap());
        buf.append(&mut to_bytes!(y.into_affine()).unwrap());
        let hash = ser_and_hash(&buf);
        
        let mut rngs: StdRng = SeedableRng::from_seed(hash);
        let c = S::rand(&mut rngs);
        if c != pi.c {
            return Some(DbsError::InvalidChallenge);
        }
        // Check if the response is correct
        if !dss_pk.verify(&hash, &pi.sig) {
            return Some(DbsError::InvalidSignature);
        }
        // .add(x.mul(c))
        if pi.a1 != g.mul(pi.r.into_repr()) + x.mul(c.into_repr()) {
            return Some(DbsError::LeftCheckFailed);
        }
        if pi.a2 != h.mul(pi.r.into_repr()) + y.mul(c.into_repr()) {
            return Some(DbsError::RightCheckFailed);
        }
        None
    }
}