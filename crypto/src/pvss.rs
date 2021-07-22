use crate::{Commitment, DleqProof, SingleDleqProof, Encryptions, Scalar, Secret, 
    Share, 
    ark_serde::{
        canonical_deserialize, 
        canonical_serialize
    }
};
use ark_ec::{AffineCurve, PairingEngine};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PVSSVec<E> 
where E: PairingEngine,
{
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub comms: Vec<Commitment<E>>, 

    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub encs: Vec<Encryptions<E>>,

    #[serde(bound(serialize = "DleqProof<E::G1Projective, E::G2Projective, Scalar<E>>: Serialize"))]
    #[serde(bound(deserialize = "DleqProof<E::G1Projective, E::G2Projective, Scalar<E>>: Deserialize<'de>"))]
    pub proofs: Vec<DleqProof<E::G1Projective, E::G2Projective, Scalar<E>>>,

    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub gs: E::G2Projective,

    #[serde(bound(serialize = "SingleDleqProof<<Commitment<E> as AffineCurve>::Projective, Scalar<E>>: Serialize"))]
    #[serde(bound(deserialize = "SingleDleqProof<<Commitment<E> as AffineCurve>::Projective, Scalar<E>>: Deserialize<'de>"))]
    pub sig_of_knowledge: SingleDleqProof<<Commitment<E> as AffineCurve>::Projective, Scalar<E>>
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatePVSS<E> 
where E: PairingEngine,
{
    /// encs contains the combined encryptions c := (c1, c2, ..., cn)
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub encs: Vec<Encryptions<E>>,

    /// comms contains the combined commitments v := (v1, v2, ..., vn)
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub comms: Vec<Commitment<E>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompositionProof<E> 
where E: PairingEngine,
{
    /// indices of the nodes whose shares we have combined
    pub indices: Vec<usize>,
    /// A vector of dleq proofs for all constituent vi and ci for [n]
    #[serde(bound(serialize = "SingleDleqProof<<Commitment<E> as AffineCurve>::Projective, Scalar<E>>: Serialize"))]
    #[serde(bound(deserialize = "SingleDleqProof<<Commitment<E> as AffineCurve>::Projective, Scalar<E>>: Deserialize<'de>"))]
    pub dleq_proof: Vec<SingleDleqProof<<Commitment<E> as AffineCurve>::Projective, Scalar<E>>>,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub gs_vec: Vec<<Commitment<E> as AffineCurve>::Projective>,
}

/// Decryption data structure that holds the decrypted share in G1 and 
/// [OPTIMIZATIONS] - proof of correct decryption (a DLEQ proof) to save pairing computations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decryption<E> 
where E: PairingEngine,
{
    /// The decrypted share
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub dec: Share<E>,
    /// The proof that this share was decrypted correctly
    #[serde(bound(serialize = "DleqProof<E::G1Projective, E::G2Projective, Scalar<E>>: Serialize"))]
    #[serde(bound(deserialize = "DleqProof<E::G1Projective, E::G2Projective, Scalar<E>>: Deserialize<'de>"))]
    pub proof: DleqProof<E::G1Projective, E::G1Projective, Scalar<E>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Beacon<E> 
where E: PairingEngine,
{
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub beacon: Secret<E>,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub value: E::G1Projective,
}