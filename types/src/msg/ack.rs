use crate::{Epoch, Proof, RespCertProposal};
use crypto::hash::Hash;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone, Builder)]
pub struct AckData {
    e: Epoch,
    prop_hash: Hash,
    proof: Proof<RespCertProposal>,
}

impl AckData {
    pub fn epoch(&self) -> &Epoch {
        &self.e
    }

    pub fn prop_hash(&self) -> &Hash {
        &self.prop_hash
    }

    pub fn proof(&self) -> &Proof<RespCertProposal> {
        &self.proof
    }
}