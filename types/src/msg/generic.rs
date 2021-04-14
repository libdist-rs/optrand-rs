use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataWithAcc {
    /// Signature on the root of the merkle tree for whatever data you are sending
    pub sign: Certificate,
    pub tree: Vec<Vec<u8>>,
    pub size: Replica,
}

/// This is the shard for the accumulator
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedShard {
    pub sign: Certificate,
    pub start: Vec<u8>,
    pub index: Replica,
    pub chain: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeliveredData {
    // pub commit: EVSSCommit381,
    // pub shares: EVSSShare381,
    pub sign: Vec<u8>,
}