use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataWithAcc {
    pub sign: Vec<u8>,
    pub tree: Vec<Vec<u8>>,
    pub size: Replica,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedData {
    pub sign: Vec<u8>,
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