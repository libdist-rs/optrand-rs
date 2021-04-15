use crypto::hash::Hash;
use serde::{Serialize, Deserialize};
use crate::Epoch;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AckMsg {
    pub block_hash: Hash,
    pub epoch: Epoch,
}