use crypto::{hash::{Hash, EMPTY_HASH}};
use serde::{Deserialize, Serialize};
use crate::{Height, AggregatePVSS};
use types_upstream::WireReady;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub parent_hash: Hash,
    pub height: Height,
    /// We devaite from the main protocol here due to the optimization
    /// By the time it is the node's turn to propose it would have already sent the (v,c) and the corresponding decomposition proof to all the nodes, so we include the hash of (v,c) here. The deliver will take care of delivering if it is not already delivered.
    pub aggregate_pvss: AggregatePVSS,

    /// The hash of the block, do not serialize, init will update it automatically
    #[serde(skip)]
    pub hash: Hash,
}

impl Block {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let c: Block = bincode::deserialize(&bytes).expect("failed to decode the block");
        return c.init();
    }

    /// Compute the hash of the block, it does not set the block hash
    pub fn compute_hash(&self) -> Hash {
        crypto::hash::ser_and_hash(self)
    }

    /// Returns a new block with empty parent hash, height 0, empty hash, and an empty certificate
    pub fn new(agg: AggregatePVSS) -> Self {
        Block {
            height: 0,
            parent_hash: EMPTY_HASH,
            hash: EMPTY_HASH,
            aggregate_pvss: agg,
        }
    }
}

pub const GENESIS_BLOCK: Block = Block {
    hash: EMPTY_HASH,
    height: 0,
    parent_hash: EMPTY_HASH,
    aggregate_pvss: AggregatePVSS{
        comms: vec![],
        encs: vec![],
    },
};

impl types_upstream::WireReady for Block {
    /// After receiving a block from the network update the hash first
    fn init(mut self) -> Self {
        self.hash = self.compute_hash();
        self
    }

    fn from_bytes(data: &[u8]) -> Self {
        Block::from_bytes(data)
    }

    fn to_bytes(self: &Self) -> Vec<u8> {
        bincode::serialize(self).expect(format!("Failed to serialize {:?}", self).as_str())
    }
}
