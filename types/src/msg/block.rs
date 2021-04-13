use crypto::hash::{Hash, EMPTY_HASH};
use serde::{Deserialize, Serialize};
use crate::{Height, Certificate};
use types_upstream::WireReady;

// #[derive(Serialize, Deserialize, Clone)]
// pub struct Content {
//     pub commits: Vec<crypto::EVSSCommit381>,
//     pub acks: Vec<Vote>,
// }

// impl Content {
//     pub const fn new() -> Self {
//         Content {
//             commits: Vec::new(),
//             acks: Vec::new(),
//         }

//     }

//     pub fn from_bytes(bytes: &[u8]) -> Self {
//         let c: Content = bincode::deserialize(&bytes).expect("failed to decode the content");
//         return c;
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub parent_hash: Hash,
    pub height: Height,

    #[serde(skip_serializing, skip_deserializing)]
    pub hash: Hash,
    pub certificate: Certificate,
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
    pub fn new() -> Self {
        Block {
            height: 0,
            parent_hash: EMPTY_HASH,
            hash: EMPTY_HASH,
            certificate: Certificate::empty_cert(),
        }
    }
}

pub const GENESIS_BLOCK: Block = Block {
    hash: EMPTY_HASH,
    certificate: Certificate::empty_cert(),
    height: 0,
    parent_hash: EMPTY_HASH,
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
}
