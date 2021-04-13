use fnv::FnvHashMap as HashMap;
use super::Block;
use crate::Height;
use crypto::hash::Hash;
use std::sync::Arc;

// TODO: Use storage
pub struct Storage {
    pub all_delivered_blocks_by_hash: HashMap<Hash, Arc<Block>>,
    pub all_delivered_blocks_by_ht: HashMap<Height, Arc<Block>>,
    pub committed_blocks_by_ht: HashMap<Height, Arc<Block>>,
    pub committed_blocks_by_hash: HashMap<Hash, Arc<Block>>,
}

impl Storage {
    /// The space parameter cannot be used in FnvHashMap implementation
    /// Creates a newly initialized storage container to store all the context
    pub fn new(_space: usize) -> Self {
        Storage {
            all_delivered_blocks_by_hash: HashMap::default(),
            all_delivered_blocks_by_ht: HashMap::default(),
            committed_blocks_by_hash: HashMap::default(),
            committed_blocks_by_ht: HashMap::default(),
        }
    }
}
