use fnv::FnvHashMap as HashMap;
use super::Block;
use crate::{Height, Replica};
use crypto::hash::Hash;
use std::sync::Arc;

// TODO: Use storage
pub struct Storage {
    pub all_delivered_blocks_by_hash: HashMap<Hash, Arc<Block>>,
    pub all_delivered_blocks_by_ht: HashMap<Height, Arc<Block>>,
    pub committed_blocks_by_ht: HashMap<Height, Arc<Block>>,
    pub committed_blocks_by_hash: HashMap<Hash, Arc<Block>>,
    pub proposer_map: HashMap<Hash, Replica>,
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
            proposer_map: HashMap::default(),
        }
    }

    /// Adds a block to the storage
    pub fn add_new_block(&mut self, b: Block) {
        let b_arc = Arc::new(b);
        self.all_delivered_blocks_by_hash.insert(b_arc.hash, b_arc.clone());
        self.all_delivered_blocks_by_ht.insert(b_arc.height, b_arc);
    }

    /// Adds a block to the list of committed blocks
    pub fn commit_new_block(&mut self, b_arc: Arc<Block>) {
        self.committed_blocks_by_hash.insert(b_arc.hash, b_arc.clone());
        self.committed_blocks_by_ht.insert(b_arc.height, b_arc);
    }
}
