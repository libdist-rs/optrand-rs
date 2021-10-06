use fnv::FnvHashMap as HashMap;
use super::Block;
use crate::{Height, PVSSVec, Replica};
use crypto::hash::Hash;
use std::{collections::VecDeque, sync::Arc};
use crate::AggregatePVSS;

// TODO: Use storage
#[derive(Default)]
pub struct Storage {
    /// The delivered blocks referred by hash
    all_delivered_blocks_by_hash: HashMap<Hash, Arc<Block>>,
    /// The delivered blocks referred by height
    all_delivered_blocks_by_ht: HashMap<Height, Arc<Block>>,

    /// The committed blocks referred by the height
    committed_blocks_by_ht: HashMap<Height, Arc<Block>>,
    /// The committed blocks referred by hash
    committed_blocks_by_hash: HashMap<Hash, Arc<Block>>,

    /// A map containing the hash of the block to its proposer
    proposer_map: HashMap<Hash, Replica>,

    /// Store Aggregate PVSS for every replica
    /// Here, we add an Aggregate PVSS in epoch e for replica i, to be used the next time replica i becomes a leader again
    rand_beacon_queue: HashMap<Replica, VecDeque<AggregatePVSS>>,

    /// When I am a leader, I will need to have t+1 sharings ready
    /// Anytime from the last time I was a leader to the next time I am a leader, I may receive t+1 sharings
    /// Delete the queue if the queue becomes empty when consuming
    next_proposal_pvss_sharings: HashMap<Replica, VecDeque<PVSSVec>>,

    /// Every round I need to send some shares
    /// This buffer contains those shares
    round_shares: VecDeque<PVSSVec>,
}

impl Storage {
    /// The space parameter cannot be used in FnvHashMap implementation
    /// Creates a newly initialized storage container to store all the context
    pub fn new(space: usize) -> Self {
        Self {
            round_shares: VecDeque::with_capacity(space),
            ..Default::default()
        }
    }

    /// Adds a block to the storage
    /// This block is now delivered
    pub fn add_delivered_block(&mut self, b: Block) {
        let b_arc = Arc::new(b);
        self.all_delivered_blocks_by_hash.insert(
            b_arc.hash().clone(), b_arc.clone());
        self.all_delivered_blocks_by_ht.insert(b_arc.height(), b_arc);
    }

    /// Adds a block to the list of committed blocks
    pub fn commit_block(&mut self, b_arc: Arc<Block>) {
        self.committed_blocks_by_hash.insert(
            b_arc.hash().clone(), b_arc.clone());
        self.committed_blocks_by_ht.insert(b_arc.height(), b_arc);
    }

    pub fn add_new_leader_sharing(&mut self) {}
    pub fn add_new_self_sharing(&mut self) {}

    pub fn get_delivered_block_by_hash(&self, hash: &Hash) -> Option<&Block> {
        self.all_delivered_blocks_by_hash.get(hash).map(|v| v.as_ref())
    }

    pub fn get_delivered_block_by_height(&self, ht: Height) -> Option<&Block> {
        self.all_delivered_blocks_by_ht.get(&ht).map(|v| v.as_ref())
    }
}
