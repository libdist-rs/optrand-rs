use std::time::Duration;

use crypto::hash::{ser_and_hash, Hash};
use tokio_util::time::DelayQueue;
use types::{Block, Height};
use std::sync::Arc;

use crate::{context::Context, events::Event};

impl Context {
    pub fn do_responsive_commit(&mut self,bhash: Hash, dq: &mut DelayQueue<Event>) {
        if self.responsive_timeout {
            return;
        }
        if self.equivocation_detected {
            return;
        }
        // Commit block and all its ancestors
        let b = self.storage.all_delivered_blocks_by_hash[&bhash].clone();
        log::debug!("Responsively committing height {} a block", b.height);
        self.commit_from_block(b);
        // Start reconstruction
        self.do_reconstruction(self.epoch, dq);
    }

    /// Tries to start the sync commit timers
    /// Make sure this is executed only once
    pub fn start_sync_commit(&mut self, ht: Height, dq: &mut DelayQueue<Event>) {
        if self.highest_committed_block.height >= ht {
            return;
        }
        if self.sync_commit_timeout {
            return;
        }
        if self.started_sync_timer {
            return;
        }
        dq.insert(Event::SyncTimer(ht), Duration::from_millis(self.delta()*2));
        self.started_sync_timer = true;
    }

    pub fn try_sync_commit(&mut self, ht: Height, _dq: &mut DelayQueue<Event>) {
        if self.highest_committed_block.height >= ht {
            return;
        }
        if self.sync_commit_timeout {
            return;
        }
        if self.equivocation_detected {
            return;
        }
        // Check if we already committed for this epoch
        self.commit_all(ht);
        log::debug!("Check if called only once");
    }

    /// Commit current epoch and all its ancestors
    fn commit_all(&mut self, ht:Height) {
        if self.highest_committed_block.height >= ht {
            return;
        }
        log::debug!("Committing height {}", ht);
        let b = self.storage.all_delivered_blocks_by_ht[&ht].clone();
        self.highest_committed_block = b.clone();
        self.commit_from_block(b)
    }

    pub(crate) fn commit_from_block(&mut self, mut b: Arc<Block>) {
        self.storage.commit_new_block(b.clone());
        self.commit_pvss(&b);
        // Add the block's PVSS contents to the random_beacon_buffer
        while !self.storage.committed_blocks_by_hash.contains_key(&b.parent_hash) {
            let pblk = self.storage.all_delivered_blocks_by_hash[&b.parent_hash].clone();
            self.storage.commit_new_block(pblk.clone());
            self.commit_pvss(&pblk);
            b = pblk;
        }
        // Add stuff to our data structures here
        
    }

    /// Commit_pvss will add the pvss vector to the internal queues
    fn commit_pvss(&mut self, b: &Arc<Block>) {
        let proposer = self.storage.proposer_map[&b.hash];
        log::debug!("Committing proposer {} PVSS block", proposer);
        let hash = ser_and_hash(&b.aggregate_pvss);
        self.config.sharings.insert(hash, b.aggregate_pvss.clone());
        let mut queue = self.config.rand_beacon_queue.remove(&proposer).unwrap();
        queue.push_back(hash);
        self.config.rand_beacon_queue.insert(proposer, queue);
    }
}