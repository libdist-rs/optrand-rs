use std::time::Duration;

use crypto::hash::ser_and_hash;
use tokio_util::time::DelayQueue;
use types::{Block, Epoch};
use std::sync::Arc;

use crate::{context::Context, events::Event};

impl Context {
    pub async fn do_responsive_commit(&mut self, dq: &mut DelayQueue<Event>) {
        log::info!("Responsively committing a block");
        if self.responsive_timeout {
            return;
        }
        if self.equivocation_detected {
            return;
        }
        // Commit block and all its ancestors
        self.commit_all();
        // Start reconstruction
        self.do_reconstruction(self.epoch, dq).await;
    }

    /// Tries to start the sync commit timers
    /// Make sure this is executed only once
    pub async fn start_sync_commit(&mut self, e: Epoch, dq: &mut DelayQueue<Event>) {
        if self.sync_commit_timeout {
            return;
        }
        if self.started_sync_timer {
            return;
        }
        dq.insert(Event::SyncTimer(e), Duration::from_millis(self.delta()*2));
        self.started_sync_timer = true;
    }

    pub async fn try_sync_commit(&mut self, dq: &mut DelayQueue<Event>) {
        if self.sync_commit_timeout {
            return;
        }
        if self.equivocation_detected {
            return;
        }
        // Check if we already committed for this epoch
        self.commit_all();
        log::info!("Check if called only once");
    }

    /// Commit current epoch and all its ancestors
    fn commit_all(&mut self) {
        if self.highest_committed_block.height > self.epoch {
            return;
        }
        let b = self.epoch_block_lock.take()
        .expect("Unexpected, since we must have locked a block before starting the sync timer");
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
        let hash = ser_and_hash(&b.aggregate_pvss);
        self.config.sharings.insert(hash, b.aggregate_pvss.clone());
        let mut queue = self.config.rand_beacon_queue.remove(&proposer).unwrap();
        queue.push_back(hash);
        self.config.rand_beacon_queue.insert(proposer, queue);
    }
}