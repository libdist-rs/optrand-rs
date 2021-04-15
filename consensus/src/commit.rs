use std::time::Duration;

use tokio_util::time::DelayQueue;
use types::Block;
use std::sync::Arc;

use crate::{context::Context, events::Event};

impl Context {
    pub async fn do_responsive_commit(&mut self, dq: &mut DelayQueue<Event>) {
        if self.responsive_timeout {
            return;
        }
        if self.equivocation_detected {
            return;
        }
        // Commit block and all its ancestors
        self.commit_all();
    }

    pub async fn start_sync_commit(&mut self, dq: &mut DelayQueue<Event>) {
        if self.sync_commit_timeout {
            return;
        }
        if self.started_sync_timer {
            return;
        }
        dq.insert(Event::SyncTimer, Duration::from_millis(self.delta()*2));
        self.started_sync_timer = true;
    }

    pub async fn try_sync_commit(&mut self, dq: &mut DelayQueue<Event>) {
        if self.sync_commit_timeout {
            return;
        }
        if self.equivocation_detected {
            return;
        }
        self.commit_all();
    }

    /// Commit current epoch and all its ancestors
    fn commit_all(&mut self) {
        let b = self.epoch_block_lock.take()
        .expect("Unexpected, since we must have locked a block before starting the sync timer");
        self.commit_from_block(b)
        
    }

    pub(crate) fn commit_from_block(&mut self, mut b: Arc<Block>) {
        self.storage.commit_new_block(b.clone());
        while !self.storage.committed_blocks_by_hash.contains_key(&b.parent_hash) {
            let pblk = self.storage.all_delivered_blocks_by_hash[&b.parent_hash].clone();
            self.storage.committed_blocks_by_hash.insert(pblk.hash, pblk.clone());
            self.storage.committed_blocks_by_ht.insert(pblk.height, pblk.clone());
            b = pblk;
        }
        // Add stuff to our data structures here
        
    }
}