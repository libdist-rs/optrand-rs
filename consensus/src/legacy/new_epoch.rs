use std::collections::VecDeque;

use tokio_util::time::DelayQueue;
use crate::{Context, Event};
use types::{Epoch, PVSSVec, ProtocolMsg, Replica};
use tokio::{sync::oneshot, time::Duration};

impl Context {
    pub fn next(&mut self) {
        // Move to the next round
        self.round_ctx.next();
        self.round_ctx.current_leader = self.next_leader();
    }

    /// Reacts to a new epoch
    /// When we have a new epoch, do the following:
    /// 1) Send a new PVSS vector to the current leader
    /// 2a) If leader, start making an aggregate block and propose the block
    /// 2b) If not, wait for a block from the leader, and use timeouts appropriately
    pub async fn new_epoch(&mut self, e: Epoch, dq: &mut DelayQueue<Event>) {
        if e != self.epoch() {
            log::debug!("Got a stale epoch end event {} in epoch {}", e, self.epoch());
            debug_assert!(e <= self.epoch(), "e must be <= self.epoch()");
            return;
        }
        
        log::debug!("Epoch {} ended, starting the next epoch {}", 
            e, self.epoch()+1);

        self.next();

        // Commit block from epoch e-t
        // if self.epoch() > self.num_faults() {
        //     let to_commit = self.epoch()-self.num_faults();
        //     log::debug!("Committing block from epoch {}", to_commit);
        //     let cb = self
        //         .storage
        //         .all_delivered_blocks_by_ht[&to_commit]
        //         .clone();
        //     self.storage.commit_new_block(cb.clone());
        // }

        // Delete stale timer events
        dq.clear();

        // Add fresh timer events
        dq.insert(
            Event::EpochEnd(self.epoch()), 
            Duration::from_millis(11*self.config.delta)
        );
        if self.leader() == self.id() {
            dq.insert(
                Event::Propose(self.epoch()), 
                Duration::from_millis(2*self.config.delta)
            );
        }
        dq.insert(
            Event::ProposeTimeout(self.epoch()), 
            Duration::from_millis(4*self.config.delta)
        );
        dq.insert(
            Event::ResponsiveCommitTimeout(self.epoch()), 
            Duration::from_millis(9*self.config.delta)
        );

        log::debug!("Sending PVSS Vector to the next leader {}", self.leader());
        let pvec = 
        if let Some(pvec) = self.storage.round_shares.pop_front() {
            pvec
        } else {
            self.sh_out.recv().await.expect("Failed to get shares to send in the round")
        };

        log::debug!("Sending new share to the leader {}", self.leader());
        let msg = ProtocolMsg::RawEpochPVSSSharing(pvec);
        self.send_message(self.leader(), msg);
    }

    pub(crate) async fn new_share(&mut self, sender: Replica, pvec: PVSSVec) {
        let (one_shot_in, one_shot_out) = oneshot::channel();
        let out = self.verified_shares_recv.clone();
        tokio::spawn(async move {
            if let Ok(x) = one_shot_out.await {
                out.send(x).await.unwrap();
            }
        });
        self.sh_verifier.send((sender, pvec, one_shot_in)).await.unwrap();
    }

    pub(crate) async fn new_verified_share(&mut self, sender: Replica, pvec: PVSSVec, dq: &mut DelayQueue<Event>) {
        log::debug!("Got a new verified share from {}", sender);
        let mut queue = if let Some(queue) = self.storage
        .next_proposal_pvss_sharings
        .remove(&sender) {
            queue
        } else {
            VecDeque::new()
        };
        queue.push_back(pvec);
        self.storage.next_proposal_pvss_sharings.insert(sender, queue);

        // Try proposing now
        self.try_propose(self.epoch(), dq).await;
    }

}