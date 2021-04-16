use std::sync::Arc;
use tokio_util::time::DelayQueue;
use crate::{Context, Event};
use types::{ProtocolMsg, Epoch};
use tokio::time::Duration;


impl Context {
    /// Reacts to a new epoch
    /// When we have a new epoch, do the following:
    /// 1) Send a new PVSS vector to the current leader
    /// 2a) If leader, start making an aggregate block and propose the block
    /// 2b) If not, wait for a block from the leader, and use timeouts appropriately
    pub fn new_epoch(&mut self, e:Epoch, dq: &mut DelayQueue<Event>) {
        if self.epoch != e {
            return;
        }
        log::debug!("Epoch {} ended, waiting for another epoch", self.epoch);
        self.epoch += 1;
        // Commit block from epoch e-t
        // if self.epoch > self.num_faults() {
        //     let cb = self.storage.all_delivered_blocks_by_ht[&(self.epoch-self.num_faults())].clone();
        //     self.commit_from_block(cb);
        // }
        // Reset variables for this epoch
        self.epoch_reset();
        // self.epoch_timer = self.epoch_timer + tokio::time::Duration::from_millis(11*self.config.delta);
        dq.insert(Event::EpochEnd(self.epoch), Duration::from_millis(11*self.config.delta));
        dq.insert(Event::ProposeTimeout, Duration::from_millis(4*self.config.delta));
        dq.insert(Event::ResponsiveCommitTimeout, Duration::from_millis(9*self.config.delta));
        // Update leader of this epoch
        self.last_leader = self.next_leader();
        log::debug!("Sending PVSS Vector to the next leader {}", self.last_leader);

        log::debug!("Setting current round {} vector from Q for {}",self.epoch, self.last_leader);
        let mut queue = self.config.rand_beacon_queue.remove(&self.last_leader).unwrap();
        let pvec_hash = queue.pop_front().unwrap();
        let first_vec = self.config.sharings.get(&pvec_hash).unwrap().clone();
        self.current_round_reconstruction_vector = Some(Arc::new(first_vec));
        self.config.rand_beacon_queue.insert(self.last_leader, queue);
        self.last_reconstruction_round = self.epoch-1;

        // Send a new PVSS vector to the leader
        let pvec = self.config.pvss_ctx.generate_shares(&self.my_secret_key, &mut crypto::std_rng());

        // If I am not the leader send a fresh sharing to the current leader
        if self.last_leader != self.config.id {
            // Send (v,c,\pi)
            self.net_send.send((self.last_leader, 
                Arc::new(
                    ProtocolMsg::RawEpochPVSSSharing(
                        pvec)
                    )
                )
            ).unwrap();
            // Send C_r'(B_l) to the leader
            self.net_send.send(
                (self.last_leader, Arc::new(
                    ProtocolMsg::RawStatus(
                        self.epoch,
                        self.highest_block.height,
                        self.highest_cert.clone()
                    )
                ))
            ).unwrap();
        } else {
            // I am the leader
            self.last_leader_epoch = self.epoch;
            // First push my own sharing to the next proposal
            self.pvss_shares.push(pvec);
            self.pvss_indices.push(self.config.id);
            // Do I need to wait 2\Delta before proposing?
            if self.highest_block.height < self.epoch-1 {
                dq.insert(Event::Propose, Duration::from_millis(self.config.delta*2));
                return;
            }
            // Do I already have the latest status message? ANS: yes
            self.do_propose(dq);
        }

        while let Some((sender,msg)) = self.get_future_messages(self.epoch) {
            self.handle_message(sender, msg, dq);
        }
    }
}