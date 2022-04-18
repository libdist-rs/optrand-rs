use types::{Epoch, Result, START_EPOCH};
use crate::{Event, EventQueue, TimeOutEvent};
use super::OptRandStateMachine;

impl OptRandStateMachine {
    /// Update the epoch
    pub fn next_epoch(&mut self) {
        // Update the leader
        self.leader_ctx.update_leader(self.epoch);
        // Update epoch
        self.epoch += 1;
        // Reset the round context
        self.rnd_ctx.reset(self.config.num_nodes);
    } 

    /// Used to fast forward the epoch to a higher epoch
    pub fn set_epoch(&mut self, e: Epoch) {
        self.epoch = e;
    }

    pub fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    /// WARNING: Must be called only after epoch timeout
    pub(crate) fn on_new_epoch(&mut self, 
        ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        self.next_epoch();
        // if self.epoch == START_EPOCH + 1 {
        //     let now = chrono::Utc::now();
        //     println!("Start time: {}", now);
        // }
        println!("Starting epoch {}", self.current_epoch());

        ev_queue.add_event(
            Event::NewEpoch(self.epoch)
        );
        // Remove the node from future proposals if no block was committed

        ev_queue.add_timeout(
            TimeOutEvent::EpochTimeOut(self.epoch), 
            self.x_delta(11),
            self.epoch,
        );

        ev_queue.add_timeout(
            TimeOutEvent::StopAcceptingProposals(self.epoch), 
            self.x_delta(4),
            self.epoch,
        );

        ev_queue.add_timeout(
            TimeOutEvent::StopSyncCommit(self.epoch), 
            self.x_delta(8),
            self.epoch,
        );

        ev_queue.add_timeout(
            TimeOutEvent::StopAcceptingAck(self.epoch), 
            self.x_delta(9),
            self.epoch,
        );
        
        self.on_status(ev_queue)
    }

    /// Things that should be done on entering a new epoch
    /// See Step 8 in the paper
    pub(crate) fn on_new_epoch_event(&mut self, 
        e: Epoch, 
        ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        // Commit Bl from epoch r-t if highest ranked certificate extends Bl
        if e > START_EPOCH + self.config.num_faults {
            let target_epoch = e - self.config.num_faults;
            // Get block proposed in epoch e-t
            let prop_arc_opt = self.storage
                .get_proposal_from_epoch(
                    &target_epoch
                );
            if let Some(prop_arc) = prop_arc_opt {
                // Check if the highest ranked certificate extends this block
                let target_hash = prop_arc.block().hash();
                // Is Bl already committed
                if let None = self.storage
                        .get_committed_block_by_hash(&target_hash) 
                {
                    // If Bl is not committed, 
                    let mut is_part_of_the_chain = false;
                    for _i in 0..self.config.num_faults+1 {
                        // Go backwards from the highest certificate and see if we hit the proposal
                        let cert_epoch = self.highest_certified_data()
                                                    .epoch();
                        let prop = self.storage
                            .get_proposal_from_epoch(&cert_epoch)
                            .ok_or(
                                format!("Could not find the proposal for the locked certificate")
                            )?;
                        if target_hash == prop.block().hash() {
                            is_part_of_the_chain = true;
                            break;
                        }
                    }
                    
                    if is_part_of_the_chain {
                        log::warn!("Committing Proposal from {} after t epochs in Epoch {}", prop_arc.epoch(), self.epoch);
                        let block = self.storage
                            .get_delivered_block_by_hash(
                                &prop_arc.block()
                                    .hash()
                            ).ok_or(
                                format!("Expected a delivered block to commit in the epoch after t epochs")
                        )?;
                        self.storage.commit_block(block)?;
                    } else {
                        // Not a part of the chain, but we received a proposal
                        // Reject
                        log::warn!("We did not get a proposal for {}; Removing the leader.", target_epoch);
                        self.leader_ctx.remove_leader(target_epoch);
                    }
                } 
                // Bl is already committed, nothing to do!
            } else {
                log::warn!("We did not get a proposal for {}; Removing the leader.", target_epoch);
                self.leader_ctx.remove_leader(target_epoch);
            }
        } 

        // Do beacon business
        self.on_beacon_share(e, ev_queue)
    }
}