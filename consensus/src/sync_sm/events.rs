use crate::{EventQueue, events::{Event, TimeOutEvent}};
use super::OptRandStateMachine;
use types::Result;

impl OptRandStateMachine {
    pub(crate) fn on_new_event(&mut self, 
        ev: Event, 
        ev_queue: &mut EventQueue, 
    ) -> Result<()> 
    {
        match ev {
            Event::TimeOut(tout_ev) => {
                self.on_new_timeout_event(
                    tout_ev,   
                    ev_queue, 
                )
            }
            Event::Message(from, msg) => {
                self.on_new_msg_event(
                    from, 
                    msg, 
                    ev_queue, 
                )
            }
            Event::NewEpoch(e) => {
                self.on_new_epoch_event(
                    e, 
                    ev_queue, 
                )
            }
            Event::OptimizerEvent(x) => {
                self.on_optimizer_event(x, ev_queue)
            }
            // _ => unimplemented!(),
        }
    }

    pub(crate) fn on_new_timeout_event(&mut self, ev: TimeOutEvent, ev_queue: &mut EventQueue) -> Result<()> {
        match ev {
            TimeOutEvent::EpochTimeOut(e) => {
                log::info!("Epoch {} finished", e);
                self.on_new_epoch(ev_queue)
            },
            TimeOutEvent::ProposeWaitTimeOut(e) => {
                log::info!("Epoch {} ready to propose", e);
                self.on_propose_timeout(ev_queue)
            }
            TimeOutEvent::StopAcceptingProposals(e) => {
                log::info!("Stop Accepting new proposals for {}", e);
                self.stop_accepting_proposals(e)
            }
            TimeOutEvent::SyncVoteWaitTimeOut(e, prop_hash) => {
                log::info!("Ready to do sync voting for {}", e);
                self.try_sync_vote(e, prop_hash, ev_queue)
            }
            TimeOutEvent::StopSyncCommit(e) => {
                log::info!("Stop accepting sync certs for {}", e);
                self.stop_accepting_sync_certs(e)
            }
            TimeOutEvent::Commit(e, prop_hash) => {
                log::info!("Time to commit in {}", e);
                self.try_commit(e,prop_hash)
            }
            _ => unimplemented!("Handling for {:?}", ev),
        }
    }

    pub(crate) fn _on_equivocation(&mut self, 
        _ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        unimplemented!()
    }
}