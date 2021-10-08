use types::{Epoch, Result};

use crate::{Event, EventQueue, MsgBuf, NewMessage, OptRandStateMachine, TimeOutEvent};

impl OptRandStateMachine {
    /// Update the epoch
    pub fn next_epoch(&mut self) {
        self.epoch += 1;
    } 

    /// Used to fast forward the epoch to a higher epoch
    pub fn set_epoch(&mut self, e: Epoch) {
        self.epoch = e;
    }

    pub fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    /// WARNING: Must be called only after epoch timeout
    pub(crate) fn on_new_epoch(&mut self, ev_queue: &mut EventQueue, msg_buf: &mut MsgBuf) -> Result<()> {
        self.next_epoch();
        self.rnd_ctx.reset(self.config.num_nodes);
        log::info!("Starting epoch {}", self.current_epoch());

        ev_queue.add_timeout(
            TimeOutEvent::EpochTimeOut(self.epoch), 
            self.x_delta(11)
        );

        ev_queue.add_timeout(
            TimeOutEvent::StopAcceptingProposals(self.epoch), 
            self.x_delta(4),
        );

        ev_queue.add_timeout(
            TimeOutEvent::StopSyncCommit(self.epoch), 
            self.x_delta(8)
        );
        
        if self.is_leader() {
            ev_queue.add_timeout(
                TimeOutEvent::ProposeWaitTimeOut(self.epoch), 
                self.x_delta(2),
            );
            let (vote, cert, pvec) = self.new_status_msg_leader();
            ev_queue.add_event(
                Event::Message(
                    self.config.id, 
                    NewMessage::Status(
                        vote, 
                        cert, 
                        pvec)
                    )
            );
        } else {
            log::info!("Sending status message");
            let msg = self.new_status_msg();
            msg_buf.push_back(msg);
        }
        Ok(())
    }
}