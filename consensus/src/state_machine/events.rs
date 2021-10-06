use std::sync::Arc;

use crate::{EventQueue, OptRandStateMachine, events::{Deliver, Event, NewMessage, TimeOutEvent}};
use types::{ProtocolMsg, Replica, Result};

impl OptRandStateMachine {
    pub fn on_new_event(&mut self, ev: Event, ev_queue: &mut EventQueue) -> Result<Vec<(Replica, Arc<ProtocolMsg>)>> {
        match ev {
            Event::TimeOut(tout_ev) => self.on_new_timeout_event(tout_ev, ev_queue),
            _ => unimplemented!(),
        }
    }

    pub fn on_new_timeout_event(&mut self, ev: TimeOutEvent, ev_queue: &mut EventQueue) -> Result<Vec<(Replica, Arc<ProtocolMsg>)>> {
        match ev {
            TimeOutEvent::EpochTimeOut(e) => {
                log::info!("Epoch {} finished", e);
                Ok(vec![])
            },
            _ => unimplemented!(),
        }
    }

    pub fn on_new_deliver_event(&mut self, ev: Deliver, ev_queue: &mut EventQueue) -> Result<Vec<(Replica, Arc<ProtocolMsg>)>> {
        unimplemented!()
    }

    pub fn on_new_msg(&mut self, ev: NewMessage, ev_queue: &mut EventQueue) -> Result<Vec<(Replica, Arc<ProtocolMsg>)>> {
        unimplemented!()
    }

    pub fn on_commit(&mut self) -> Result<Vec<(Replica, Arc<ProtocolMsg>)>> {
        unimplemented!()
    }

    pub fn on_equivocation(&mut self) -> Result<Vec<(Replica, Arc<ProtocolMsg>)>> {
        unimplemented!()
    }
}