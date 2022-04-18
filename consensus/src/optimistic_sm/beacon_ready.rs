use std::sync::Arc;
use types::{Beacon, Epoch, ProtocolMsg, Result};
use crate::{OutMsg, ev_queue::EventQueue, events::{Event, NewMessage}};

use super::OptRandStateMachine;

impl OptRandStateMachine {
    /// Called when we generate a beacon from reconstruction
    pub(crate) fn on_beacon_ready(&self, 
        e: Epoch, 
        beacon: Beacon,
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        let msg = self.beacon_ready_msg(e, beacon.clone());
        ev_queue.send_msg(msg);
        ev_queue.add_event(
            Event::Message(
                self.config.id, 
                NewMessage::BeaconReady(
                    e, beacon
                )
            )
        );
        Ok(())
    }

    fn beacon_ready_msg(&self, e: Epoch, beacon: Beacon) -> OutMsg {
        (
            self.config.num_nodes,
            Arc::new(ProtocolMsg::BeaconReady(e, beacon)),
        )
    }

    pub(crate) fn verify_beacon_ready(&self, 
        _e: Epoch, 
        _beacon: &Beacon
    ) -> Result<()> 
    {
        // todo!()
        log::warn!("Unimplemented beacon ready verification");
        Ok(())
    }

    pub(crate) fn on_verified_beacon(&self, 
        _e: Epoch, 
        _b: Beacon,
    ) -> Result<()> {
        log::warn!("Unimplemented beacon ready handling");
        Ok(())
    }
}