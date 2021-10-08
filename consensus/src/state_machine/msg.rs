use std::sync::Arc;

use crate::OptRandStateMachine;
use types::{Certificate, PVSSVec, Proposal, ProtocolMsg, Replica, Result, error::Error};

impl OptRandStateMachine {
    pub fn build_beacon_ready(&self) -> Result<ProtocolMsg> {
        let beacon = self.latest_beacon
            .as_ref()
            .ok_or(Error::BuilderUnsetField("beacon"))?
            .clone();
        Ok(ProtocolMsg::BeaconReady(self.epoch, beacon))
    }
}