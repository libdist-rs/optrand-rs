use std::sync::Arc;
use types::{Certificate, PVSSVec, ProtocolMsg, Replica, Result, START_EPOCH, Vote};

use crate::{OptRandStateMachine, OutMsg};

impl OptRandStateMachine {
    pub fn new_status_msg(&mut self) -> OutMsg {
        (
            self.leader(), 
            Arc::new(
                ProtocolMsg::Status(
                    self.highest_certified_data().clone(),
                    self.highest_certificate().clone(), 
                    self.config.pvss_ctx.generate_shares(
                        &self.sk, 
                        &mut self.rng
                    )
                )
            )
        )
    }

    pub fn new_status_msg_leader(&mut self) -> (Vote, Certificate<Vote>, PVSSVec) {
        (
            self.highest_certified_data().clone(),
            self.highest_certificate().clone(), 
            self.config.pvss_ctx.generate_shares(
                &self.sk, 
                &mut self.rng
            )
        )
    }

    pub fn verify_status(&mut self, from: Replica, vote: &Vote, cert: &Certificate<Vote>, pvec: &PVSSVec) -> Result<()> {
        // Prevent duplicated vertification everytime
        if vote.epoch() != START_EPOCH {
            cert.buffered_is_valid(vote, &self.pk_map, &mut self.storage)?;
            if cert.len() != self.config.num_faults + 1 {
                log::warn!("Invalid num of sigs: Expected: {}, Got {}", self.config.num_faults+1,cert.len());
                return Err(
                    format!("Status verification").into()
                );
            }
        }
        if let Some(e) = self.config.pvss_ctx.verify_sharing(pvec, &self.pk_map[&from]) {
            return Err(format!("DBSError: {:?}", e).into());
        }
        Ok(())
    }

    pub fn on_verified_status(&mut self, from: Replica, vote: Vote, cert: Certificate<Vote>, pvec: PVSSVec) -> Result<()> {
        if self.rnd_ctx.num_beacon_shares() == self.config.num_faults + 1 {
            log::info!("Ready to propose");
        } else {
            log::info!("Adding a PVSS Vec from {}", from);
            self.rnd_ctx.add_round_share(from, pvec);
        }
        // DONE: Update highest certificate
        if vote.higher_than(self.highest_certified_data()) {
            log::info!("Updating from {} to a higher epoch cert {}", self.highest_certified_data().epoch(), vote.epoch());
            self.update_highest_cert(vote, cert)?;
        }
        Ok(())
    }
}