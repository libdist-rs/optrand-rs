use std::sync::Arc;
use types::{Certificate, PVSSVec, ProtocolMsg, Replica, Result, START_EPOCH, Vote};

use crate::{Event, NewMessage, OutMsg, ThreadSendMsg, TimeOutEvent, ev_queue::EventQueue};
use super::OptRandStateMachine;

impl OptRandStateMachine {
    fn status_msg(&mut self, 
        shares: PVSSVec, 
        highest_cert_data: Vote, 
        highest_cert: Certificate<Vote>,
    ) -> OutMsg {
        (
            self.leader_ctx.current_leader(), 
            Arc::new(
                ProtocolMsg::Status(
                    highest_cert_data,
                    highest_cert,
                    shares,
                )
            )
        )
    }

    pub fn verify_status(&mut self, 
        from: Replica, 
        vote: &Vote, 
        cert: &Certificate<Vote>, 
        pvec: PVSSVec
    ) -> Result<()> {
        // Prevent duplicated vertification everytime
        // Don't verify if we already have the latest certificate 
        if !self.highest_certified_data().higher_than(vote) {
            if vote.epoch() != START_EPOCH {
                cert.buffered_is_valid(vote, &self.pk_map, &mut self.storage)?;
                if cert.len() != vote.num_sigs(self.config.num_nodes) {
                    log::warn!("Invalid num of sigs: Expected: {}, Got {}", vote.num_sigs(self.config.num_nodes),cert.len());
                    return Err(
                        format!("Status verification").into()
                    );
                }
            }
        }

        self.leader_thread_sender
            .send(ThreadSendMsg::NewContribution(
                from, pvec
            ))
            .map_err(|e| format!("Sending error: {}", e))?;
        Ok(())
    }

    pub fn on_verified_status(&mut self, 
        _from: Replica, 
        vote: Vote, 
        cert: Certificate<Vote>, 
        // pvec: PVSSVec
    ) -> Result<()> {
        // self.rnd_ctx.add_round_share(
        //     from, 
        //     &self.config.pvss_ctx,
        //     &self.pk_map,
        //     pvec, 
        //     self.config.num_faults
        // )?;
        if vote.higher_than(self.highest_certified_data()) {
            log::info!("Updating from {} to a higher epoch cert {}", self.highest_certified_data().epoch(), vote.epoch());
            self.update_highest_cert(vote, cert)?;
        }
        Ok(())
    }

    pub(crate) fn on_status(&mut self,
        ev_queue: &mut EventQueue,
    ) -> Result<()> 
    {
        let shares = self.config.pvss_ctx.generate_shares(&self.sk, &mut self.rng);
        let highest_cert_data = self.highest_certified_data().clone();
        let highest_cert = self.highest_certificate().clone();
        if self.leader_ctx.is_leader(self.config.id) {
            ev_queue.add_timeout(
                TimeOutEvent::ProposeWaitTimeOut(self.epoch), 
                self.x_delta(2),
                self.epoch,
            );
            self.leader_thread_sender.send(
                ThreadSendMsg::NewContribution(self.config.id, shares)
            ).map_err(|e| format!("Sending error: {}", e))?;
            ev_queue.add_event(
                Event::Message(
                    self.config.id, 
                    NewMessage::Status(
                        highest_cert_data, 
                        highest_cert, 
                    )
                )
            );
        } else {
            log::info!("Sending status message");
            let msg = self.status_msg(
                shares, 
                highest_cert_data, 
                highest_cert
            );
            ev_queue.send_msg(msg);
        }
        Ok(())
    }
}