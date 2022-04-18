use std::sync::Arc;
use crypto::hash::Hash;
use types::error::Error;
use types::{AckData, AckDataBuilder, Certificate, Epoch, Proof, ProtocolMsg, Replica, RespCertProposal, Result};

use crate::events::{Event, NewMessage};
use crate::OutMsg;
use crate::ev_queue::EventQueue;

use super::OptRandStateMachine;

impl OptRandStateMachine {
    pub(crate) fn stop_accepting_acks(&mut self, e: Epoch) -> Result<()> {
        if e != self.epoch {
            return Err(Error::Generic(format!("Got Stop Accepting Sync Cert timeout for {} in Epoch {}", e, self.epoch)));
        }
        self.rnd_ctx.stop_accepting_acks = true;
        Ok(())
    }

    pub(crate) fn do_ack(&mut self, 
        e: Epoch,
        proof: Proof<RespCertProposal>,
        prop_hash: Hash,
        ev_queue: &mut EventQueue,
    ) -> Result<()>
    {
        let ack = {
            let mut ack = AckDataBuilder::default();
            ack
                .prop_hash(prop_hash)
                .e(e)
                .proof(proof)
                .build()
                .map_err(|err| format!("Builder error: {}", err))?
        };
        let cert = Certificate::new_cert(&ack, self.config.id, &self.sk)?;
        let msg = self.new_ack_msg(ack.clone(), cert.clone());
        ev_queue.send_msg(msg);
        ev_queue.add_event(
            Event::Message(
                self.config.id,
                NewMessage::Ack(ack, cert),
            )
        );
        Ok(())
    }

    fn new_ack_msg(&self, ack: AckData, cert: Certificate<AckData>) -> OutMsg {
        (
            self.config.num_nodes, // SendAll
            Arc::new(ProtocolMsg::Ack(ack, cert))
        )
    }

    pub(crate) fn verify_ack(&mut self, 
        from: Replica, 
        ack: &AckData, 
        cert: &Certificate<AckData>,
    ) -> Result<()>
    {
        if self.rnd_ctx.enough_acks_for_epoch {
            return Ok(());
        }
        if self.rnd_ctx.stop_accepting_acks {
            return Ok(());
        }
        if ack.epoch() != &self.epoch {
            return Err(
                Error::Generic(format!("got an ack for {} in epoch {}", ack.epoch(), self.epoch))
            );
        }
        if !cert.is_vote() {
            return Err(
                format!("Expected only one sig in the certificate").into()
            );
        }
        if !cert.sigs.contains_key(&from) {
            return Err(
                format!("This certificate is not from the sender").into()
            );
        }
        cert.buffered_is_valid(ack, &self.pk_map, &mut self.storage)?;

        if self.storage.is_equivocation_resp_cert(
            self.epoch,
            ack.proof().acc()
        ) 
        {
            return Err(
                format!("Got an equivocation from an ack").into()
            );
        }

        // Check for equivocating proposal in resp cert
        if let Some((_, proof_orig)) = self.storage.prop_from_hash(ack.prop_hash()) {
            if self.storage.is_equivocation_prop(self.epoch, proof_orig.acc()) {
                return Err(Error::EquivocationDetected(self.epoch));
            }
        } else {
            return Err(
                Error::Generic(format!("Delivered a resp cert for an unknown proposal hash"))
            );
        }
        Ok(())
    }

    pub(crate) fn on_verified_ack(&mut self, 
        from: Replica, 
        ack: AckData, 
        _cert: Certificate<AckData>
    ) -> Result<()> {
        if self.rnd_ctx.enough_acks_for_epoch {
            return Ok(());
        }
        if self.rnd_ctx.stop_accepting_acks {
            return Ok(());
        }
        if let Ok(Some(_)) = self.rnd_ctx.add_ack(from, self.config.num_nodes, ack) {
            if self.leader_ctx.is_leader(self.config.id) {
                let perf = self.rnd_ctx.stop_and_measure();
                println!("Optimistic performance: {}", perf.as_micros());
            }
        }
        Ok(())
    }
}