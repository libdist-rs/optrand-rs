use std::sync::Arc;
use crate::{Event, EventQueue, NewMessage, OutMsg, TimeOutEvent};
use super::OptRandStateMachine;
use types::{Certificate, Proof, ProofBuilder, ProposalBuilder, ProtocolMsg, Replica, RespCertData, RespCertProposal, Result, Vote, error::Error};
use types_upstream::WireReady;

impl OptRandStateMachine {
    pub(crate) fn propose_resp_cert(&mut self, 
        v: Vote,
        c: Certificate<Vote>,
        ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        log::info!("Proposing resp cert");
        // Create deliverable resp cert message
        let prop = {
            let mut prop_builder = ProposalBuilder::default();
            prop_builder
                .data(RespCertData {
                    vote: v,
                    cert: c,
                })
                .codewords(None)
                .witnesses(None)
                .build()
                .map_err(|e| format!("Proposal Builder Error: {}", e))?
                .init()
        };
        let proof = {
            let (acc, _codes, _wits) = self.resp_cert_acc_builder.build(&prop)?;
            let sign = Certificate::new_cert(&(self.epoch, acc.clone()),self.config.id, &self.sk)?;
            let mut proof = ProofBuilder::default(); 
            proof
                .acc(acc)
                .sign(sign)
                .build()
                .map_err(|e| format!("Proof Build Error: {}", e))?
        };
        let msg = self.new_resp_cert_msg(prop.clone(), proof.clone())?;
        ev_queue.send_msg(msg);
        ev_queue.add_event(
            Event::Message(
                self.config.id,
                NewMessage::RespCert(prop, proof),
            )
        );
        Ok(())
    }

    pub(crate) fn verify_resp_cert(&mut self, 
        from: Replica,
        prop: &RespCertProposal,
        proof: &Proof<RespCertProposal>,
    ) -> Result<()> {
        if from != self.leader_ctx.current_leader() {
            return Err(
                Error::Generic(
                    format!("Expected resp cert from epoch leader {}", 
                        self.leader_ctx.current_leader())
                )
            );
        }

        if self.epoch != prop.data.vote.epoch() {
            return Err(Error::Generic(
                format!("Expected a resp cert from the current epoch {}, got a resp cert from {}", self.epoch, prop.data.vote.epoch())
            ));
        }

        // Check signatures
        prop.is_valid(from,
            self.epoch,
            proof, 
            &mut self.storage, 
            &self.resp_cert_acc_builder, 
            &self.pk_map)?;

        // Check for equivocating resp cert
        if self.storage.is_equivocation_resp_cert(self.epoch, proof.acc()) {
            log::warn!("Proposal equivocation detected for {}", prop.epoch());
            todo!();
            // return Err(
            //     Error::EquivocationDetected(self.epoch)
            // );
        }

        // Check for equivocating proposal in resp cert
        if let Some((_, proof_orig)) = self.storage.prop_from_hash(prop.data.vote.proposal_hash()) {
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

    pub(crate) fn on_verified_resp_cert(&mut self,
        mut prop: RespCertProposal,
        proof: Proof<RespCertProposal>,
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        // Deliver
        self.deliver_resp_cert_msg(&mut prop, &proof, ev_queue)?;
        self.do_ack(self.epoch, 
            proof.clone(), 
            *prop.data.vote.proposal_hash(), 
            ev_queue, 
        )?;
        // Start 2\Delta commit timer
        ev_queue.add_timeout(
            TimeOutEvent::Commit(
                    self.epoch,
                    *prop.data.vote.proposal_hash(),
                ), 
            self.x_delta(2),
            self.epoch,
        );

        // Update highest certificate
        if prop.data.vote.higher_than(self.highest_certified_data()) {
            log::info!("Updating from {} to a higher epoch cert {}", self.highest_certified_data().epoch(), prop.data.vote.epoch());
            self.update_highest_cert(prop.data.vote.clone(), prop.data.cert.clone())?;
        }

        // Update storage
        self.storage.add_resp_cert(prop.data.vote, prop.data.cert);

        // Update round context to prevent processing of Deliver messages
        self.rnd_ctx.received_resp_cert_directly = true;

        Ok(())
    }

    fn new_resp_cert_msg(&mut self, 
        prop: RespCertProposal,
        proof: Proof<RespCertProposal>,
    ) -> Result<OutMsg> 
    {
        Ok((
            self.config.num_nodes, // SendAll
            Arc::new(ProtocolMsg::RespCert(prop, proof)),
        ))
    }
}
