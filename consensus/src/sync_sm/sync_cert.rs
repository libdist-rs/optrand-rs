use std::sync::Arc;

use crate::{Event, EventQueue, NewMessage, OutMsg, TimeOutEvent};
use super::OptRandStateMachine;
use types::{Certificate, Proof, ProofBuilder, ProposalBuilder, ProtocolMsg, Replica, Result, SyncCertData, SyncCertProposal, Vote, error::Error};
use types_upstream::WireReady;

impl OptRandStateMachine {
    pub(crate) fn propose_sync_cert(&mut self, 
        v: Vote,
        c: Certificate<Vote>,
        ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        log::info!("Proposing sync cert");
        // Create deliverable sync cert message
        let prop = {
            let mut prop_builder = ProposalBuilder::default();
            prop_builder
                .data(SyncCertData {
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
            let (acc, _codes, _wits) = self.sync_cert_acc_builder.build(&prop)?;
            let sign = Certificate::new_cert(&(self.epoch, acc.clone()),self.config.id, &self.sk)?;
            let mut proof = ProofBuilder::default(); 
            proof
                .acc(acc)
                .sign(sign)
                .build()
                .map_err(|e| format!("Proof Build Error: {}", e))?
        };
        let msg = self.new_sync_cert_msg(prop.clone(), proof.clone())?;
        ev_queue.send_msg(msg);
        ev_queue.add_event(
            Event::Message(
                self.config.id,
                NewMessage::SyncCert(prop, proof),
            )
        );
        Ok(())
    }

    pub(crate) fn verify_sync_cert(&mut self, 
        from: Replica,
        prop: &SyncCertProposal,
        proof: &Proof<SyncCertProposal>,
    ) -> Result<()> {
        if from != self.leader_ctx.current_leader() {
            return Err(
                Error::Generic(
                    format!("Expected sync cert from epoch leader {}", 
                        self.leader_ctx.current_leader())
                )
            );
        }

        if self.epoch != prop.data.vote.epoch() {
            return Err(Error::Generic(
                format!("Expected a sync cert from the current epoch {}, got a sync cert from {}", self.epoch, prop.data.vote.epoch())
            ));
        }
        // Did we get the proposal in time?
        if self.rnd_ctx.stop_accepting_sync_certs {
            log::error!("Got a sync cert from {} too late. Check delta timings", from);
            return Err(Error::Generic(format!("Sync Cert too late")));
        }

        // Check signatures
        prop.is_valid(from,
            self.epoch,
            proof, 
            &mut self.storage, 
            &self.sync_cert_acc_builder, 
            &self.pk_map)?;

        // Check for equivocating sync cert
        if self.storage.is_equivocation_sync_cert(self.epoch, proof.acc()) {
            log::warn!("Proposal equivocation detected for {}", prop.epoch());
            todo!();
            // return Err(
            //     Error::EquivocationDetected(self.epoch)
            // );
        }

        // Check for equivocating proposal in sync cert
        if let Some((_, proof_orig)) = self.storage.prop_from_hash(prop.data.vote.proposal_hash()) {
            if self.storage.is_equivocation_prop(self.epoch, proof_orig.acc()) {
                return Err(Error::EquivocationDetected(self.epoch));
            }
        } else {
            return Err(
                Error::Generic(format!("Delivered a sync cert for an unknown proposal hash"))
            );
        }
        Ok(())
    }

    pub(crate) fn on_verified_sync_cert(&mut self,
        mut prop: SyncCertProposal,
        proof: Proof<SyncCertProposal>,
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        // Deliver
        self.deliver_sync_cert_msg(&mut prop, &proof, ev_queue)?;

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
        self.storage.add_sync_cert(prop.data.vote, prop.data.cert);

        // Update round context to prevent processing of Deliver messages
        self.rnd_ctx.received_sync_cert_directly = true;

        Ok(())
    }

    fn new_sync_cert_msg(&mut self, 
        prop: SyncCertProposal,
        proof: Proof<SyncCertProposal>,
    ) -> Result<OutMsg> 
    {
        Ok((
            self.config.num_nodes, // SendAll
            Arc::new(ProtocolMsg::SyncCert(prop, proof)),
        ))
    }

    pub(crate) fn stop_accepting_sync_certs(&mut self, e: usize) -> Result<()> {
        if e != self.epoch {
            return Err(Error::Generic(format!("Got Stop Accepting Sync Cert timeout for {} in Epoch {}", e, self.epoch)));
        }
        self.rnd_ctx.stop_accepting_sync_certs = true;
        Ok(())
    }

    
}