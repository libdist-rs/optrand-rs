use std::sync::Arc;

use crate::{Event, EventQueue, NewMessage, OutMsg, TimeOutEvent};
use super::OptRandStateMachine;
use crypto::hash::ser_and_hash;
use types::{BlockBuilder, Certificate, DirectProposal, Epoch, Proof, ProofBuilder, ProposalBuilder, ProposalData, ProtocolMsg, Replica, Result, error::Error};
use types_upstream::WireReady;

impl OptRandStateMachine {
    pub(crate) fn on_propose_timeout(&mut self, 
        ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        log::info!("Time to propose");

        // Aggregate the shares
        let (agg, decom) = if let Some(x) = self.config.leader_beacon_queue.pop_front() {
            x
        } else {
            return Err(
                Error::Generic(
                    format!("Did not receive t+1 pvss vecs to agg in time")
                )
            );
        };
        log::info!("Proposing Aggregated PVSS");

        // Build the proposal 
        let parent = self.highest_certified_block();
        let block = {
            let mut block_builder = BlockBuilder::default();
            block_builder
                .height(parent.height() + 1) 
                .parent_hash(*parent.hash()) 
                .aggregate_pvss(agg)
                .aggregate_proof(decom)
                .proposer(self.config.id)
                .build()?
        };
        let prop = {
            let mut prop_builder = ProposalBuilder::default();
            prop_builder
                .data(ProposalData {
                    epoch: self.epoch,
                    highest_cert_data: self.highest_certified_data().clone(),
                    highest_cert:self.highest_certificate().clone(),
                    block,
                })
                .codewords(None)
                .witnesses(None)
                .build()
                .map_err(|e| format!("Proposal Builder Error: {}", e))?
                .init()
        };
        let proof = {
            let (acc, _codes, _wits) = self.prop_acc_builder.build(&prop)?;
            let sign = Certificate::new_cert(&(self.epoch, acc.clone()),self.config.id, &self.sk)?;
            let mut proof = ProofBuilder::default(); 
            proof
                .acc(acc)
                .sign(sign)
                .build()
                .map_err(|e| format!("Proof Build Error: {}", e))?
        };
        // Multicast the proposal
        let msg = self.new_proposal_msg(prop.clone(), proof.clone())?;
        ev_queue.send_msg(msg);
        ev_queue.add_event(
            Event::Message(
                self.config.id, 
                NewMessage::Propose(prop, proof)
            )
        );
        Ok(())
    }

    pub fn new_proposal_msg(&mut self, 
        prop: DirectProposal, 
        proof: Proof<DirectProposal>
    ) -> Result<OutMsg> {
        Ok((
            self.config.num_nodes, // SendAll
            Arc::new(ProtocolMsg::RawPropose(prop.clone(), proof))
        ))
    }

    /// We require mutability because we will add signatures to the buffer
    pub fn verify_proposal(&mut self, 
        from: Replica, 
        prop: &DirectProposal, 
        proof: &Proof<DirectProposal>
    ) -> Result<()> {
        if from != self.leader_ctx.current_leader() || from != *prop.proposer() {
            return Err(
                Error::Generic(
                    format!("Expected proposal from epoch leader {}", 
                        self.leader_ctx.current_leader())
                )
            );
        }

        if self.epoch != prop.epoch() {
            return Err(Error::Generic(
                format!("Expected a proposal from the current epoch {}, got a proposal from {}", self.epoch, prop.epoch())
            ));
        }

        // Did we get the proposal in time?
        if self.rnd_ctx.stop_accepting_proposals {
            log::error!("Got a proposal from {} too late. Check delta timings", from);
            return Err(Error::Generic(format!("Proposal too late")));
        }

        // Check if the proposal is basically valid
        prop.is_valid(from,
            self.epoch,
            proof, 
            &mut self.storage, 
            &self.config.pvss_ctx, 
            &self.prop_acc_builder, 
            &self.pk_map)?;

        // Check if the agg is already stored and ready
        let h = ser_and_hash(prop.block().pvss());
        if !self.config.pool_of_verified_shares.contains_key(&h) {
            log::error!("We don't have the agg verified and ready");
            return Err(format!("Agg not ready").into());
        }
        
        // Check for equivocations
        if self.storage.is_equivocation_prop(self.epoch, proof.acc()) {
            log::warn!("Proposal equivocation detected for {}", prop.epoch());
            todo!();
            // return Err(
            //     Error::EquivocationDetected(self.epoch)
            // );
        }



        // Does the proposed block extend the highest certified block?
        if prop.block().height() < self.highest_certified_block().height() + 1 {
            // We got a block that does not extend the highest certified block 
            return Err(Error::Generic(
                format!("The proposed block with height {} does not extend the local highest certified block with height {}", prop.block().height(), self.highest_certified_block().height())
            ));
        }

        // Is the certificate valid?
        if prop.block().height() != 1 {
            if prop.highest_cert().len() != prop.data.highest_cert_data.num_sigs(self.config.num_nodes) {
                return Err(Error::Generic(
                    format!("Expected {} sigs in the certificate. Got {}", self.config.num_faults + 1, prop.highest_cert().len())
                ));
            }
            prop.highest_cert().buffered_is_valid(prop.vote(), &self.pk_map, &mut self.storage)?;
        }

        // Check for equivocation
        log::info!("Got a valid proposal");
        Ok(())
    }

    pub fn stop_accepting_proposals(&mut self, e: Epoch) -> Result<()> {
        if e != self.epoch {
            return Err(Error::Generic(format!("Got Stop Accepting Proposal timeout for {} in Epoch {}", e, self.epoch)));
        }
        self.rnd_ctx.stop_accepting_proposals = true;
        Ok(())
    }

    pub(crate) fn on_verified_propose(&mut self, 
        mut prop: DirectProposal, 
        proof: Proof<DirectProposal>, 
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        // Deliver
        self.deliver_propose_msg(&mut prop, &proof, ev_queue)?;

        // Vote
        ev_queue.add_timeout(
            TimeOutEvent::SyncVoteWaitTimeOut(self.epoch, prop.hash()), 
            self.x_delta(2),
            self.epoch,
        );

        // Update storage
        let block = prop.block().clone();
        let (acc, sign) = proof.unpack();
        self.storage.add_proposal(prop, acc, sign)?;
        self.storage.add_delivered_block(block);

        // Update round context
        self.rnd_ctx.received_proposal_directly = true;

        Ok(())
    }
}