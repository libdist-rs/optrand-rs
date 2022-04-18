use std::sync::Arc;
use types::{DeliverData, DirectProposal, Proof, ProtocolMsg, Replica, Result, error::Error, reed_solomon_threshold};
use crate::ev_queue::EventQueue;
use super::OptRandStateMachine;

impl OptRandStateMachine {
    /// Adds deliver messages to all the nodes
    /// The first message is a multicast of self share
    /// The second to n+1th message is a send to node i its share
    pub(crate) fn deliver_propose_msg(&self, 
        prop:&mut DirectProposal, 
        proof: &Proof<DirectProposal>, 
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        let codes = prop.get_codewords(&self.prop_acc_builder)?;
        let wits = prop.get_witnesses(&self.prop_acc_builder)?;
        // Send my share to all the nodes first
        let deliver_data_my_share = DeliverData{
            acc: proof.acc().clone(),
            sign: proof.sign().clone(),
            shard: codes[self.config.id].clone(),
            wit: wits[self.config.id].clone(),
        };
        ev_queue.send_msg((self.config.num_nodes, Arc::new(ProtocolMsg::DeliverPropose(self.config.id, deliver_data_my_share))));

        for i in 0..self.config.num_nodes {
            if i == self.config.id {
                continue;
            }
            // Send other's shares
            let deliv_data = DeliverData {
                acc: proof.acc().clone(),
                sign: proof.sign().clone(),
                shard: codes[i].clone(),
                wit: wits[i].clone(),
            };
            let msg = (i as Replica, Arc::new(ProtocolMsg::DeliverPropose(i as Replica, deliv_data)));
            ev_queue.send_msg(msg);
        }
        Ok(())
    }

    /// Check whether the delivered message is correct
    pub(crate) fn verify_propose_deliver_share(&self, 
        sender: Replica,
        sh_for: Replica, 
        sh: &DeliverData<DirectProposal>
    ) -> Result<()> {
        // Check for equivocations
        if self.storage.is_equivocation_prop(self.epoch, &sh.acc) {
            log::warn!("Proposal equivocation detected for {}", self.epoch);
            todo!();
            // return Err(
            //     Error::EquivocationDetected(self.epoch)
            // );
        }

        // Bypass all checks if we received the shares directly
        if self.rnd_ctx.received_proposal_directly {
            return Ok(());
        }
        if sh_for != sender && sh_for != self.config.id {
            return Err(Error::Generic(
                format!("Got a deliver share for {} from {}", sh_for, sender)
            ));
        }
        // Verify the codeword
        self.prop_acc_builder.verify_witness(&sh.acc, 
            &sh.wit, 
            &sh.shard, 
            sh_for)
    }

    pub(crate) fn on_verified_propose_deliver(&mut self, 
        sh_for: Replica, 
        sh: DeliverData<DirectProposal>
    ) -> Result<()> {
        // Add propose accumulator to prevent equivocation via deliver
        self.storage.add_prop_data_from_deliver(self.epoch, sh.acc.clone(), sh.sign.clone());

        // Bypass checks if we received the shares directly
        if self.rnd_ctx.received_proposal_directly {
            return Ok(());
        }

        // Add the share
        self.rnd_ctx.add_propose_deliver_share(sh_for, sh.clone());
        // Try reconstruction
        let prop = if let Some(x) = self.rnd_ctx.cleave_propose_from_deliver(
            self.config.num_nodes, 
            reed_solomon_threshold(self.config.num_nodes),
        ) {
            if let Err(e) = x {
                return Err(e);
            }
            x.unwrap()
        } else {
            return Ok(());
        };
        // Add proposal to storage
        let block = prop.block().clone();
        self.storage.add_proposal(prop, sh.acc, sh.sign)?;
        self.storage.add_delivered_block(block);
        Ok(())
    }
}