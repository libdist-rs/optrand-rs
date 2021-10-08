use std::sync::Arc;
use types::{DeliverData, DirectProposal, Proof, Proposal, ProposalData, ProtocolMsg, Replica, Result, error::Error};
use crate::{MsgBuf, OptRandStateMachine};

impl OptRandStateMachine {
    /// Adds deliver messages to all the nodes
    /// The first message is a multicast of self share
    /// The second to n+1th message is a send to node i its share
    pub(crate) fn deliver_propose_msg(&self, 
        prop:&mut DirectProposal, 
        proof: &Proof<DirectProposal>, 
        msg_buf: &mut MsgBuf
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
        msg_buf.push_back((self.config.num_nodes, Arc::new(ProtocolMsg::DeliverPropose(self.config.id, deliver_data_my_share))));

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
            msg_buf.push_back(msg);
        }
        Ok(())
    }

    /// Check whether the delivered message is correct
    pub(crate) fn verify_propose_deliver_share(&self, 
        sender: Replica,
        from: Replica, 
        sh: &DeliverData<DirectProposal>
    ) -> Result<()> {
        // Bypass all checks if we received the shares directly
        if self.rnd_ctx.received_proposal_directly {
            return Ok(());
        }
        if from != sender && from != self.config.id {
            return Err(Error::Generic(
                format!("Got a deliver share for {} from {}", from, sender)
            ));
        }
        // Verify the codeword
        self.prop_acc_builder.verify_witness(&sh.acc, 
            &sh.wit, 
            &sh.shard, 
            sender)
    }

    pub(crate) fn on_verified_propose_deliver(&mut self, 
        sh_for: Replica, 
        sh: DeliverData<DirectProposal>
    ) -> Result<()> {
        // Bypass checks if we received the shares directly
        if self.rnd_ctx.received_proposal_directly {
            return Ok(());
        }

        // Add the share
        self.rnd_ctx.add_propose_deliver_share(sh_for, sh);
        // Try reconstruction
        let prop = if let Some(x) = self.rnd_ctx.cleave_propose_from_deliver(
            self.config.num_nodes, 
            self.config.num_nodes/4 + 1
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
        self.storage.add_proposal(prop);
        self.storage.add_delivered_block(block);
        Ok(())
    }
}