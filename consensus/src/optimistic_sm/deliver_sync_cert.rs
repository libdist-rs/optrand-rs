use std::sync::Arc;

use types::{DeliverData, Proof, ProtocolMsg, Replica, Result, SyncCertProposal, error::Error, reed_solomon_threshold};
use crate::ev_queue::EventQueue;
use super::OptRandStateMachine;

impl OptRandStateMachine {
    pub(crate) fn deliver_sync_cert_msg(&self, 
        prop: &mut SyncCertProposal, 
        proof: &Proof<SyncCertProposal>, 
        ev_queue: &mut EventQueue,
    ) -> Result<()> 
    {
        let codes = prop.get_codewords(&self.sync_cert_acc_builder)?;
        let wits = prop.get_witnesses(&self.sync_cert_acc_builder)?;
        // Send my share to all the nodes first
        let deliver_data_my_share = DeliverData{
            acc: proof.acc().clone(),
            sign: proof.sign().clone(),
            shard: codes[self.config.id].clone(),
            wit: wits[self.config.id].clone(),
        };
        ev_queue.send_msg((self.config.num_nodes, Arc::new(ProtocolMsg::DeliverSyncCert(self.config.id, deliver_data_my_share))));

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
            let msg = (i as Replica, Arc::new(ProtocolMsg::DeliverSyncCert(i as Replica, deliv_data)));
            ev_queue.send_msg(msg);
        }
        Ok(())
    }

    /// Check whether the delivered message is correct
    pub(crate) fn verify_sync_cert_deliver_share(&self, 
        sender: Replica,
        sh_for: Replica, 
        sh: &DeliverData<SyncCertProposal>
    ) -> Result<()> {
        // Bypass all checks if we received the shares directly
        if self.rnd_ctx.received_sync_cert_directly {
            return Ok(());
        }
        if sh_for != sender && sh_for != self.config.id {
            return Err(Error::Generic(
                format!("Got a deliver share for {} from {}", sh_for, sender)
            ));
        }
        // Verify the codeword
        self.sync_cert_acc_builder.verify_witness(&sh.acc, 
            &sh.wit, 
            &sh.shard, 
            sh_for)
    }

    pub(crate) fn on_verified_sync_cert_deliver(&mut self, 
        sh_for: Replica, 
        sh: DeliverData<SyncCertProposal>
    ) -> Result<()> {
        // Bypass checks if we received the shares directly
        if self.rnd_ctx.received_sync_cert_directly {
            return Ok(());
        }

        // Add the share
        self.rnd_ctx.add_sync_cert_deliver_share(sh_for, sh);
        // Try reconstruction
        let prop = if let Some(x) = self.rnd_ctx.cleave_sync_cert_from_deliver(
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

        // Update highest certificate
        if prop.data.vote.higher_than(self.highest_certified_data()) {
            log::info!("Updating from {} to a higher epoch cert {}", self.highest_certified_data().epoch(), prop.data.vote.epoch());
            self.update_highest_cert(prop.data.vote.clone(), prop.data.cert.clone())?;
        }
        // Add sync cert to storage
        self.storage.add_sync_cert(prop.data.vote, prop.data.cert);
        
        Ok(())
    }

}