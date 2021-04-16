use types::{CertType, Height};
use crypto::hash::ser_and_hash;
use crate::Context;


impl Context {
    /// Handle status messages from other nodes
    pub fn do_receive_status(&mut self, ht: Height, cert: CertType) {
        if self.highest_block.height >= ht {
            // We already have the highest certificate certificate
            return;
        }
        log::warn!("Should not be called in optimistic conditions");
        // Check if we have the block that this status is talking about
        let block_hash = match cert {
            CertType::Resp(ref rcert) => rcert.resp_vote.block_hash,
            CertType::Sync(ref scert) => scert.sync_vote.block_hash,
        };
        if !self.storage.all_delivered_blocks_by_hash.contains_key(&block_hash) {
            // Invalid certificate, this cannot occur with correct players
            return;
        }
        // Check signature validity
        match cert {
            CertType::Resp(ref rcert) => {
                let hash = ser_and_hash(&rcert.resp_vote);
                if rcert.cert.msg != hash {
                    log::warn!("Invalid responsive certificate received");
                    log::warn!("Got {:?} resp cert", rcert);
                    log::warn!("Computed hash {:?}", hash);
                    return;
                }
                for v in &rcert.cert.votes {
                    if !self.pub_key_map[&v.origin].verify(&rcert.cert.msg, &v.auth) {
                        log::warn!("Invalid signature on resp cert");
                        return;
                    }
                } 
            },
            CertType::Sync(ref scert) => {
                let hash = ser_and_hash(&scert.sync_vote);
                if scert.cert.msg != hash {
                    log::warn!("Invalid sync certificate received");
                    log::warn!("Got {:?} sync cert", scert);
                    log::warn!("Computed hash {:?}", hash);
                    return;
                }
                for v in &scert.cert.votes {
                    if !self.pub_key_map[&v.origin].verify(&scert.cert.msg, &v.auth) {
                        log::warn!("Invalid signature on sync cert");
                        return;
                    }
                } 
            }
        }
        // Signatures are valid, update highest block
        let b = self.storage.all_delivered_blocks_by_hash[&block_hash].clone();
        self.highest_block = b;
        self.highest_cert = cert;
    }
}