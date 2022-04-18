use tokio_util::time::DelayQueue;
use types::{CertType, DataWithAcc, Epoch, ProtocolMsg, Replica, SignedShard, SyncCertMsg};
use std::sync::Arc;
use crate::{Context, Event, get_sign, get_acc_with_shard};
use types_upstream::WireReady;
use crypto::hash::ser_and_hash;


impl Context {
    /// A function called on receiving a shard or on receiving the synchronous certificate
    pub fn do_deliver_sync_cert(&mut self, acc: DataWithAcc, shards: Vec<Vec<u8>>, _dq: &mut DelayQueue<Event>) {
        let myid = self.config.id;
        let my_shard_auth = get_sign(&acc, myid);
        // Sending my shard; Execute once every epoch
        if !self.sync_cert_shard_self_sent {
            self.deliver_sync_cert_self(shards[myid].clone(), 
                my_shard_auth.clone());
        }
        if self.sync_cert_shard_others_sent {
            return;
        }
        for i in 0..self.config.num_nodes {
            if myid == i {
                continue;
            }
            let your_shard_auth = get_sign(&acc, i);
            // Sending your shard
            self.net_send.send(
                (i,
                    Arc::new(ProtocolMsg::DeliverSyncCert(
                        self.epoch,
                        shards[i].clone(),
                        your_shard_auth,
                        i
                    ))
                )
            ).unwrap();
        }
        self.sync_cert_shard_others_sent = true;
    }

    /// Received synchronous certificate directly
    pub fn receive_sync_cert_direct(&mut self, rcert: SyncCertMsg, _cert: DataWithAcc, dq: &mut DelayQueue<Event>) {
        if self.sync_cert_received_directly {
            // Check equivocation
            return;
        }
        if self.sync_cert_received.is_some() {
            // Check equivocation
            self.sync_cert_received_directly = true;
            return;
        }
        // Check validity of the sync certificate
        if self.epoch != rcert.sync_vote.epoch {
            // Stale message
            log::warn!("Stale sync certificate received");
            return;
        }
        // Check if the signature is on the correct message
        let hash = ser_and_hash(&rcert.sync_vote);
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
        self.sync_cert_received = Some(Arc::new(rcert.clone()));
        let b = self.storage.all_delivered_blocks_by_hash[&rcert.sync_vote.block_hash].clone();
        if self.highest_block.height < b.height {
            self.highest_block = b.clone();
            self.highest_cert = CertType::Sync(rcert.clone());
        }
        if self.epoch_block_lock.is_none() {
            log::warn!("I think this should not be triggered");
            let b = self.storage.all_delivered_blocks_by_hash[&rcert.sync_vote.block_hash].clone();
            self.epoch_block_lock = Some(b);
        }
        self.start_sync_commit(b.height, dq);
    }

    pub fn receive_sync_cert_indirect(&mut self, rcert: SyncCertMsg, dq: &mut DelayQueue<Event>) {
        if self.sync_cert_received_directly {
            // Check equivocation
            return;
        }
        if self.sync_cert_received.is_some() {
            // Check equivocation
            return;
        }
        // Check validity of the sync certificate
        if self.epoch != rcert.sync_vote.epoch {
            // Stale message
            log::warn!("Stale sync certificate received");
            return;
        }
        // Check if the signature is on the correct message
        let hash = ser_and_hash(&rcert.sync_vote);
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
        self.sync_cert_received = Some(Arc::new(rcert.clone()));
        let b = self.storage.all_delivered_blocks_by_hash[&rcert.sync_vote.block_hash].clone();
        if self.highest_block.height < b.height {
            self.highest_block = b.clone();
            self.highest_cert = CertType::Sync(rcert.clone());
        }
        if self.epoch_block_lock.is_none() {
            log::warn!("I think this should not be triggered");
            let b = self.storage.all_delivered_blocks_by_hash[&rcert.sync_vote.block_hash].clone();
            self.epoch_block_lock = Some(b);
        }
        self.start_sync_commit(b.height, dq);
    }

    /// Received a deliver message for a responsive certificate
    pub fn do_receive_sync_cert_deliver(&mut self, e:Epoch,shard: Vec<u8>, auth: SignedShard, origin: Replica, dq: &mut DelayQueue<Event>) {
        if self.epoch != e {
            return;
        }
        if self.sync_cert_received_directly {
            // Check for equivocation and then return since we already sent shares before
            return;
        }
        if self.sync_cert_received.is_some() {
            return;
        }
        
        self.sync_cert_gatherer.add_share(shard.clone()
        , origin, &self.pub_key_map[&self.last_leader], auth.clone());
        // I can only send my shares for now
        if origin == self.config.id && !self.sync_cert_shard_self_sent {
            self.deliver_sync_cert_self(shard, auth.clone());
            self.sync_cert_shard_self_sent = true;
        }
        if self.sync_cert_gatherer.shard_num < (self.num_nodes()/4) + 1 {
            return;
        }
        let p = self.sync_cert_gatherer.reconstruct(self.num_nodes()).unwrap();
        let rcert = SyncCertMsg::from_bytes(&p).init();
        let (shards, cert) = get_acc_with_shard(&self, &rcert, auth);
        self.do_deliver_sync_cert(cert, shards, dq);
        self.receive_sync_cert_indirect(rcert.clone(), dq);
        self.sync_cert_received = Some(Arc::new(rcert));
    }
}