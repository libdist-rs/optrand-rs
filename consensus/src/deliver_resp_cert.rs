use tokio::time::Duration;
use tokio_util::time::DelayQueue;
use types::{AckMsg, CertType, DataWithAcc, Epoch, ProtocolMsg, Replica, ResponsiveCertMsg, SignedShard};
use std::sync::Arc;
use types_upstream::WireReady;
use crypto::hash::ser_and_hash;
use crate::{Context, Event, check_valid, get_acc_with_shard, get_sign, get_tree, to_shards};
use util::io::to_bytes;


impl Context {
    /// A function called on receiving a shard or on receiving the responsive certificate
    pub fn do_deliver_resp_cert(&mut self, acc: DataWithAcc, shards: Vec<Vec<u8>>, _dq: &mut DelayQueue<Event>) {
        let myid = self.config.id;
        let my_shard_auth = get_sign(&acc, myid);
        // Sending my shard; Execute once every epoch
        if !self.resp_cert_shard_self_sent {
            self.deliver_resp_cert_self(shards[myid].clone(), 
                my_shard_auth.clone());
        }
        if self.resp_cert_shard_others_sent {
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
                    Arc::new(ProtocolMsg::DeliverResponsiveCert(
                        self.epoch,
                        shards[i].clone(),
                        your_shard_auth,
                        i
                    ))
                )
            ).unwrap();
        }
        self.resp_cert_shard_others_sent = true;
    }

    /// Received responsive certificate directly
    pub fn receive_resp_cert_direct(&mut self, rcert: ResponsiveCertMsg, cert: DataWithAcc, dq: &mut DelayQueue<Event>) {
        // Initiate the synchronous path if this is the first certificate
        if self.resp_cert_received.is_some() {
            // Check equivocation
            self.resp_cert_received_directly = true;
            return;
        }
        // Lock on to the block
        if self.epoch != rcert.resp_vote.epoch {
            // Stale message
            log::warn!("Stale resp certificate received");
            return;
        }
        // Check if the signature is on the correct message
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
        // Check if the accumulator is correct
        let new_acc = get_tree(self.num_nodes(), &rcert);
        if !check_valid(&new_acc,&cert,  &self.pub_key_map[&self.last_leader]) {
            log::warn!("Received an incorrect accumulator for a correct proposal from {}", self.last_leader);
            return;
        }
        self.resp_cert_received_directly = true;
        self.resp_cert_received = Some(Arc::new(rcert.clone()));
        let b = self.storage.all_delivered_blocks_by_hash[&rcert.resp_vote.block_hash].clone();
        if self.highest_block.height < b.height {
            self.highest_block = b.clone();
            self.highest_cert = CertType::Resp(rcert.clone());
        }
        let shards = to_shards(to_bytes(&rcert), self.num_nodes());
        self.do_deliver_resp_cert(cert, shards, dq);
        let ack = AckMsg{
            block_hash: rcert.resp_vote.block_hash,
            epoch: rcert.resp_vote.epoch,
        };
        self.do_ack(ack, dq);
        // We obtained a beacon for this, go to the next round
        // if self.last_reconstruction_round == self.epoch {
        //     // To break recursion, we use the delay queue
        //     dq.insert(Event::EpochEnd(rcert.resp_vote.epoch), Duration::from_nanos(1));
        // }
    }

    /// Received a responsive certificate indirectly
    pub fn do_receive_resp_cert_indirect(&mut self, rcert: ResponsiveCertMsg, dq: &mut DelayQueue<Event>) {
        if self.epoch != rcert.resp_vote.epoch {
            // Stale message
            log::warn!("Stale resp certificate received");
            return;
        }
        // Check if the signature is on the correct message
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
        self.resp_cert_received = Some(Arc::new(rcert.clone()));
        let b = self.storage.all_delivered_blocks_by_hash[&rcert.resp_vote.block_hash].clone();
        if self.highest_block.height < b.height {
            self.highest_block = b.clone();
            self.highest_cert = CertType::Resp(rcert.clone());
        }
        let ack = AckMsg{
            block_hash: rcert.resp_vote.block_hash,
            epoch: rcert.resp_vote.epoch,
        };
        self.do_ack(ack, dq);
        // We obtained a beacon for this, go to the next round
        if self.last_reconstruction_round == self.epoch {
            // To break recursion, we use the delay queue
            dq.insert(Event::EpochEnd(rcert.resp_vote.epoch), Duration::from_nanos(1));
        }
    }

    /// Received a deliver message for a responsive certificate
    pub fn do_receive_resp_cert_deliver(&mut self, e:Epoch,shard: Vec<u8>, auth: SignedShard, origin: Replica, dq: &mut DelayQueue<Event>) {
        if e != self.epoch {
            return;
        }
        if self.resp_cert_received.is_some() {
            return;
        }
        if self.resp_cert_received_directly {
            // Check for equivocation and then return since we already sent shares before
            let (shards, cert) = get_acc_with_shard(&self, &self.resp_cert_received.as_ref().unwrap().as_ref(), auth);
            self.do_deliver_resp_cert(cert, shards, dq);
            return;
        }
        self.resp_cert_gatherer.add_share(shard.clone()
        , origin, &self.pub_key_map[&self.last_leader], auth.clone());
        // I can only send my shares for now
        if origin == self.config.id && !self.resp_cert_shard_self_sent {
            self.deliver_resp_cert_self(shard, auth.clone());
            self.resp_cert_shard_self_sent = true;
        }
        if self.resp_cert_gatherer.shard_num < (self.num_nodes()/4) + 1 {
            return;
        }
        let p = self.resp_cert_gatherer.reconstruct(self.num_nodes()).unwrap();
        let rcert = ResponsiveCertMsg::from_bytes(&p).init();
        let (shards, cert) = get_acc_with_shard(&self, &rcert, auth);
        self.do_deliver_resp_cert(cert, shards, dq);
        self.do_receive_resp_cert_indirect(rcert.clone(), dq);
        self.resp_cert_received = Some(Arc::new(rcert));
    }
}