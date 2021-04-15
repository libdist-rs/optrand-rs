use crypto::{DecompositionProof, hash::ser_and_hash};
use tokio_util::time::DelayQueue;
use types::{Block, DataWithAcc, Proposal, ProtocolMsg, Replica, SignedShard};
use crate::{Context, Event, accumulator::{check_valid, get_acc_with_shard, get_sign, get_tree, to_shards}, get_acc};
use std::sync::Arc;
use util::io::to_bytes;
use types_upstream::WireReady;

impl Context {
    /// do_propose is called when the node is ready to propose
    /// This will extend the highest known certificate of the node and create a block extending the highest known certificate
    pub(crate) async fn do_propose(&mut self, dq: &mut DelayQueue<Event>) {
        let mut queue = self.config.beacon_sharing_buffer
            .remove(&self.config.id).unwrap();
        let pvec_hash = queue.pop_front().unwrap();
        self.config.beacon_sharing_buffer.insert(self.config.id, queue);

        let pvec = self.config.sharings[&pvec_hash].clone();
        let mut new_block = Block::new(pvec);
        new_block.height = self.locked_block.height + 1;
        new_block.parent_hash = self.locked_block.hash;
        new_block.hash = new_block.compute_hash();

        let decomps = self.decomps[&pvec_hash].clone();

        let p = types::Proposal{
            epoch: self.epoch,
            highest_certificate: self.highest_cert.as_ref().clone(),
            new_block,
        };

        let (shards, z_pa) = get_acc(&self, &p);
        let auth = get_sign(&z_pa, self.config.id);
        self.propose_gatherer.add_share(shards[self.config.id].clone(), self.config.id, &self.pub_key_map[&self.config.id], auth);
        for i in 0..self.config.num_nodes {
            if i == self.config.id {
                continue;
            }
            self.net_send.send((
                i, // Because multicast
                Arc::new(ProtocolMsg::RawPropose(p.clone(), z_pa.clone(), decomps[i].clone()))
            )).unwrap();
        }
        // The leader will just do the deliver propose part as it has generated things correctly
        self.do_deliver_propose(&z_pa, shards).await;
        self.propose_received_directly = true;
        self.do_vote(&p, dq).await;
    }

    /// A function called by all the nodes to deliver a propose message
    /// This function will assume that the proposal has been checked before-hand and that the root is signed
    /// Call as soon as a valid block is received/reconstructed
    pub(crate) async fn do_deliver_propose(&mut self, acc: &DataWithAcc, shards: Vec<Vec<u8>>) 
    {
        let myid = self.config.id;
        let my_shard_auth = get_sign(acc, myid);
        // Sending my shard; Execute once every epoch
        if !self.propose_shard_self_sent {
            self.deliver_propose_self(shards[myid].clone(), 
                my_shard_auth.clone()).await;
        }
        if self.propose_shard_others_sent {
            return;
        }
        for i in 0..self.config.num_nodes {
            if myid == i {
                continue;
            }
            let your_shard_auth = get_sign(acc, i);
            // Sending your shard
            self.net_send.send(
                (i,
                    Arc::new(ProtocolMsg::DeliverPropose(
                        shards[i].clone(),
                        your_shard_auth,
                        i
                    ))
                )
            ).unwrap();
        }
        self.propose_shard_others_sent = true;
    }

    /// Receive proposal is called when a new proposal is received
    pub async fn receive_proposal_direct(&mut self, sender:Replica, p: Proposal, cert: DataWithAcc, decomp: DecompositionProof, dq: &mut DelayQueue<Event>) {
        // Check if we have this sharing already
        let pvec_hash = crypto::hash::ser_and_hash(&p.new_block.aggregate_pvss);
        // If we don't have it, verify and add it
        if !self.config.sharings.contains_key(&pvec_hash) {
            // Check decompositions first so that the adversary cannot trigger 2n pairings checks incorrectly
            if let Some(err) = self.config.pvss_ctx.decomp_verify(&p.new_block.aggregate_pvss, &decomp, &self.pub_key_map) {
                log::warn!("Invalid decomposition received from {} with error {:?}", sender, err);
                return;
            }
            if let Some(err) = self.config.pvss_ctx.pverify(&p.new_block.aggregate_pvss) {
                log::warn!("Invalid sharing received from {} with error {:?}", sender, err);
                return;
            }
            let hash = ser_and_hash(&p.new_block.aggregate_pvss);
            self.config.sharings.insert(hash, p.new_block.aggregate_pvss.clone());
            self.my_decomps.insert(hash, decomp);
        }
        // We have a checked and confirmed that the pvss sharing is okay
        // Check if the accumulator is doing okay; signed correctly
        let new_acc = get_tree(self.num_nodes(), &p);
        if !check_valid(&new_acc,&cert,  &self.pub_key_map[&sender]) {
            log::warn!("Received an incorrect accumulator for a correct proposal from {}", sender);
            return;
        }
        self.propose_received_directly = true;
        // Send shards to others
        let shards = to_shards(&to_bytes(&p), self.num_nodes());
        self.do_deliver_propose(&cert, shards).await;
        self.do_vote(&p, dq).await;
        self.storage.add_new_block(p.new_block);
    }

    pub async fn do_receive_propose_deliver(&mut self, shard: Vec<u8>, auth: SignedShard, origin: Replica) {
        if self.propose_received_directly {
            // Check for equivocation and then return since we already sent shares before
            return;
        }
        self.propose_gatherer.add_share(shard.clone()
        , origin, &self.pub_key_map[&self.last_leader], auth.clone());
        // I can only send my shares for now
        if origin == self.config.id && !self.propose_shard_self_sent {
            self.deliver_propose_self(shard, auth.clone()).await;
            self.propose_shard_self_sent = true;
        }
        if self.propose_gatherer.shard_num <= (self.num_nodes()/4) + 1 {
            return;
        }
        let p = self.propose_gatherer.reconstruct(self.num_nodes()).unwrap();
        let prop = Proposal::from_bytes(&p).init();
        let (shards, cert) = get_acc_with_shard(&self, &prop, auth);
        self.do_deliver_propose(&cert, shards).await;
        self.do_receive_proposal_indirect(prop).await;
    }

    /// What do we do when we receive a proposal indirectly?
    pub async fn do_receive_proposal_indirect(&mut self, p: Proposal)
    {
        // Check if we have this sharing already
        let pvec_hash = crypto::hash::ser_and_hash(&p.new_block.aggregate_pvss);
        // If we don't have it, verify and add it
        if !self.config.sharings.contains_key(&pvec_hash) {
            if let Some(err) = self.config.pvss_ctx.pverify(&p.new_block.aggregate_pvss) {
                log::warn!("Invalid sharing received via deliver with error {:?}", err);
                return;
            }
            let hash = ser_and_hash(&p.new_block.aggregate_pvss);
            self.config.sharings.insert(hash, p.new_block.aggregate_pvss.clone());
        }
        // We have checked and confirmed that the pvss sharing is okay
        self.storage.add_new_block(p.new_block);
    }
}