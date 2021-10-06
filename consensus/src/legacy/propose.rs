use std::sync::Arc;

use crypto::hash::EMPTY_HASH;
use fnv::FnvHashSet;
use tokio_util::time::DelayQueue;
use types::{Block, CertType, DataWithAcc, Epoch, PVSSVec, Proposal, ProtocolMsg, Replica};
use types_upstream::WireReady;

use crate::{Context, Event, get_acc};

impl Context {
    /// Called when the propose event happens
    /// Must be triggered only when the node is the leader for the current epoch
    pub(crate) async fn do_propose(&mut self, e: Epoch, dq: &mut DelayQueue<Event>, vecs: Vec<PVSSVec>, indices: &[Replica]) {
        log::info!("{} am proposing in {}", self.id(), e);

        let (agg_vec, agg_pi) = self.config.pvss_ctx.aggregate(&indices, vecs);
        let mut block = Block::new(agg_vec, agg_pi);
        // Add parent block
        block.update_parent(self.highest_block.as_ref());
        let proposal = Proposal{
            epoch: self.epoch(),
            new_block: block,
            highest_certificate: self.highest_cert.as_ref().clone(),
        };

        // Generate accumulators
        let (shards, data) = get_acc(self, &proposal);

        log::info!("Proposing a block that extends {}", self.highest_block.height);
        self.broadcast(ProtocolMsg::RawPropose(self.epoch(),proposal, data));
        self.round_ctx.already_proposed = true;
    }

    /// Try propose will try to propose if all the conditions are met
    /// This will be attempted if
    /// 1. we receive new valid shares
    /// 2. A new vote
    /// 3. A status message
    /// 4. On entering a new epoch
    /// 5. On a timeout
    pub(crate) async fn try_propose(&mut self, e: Epoch, dq: &mut DelayQueue<Event>) {
        if e < self.epoch() {
            return;
        }
        // Not stale

        if self.leader() != self.id() {
            return;
        }
        // I am the leader

        if self.storage.next_proposal_pvss_sharings.len() <= self.num_faults() {
            return;
        }
        // I have sufficient vectors

        if self.round_ctx.already_proposed {
            log::debug!("Already proposed in this epoch, return");
            return;
        }
        // I did not already propose

        if !(self.highest_block.height == self.epoch()-1 || self.round_ctx.status_timed_out) {
            return;
        }
        // Either we have the highest certificate or we timedout

        self.round_ctx.already_proposed = true;
        let mut count = 0;
        let mut vecs = Vec::with_capacity(self.num_faults()+1);
        let mut indices = Vec::with_capacity(self.num_faults()+1);
        for id in 0..self.num_nodes() {
            if count == self.num_faults()+1 {
                break;
            }
            if self.storage.next_proposal_pvss_sharings.contains_key(&id) {
                let mut queue = self.storage.next_proposal_pvss_sharings.remove(&id).unwrap();
                vecs.push(queue.pop_front().expect("Do not insert empty queues into this queue"));
                indices.push(id);
                count += 1;
                if !queue.is_empty() {
                    self.storage.next_proposal_pvss_sharings.insert(id, queue);
                }
            }
        }
        assert_eq!(vecs.len(), self.num_faults()+1);

        self.do_propose(e, dq, vecs, &indices).await;
    } 

    /// Called on receiving a propose message
    pub(crate) async fn on_recv_propose(&mut self,
        e: Epoch,  
        p: Proposal,
        z_pa: DataWithAcc, 
        sender: Replica,
        dq: &mut DelayQueue<Event>
    ) {
        if p.epoch < self.epoch() {
            log::debug!("Received stale proposals");
            return;
        }
        // What to do if we receive a block from a future epoch?
        if p.epoch > self.epoch() {
            panic!("Future blocks: Unimplemented");
        }

        // Is epoch_timer-r >= 7Delta
        if self.round_ctx.propose_timeout {
            return;
        }
        
        log::debug!("New proposal received: {:?}", p);
        // Check if the proposal is valid

        let block_hash = self.highest_cert.get_hash();
        if !self.storage.all_delivered_blocks_by_hash.contains_key(&block_hash) {
            log::debug!("Got a certificate for an unknown hash");
            return;
        }

        let block = self.storage.all_delivered_blocks_by_hash[&block_hash].clone();
        if block.height < self.highest_block.height {
            log::warn!("Invalid proposal received. Proposal extends a lower height block");
            return;
        }
        // Check certificates
        let mut set = FnvHashSet::default();
        match p.highest_certificate {
            CertType::Resp(ref x, ref y) => {
                if y.msg != x.block_hash {
                    return;
                }
                for v in &y.votes {
                    if v.origin >= self.num_nodes() {
                        return;
                    }
                    if !self.pub_key_map[&v.origin].verify(&y.msg, &v.auth) {
                        return;
                    }
                    set.insert(v.origin);
                }
            }
            CertType::Sync(ref x, ref y) => {
                if y.msg != x.block_hash {
                    return;
                }
                for v in &y.votes {
                    if v.origin >= self.num_nodes() {
                        return;
                    }
                    if !self.pub_key_map[&v.origin].verify(&y.msg, &v.auth) {
                        return;
                    }
                    set.insert(v.origin);
                }
            }
        }
        if set.len() <= self.num_faults() {
            log::warn!("Got a certificate with insufficent votes");
            return;
        }

        // Update if this is a higher block
        if block.height > self.highest_block.height {
            self.highest_block = block.clone();
            self.highest_cert = Arc::new(p.highest_certificate.clone());
        }

        let p_arc = Arc::new(p);

        if sender == self.leader() {
            self.round_ctx.propose_received_directly = true;
        }

        self.round_ctx.propose_received = Some(p_arc);
    }
}