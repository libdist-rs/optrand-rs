use fnv::{FnvHashMap as HashMap, FnvHashSet};
use super::Block;
use crate::{Certificate, DeliverData, DirectProposal, Epoch, Height, MTAccumulator, PVSSVec, Proof, Replica, Result, SyncCertProposal, Vote, ProofBuilder};
use crypto::hash::{Hash, ser_and_hash};
use std::{collections::VecDeque, sync::Arc};
use crate::AggregatePVSS;

// TODO: Use storage
#[derive(Default)]
pub struct Storage {
    /// The delivered blocks referred by hash
    all_delivered_blocks_by_hash: HashMap<Hash, Arc<Block>>,
    /// The delivered blocks referred by height
    all_delivered_blocks_by_ht: HashMap<Height, Arc<Block>>,

    /// The committed blocks referred by the height
    committed_blocks_by_ht: HashMap<Height, Arc<Block>>,
    /// The committed blocks referred by hash
    committed_blocks_by_hash: HashMap<Hash, Arc<Block>>,


    /// A mapping of the proposal to its hash
    prop_hash_map: HashMap<Hash, (Arc<DirectProposal>, Arc<Proof<DirectProposal>>)>,
    /// Sync Vote Bank
    sync_vote_map: HashMap<Epoch, (Vote, Certificate<Vote>)>,

    /// This contains a list of all verified signatures from all the senders
    /// This is used to prevent re-verifying the same signatures over and over again
    verified_sigs: Vec<HashMap<Hash, Vec<u8>>>,


    /// Did we detect an equivocation for a proposal in this epoch
    equivocation_map: FnvHashSet<Epoch>,
    /// Used to check for proposal equivocation
    prop_epoch_map: HashMap<Epoch, (
        MTAccumulator<DirectProposal>, 
        Certificate<(Epoch, MTAccumulator<DirectProposal>)>
    )>,
    // /// Used to check for sync cert equivocation
    sync_cert_epoch_map: HashMap<Epoch, (
        MTAccumulator<SyncCertProposal>, 
        Certificate<(Epoch, MTAccumulator<SyncCertProposal>)>
    )>,

    /// Store Aggregate PVSS for every replica
    /// Here, we add an Aggregate PVSS in epoch e for replica i, to be used the next time replica i becomes a leader again
    rand_beacon_queue: HashMap<Replica, VecDeque<AggregatePVSS>>,

    /// When I am a leader, I will need to have t+1 sharings ready
    /// Anytime from the last time I was a leader to the next time I am a leader, I may receive t+1 sharings
    /// Delete the queue if the queue becomes empty when consuming
    next_proposal_pvss_sharings: HashMap<Replica, VecDeque<PVSSVec>>,
}

impl Storage {
    /// The space parameter cannot be used in FnvHashMap implementation
    /// Creates a newly initialized storage container to store all the context
    pub fn new(num_nodes: usize) -> Self {
        let mut storage = Self {
            verified_sigs: Vec::with_capacity(num_nodes),
            ..Default::default()
        };
        for i in 0..num_nodes {
            storage.verified_sigs.insert(i, HashMap::default());
        }
        storage
    }

    /// Adds a block to the storage
    /// This block is now delivered
    pub fn add_delivered_block(&mut self, b: Block) {
        let b_arc = Arc::new(b);
        self.all_delivered_blocks_by_hash.insert(
            b_arc.hash().clone(), b_arc.clone());
        self.all_delivered_blocks_by_ht.insert(b_arc.height(), b_arc);
    }

    /// Adds a block to the list of committed blocks
    pub fn commit_block(&mut self, mut b_arc: Arc<Block>) -> Result<()>{
        let mut ht = b_arc.height();
        while !self.committed_blocks_by_ht.contains_key(&ht) {
            self.committed_blocks_by_hash.insert(
                b_arc.hash().clone(), b_arc.clone());
            self.committed_blocks_by_ht.insert(b_arc.height(), b_arc);
            if ht == 0 {
                break;
            }
            ht = ht-1;
            b_arc = self.get_delivered_block_by_height(ht).ok_or(
                format!("Trying to commit an unknown height {}", ht)
            )?;
        }
        Ok(())
    }

    pub fn get_delivered_block_by_hash(&self, hash: &Hash) -> Option<Arc<Block>> {
        self.all_delivered_blocks_by_hash.get(hash).map(|v| v.clone())
    }

    pub fn get_delivered_block_by_height(&self, ht: Height) -> Option<Arc<Block>> {
        self.all_delivered_blocks_by_ht.get(&ht).map(|v| v.clone())
    }

    /// Ensure that the signature is already verified before storing it
    pub fn add_verified_sig(&mut self, from: Replica, msg_hash: Hash, sig: Vec<u8>) {
        self.verified_sigs[from].insert(msg_hash, sig);
    }

    pub fn is_already_verified(&self, from: Replica, msg_hash: &Hash) -> bool {
        self.verified_sigs[from].contains_key(msg_hash)
    }

    /// Ensure that equivocations are checked for, before adding the proposal
    pub fn add_proposal(&mut self, 
        p: DirectProposal, 
        acc: MTAccumulator<DirectProposal>,
        sign: Certificate<(Epoch, MTAccumulator<DirectProposal>)>,
    ) -> Result<()> {
        let p_arc = Arc::new(p);
        let proof_arc = {
            let mut proof = ProofBuilder::default();
            let proof = proof.acc(acc.clone())
                .sign(sign.clone())
                .build()
                .map_err(|e| 
                    format!("Failed to build proof with error: {}", e)
                )?;
            Arc::new(proof)
        };
        let hash = ser_and_hash(p_arc.as_ref());
        self.prop_hash_map.insert(hash, (p_arc.clone(), proof_arc));
        self.prop_epoch_map.insert(p_arc.epoch(), (acc, sign));
        Ok(())
    }

    /// Add prop data from Deliver data
    /// Used to prevent equivocation via Deliver
    pub fn add_prop_data_from_deliver(&mut self,
        e: Epoch,
        acc: MTAccumulator<DirectProposal>,
        sign: Certificate<(Epoch, MTAccumulator<DirectProposal>)>,
    ) {
        self.prop_epoch_map.insert(e, (acc, sign));
    }

    pub fn prop_from_hash(&self, hash: &Hash) -> Option<(Arc<DirectProposal>, Arc<Proof<DirectProposal>>)> {
        self.prop_hash_map.get(hash).map(|v| v.clone())
    }

    pub fn add_new_leader_sharing(&mut self) {
        todo!();
    }
    pub fn add_new_self_sharing(&mut self) {
        todo!();
    }


    /// Checks if we received an equivocating proposal
    /// Check the validity of the certificate first
    pub fn is_equivocation_prop(&self, 
        e: Epoch, 
        acc: &MTAccumulator<DirectProposal>,
    ) -> bool {
        if let Some((acc_known, _)) = self.prop_epoch_map.get(&e) {
            return acc.hash != acc_known.hash;
        }
        return false;
    }

    /// Checks if we received an equivocating proposal
    /// Check the validity of the certificate first
    pub fn is_equivocation_sync_cert(&self, 
        e: Epoch, 
        acc: &MTAccumulator<SyncCertProposal>,
    ) -> bool {
        // No equivocating sync_certs were found
        if let Some((acc_known, _)) = self.sync_cert_epoch_map.get(&e) {
            return acc.hash != acc_known.hash;
        }
        return false;
    }

    /// Check if either proposal or sync_cert equivocations were found
    pub fn is_equivocation(&self, e:&Epoch) -> bool {
        self.equivocation_map.contains(e)
    }

    /// Add a sync vote to storage
    /// If an equivocation is detected, the vote will not be added, and the option will be non-empty
    pub fn add_sync_vote(&mut self, 
        from: Replica, 
        v: Vote, 
        mut c: Certificate<Vote>
    ) -> Option<()> {
        if let Some((vote, cert)) = self.sync_vote_map.get_mut(&v.epoch()) {
            if v.proposal_hash() != vote.proposal_hash() {
                return Some(());
            }
            cert.add_signature(from, c.sigs.remove(&from).unwrap());
        } else {
            self.sync_vote_map.insert(v.epoch(), (v,c));
        }
        None
    }

    /// Tries to create a sync cert for the epoch
    pub fn cleave_sync_cert(&mut self, 
        e: Epoch,
        num_sigs: usize,
    ) -> Option<(Vote, Certificate<Vote>)> {
        // SAFETY: Should not error, since we try cleaving only after adding a vote
        if self.sync_vote_map[&e].1.len() >= num_sigs {
            return Some(
                self.sync_vote_map.get(&e)
                    .expect("Unreachable since the length is more than or eqaul to num_sigs")
                    .clone()
            );
        }
        None
    }
    
    /// Add sync cert to the storage
    /// Check for equivocations first
    pub fn add_sync_cert(&mut self, 
        v:Vote,
        c: Certificate<Vote>,
    )
    {
        self.sync_vote_map.insert(v.epoch(), (v,c));
    }
}
