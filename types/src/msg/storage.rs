use fnv::{FnvHashMap as HashMap, FnvHashSet};
use super::Block;
use crate::*;
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
    /// A mapping of the epoch to the proposal
    prop_epoch_map: HashMap<Epoch, Arc<DirectProposal>>,

    /// Sync Vote Bank used by the leader to create sigs
    sync_vote_map: HashMap<Epoch, (Vote, Certificate<Vote>)>,
    /// Responsive Vote Bank used by the leader to create sigs
    resp_vote_map: HashMap<Epoch, (Vote, Certificate<Vote>)>,

    /// This contains a list of all verified signatures from all the senders
    /// This is used to prevent re-verifying the same signatures over and over again
    verified_sigs: Vec<HashMap<Hash, Vec<u8>>>,


    /// Did we detect an equivocation for a proposal in this epoch
    equivocation_map: FnvHashSet<Epoch>,
    /// Used to check for proposal equivocation
    prop_eq_epoch_map: HashMap<Epoch, (
        MTAccumulator<DirectProposal>, 
        Certificate<(Epoch, MTAccumulator<DirectProposal>)>
    )>,
    /// Used to check for sync cert equivocation
    sync_cert_eq_epoch_map: HashMap<Epoch, (
        MTAccumulator<SyncCertProposal>, 
        Certificate<(Epoch, MTAccumulator<SyncCertProposal>)>
    )>,
    /// Used to check for resp cert equivocation
    resp_cert_eq_epoch_map: HashMap<Epoch, (
        MTAccumulator<RespCertProposal>, 
        Certificate<(Epoch, MTAccumulator<RespCertProposal>)>
    )>,

    /// Store beacon PVSS vectors here
    rand_beacon_pvss: HashMap<Replica, VecDeque<AggregatePVSS>>,

}

impl Storage {
    /// The space parameter cannot be used in FnvHashMap implementation
    /// Creates a newly initialized storage container to store all the context
    pub fn new(num_nodes: usize, rand_beacon_pvss: HashMap<Replica, VecDeque<AggregatePVSS>>) -> Self {
        // let mut rand_beacon_pvss = Vec::with_capacity(num_nodes);
        // for i in 0..num_nodes {
        //     rand_beacon_pvss[i] = VecDeque::new();
        // }

        let mut storage = Self {
            verified_sigs: Vec::with_capacity(num_nodes),
            rand_beacon_pvss,
            ..Default::default()
        };
        for i in 0..num_nodes {
            storage.verified_sigs.insert(i, HashMap::default());
        }
        storage.add_delivered_block(Block::GENESIS_BLOCK);
        let gen_arc = storage.get_delivered_block_by_height(Block::GENESIS_BLOCK.height()).expect("Could not find genesis block even after adding it to the storage");
        storage.committed_blocks_by_hash.insert(
            *gen_arc.hash(), 
            gen_arc.clone()
        );
        storage.committed_blocks_by_ht.insert(0, gen_arc);
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
        // Prevent committing height 0, genesis block
        // Check if it breaks other assumptions (Should be fixed now)
        while ht > 0 && !self.committed_blocks_by_ht.contains_key(&ht) {
            // Everytime we commit a block, we add the sharings to the random beacon queue
            log::info!("Adding a PVSS vector to Q for {}", b_arc.proposer());
            let queue= self.rand_beacon_pvss
                .get_mut(b_arc.proposer())
                .ok_or(
                    format!("We can't have committed a block while having an empty randombeacon queue")
                )?;
            queue.push_back(b_arc.pvss().clone());
            self.committed_blocks_by_hash.insert(
                b_arc.hash().clone(), b_arc.clone());
            self.committed_blocks_by_ht.insert(b_arc.height(), b_arc);
            ht = ht-1;
            b_arc = self.get_delivered_block_by_height(ht).ok_or(
                format!("Trying to commit an unknown height {}", ht)
            )?;
        }
        Ok(())
    }

    pub fn get_committed_block_by_hash(&self, hash: &Hash) -> Option<&Arc<Block>> {
        self.committed_blocks_by_hash.get(hash)
    }

    pub fn get_proposal_from_epoch(&self, 
        e: &Epoch
    ) -> Option<Arc<DirectProposal>> {
        self.prop_epoch_map.get(e)
            .map(|e| e.clone())
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
        self.prop_eq_epoch_map.insert(p_arc.epoch(), (acc, sign));
        self.prop_epoch_map.insert(p_arc.epoch(), p_arc);
        Ok(())
    }

    /// Add prop data from Deliver data
    /// Used to prevent equivocation via Deliver
    pub fn add_prop_data_from_deliver(&mut self,
        e: Epoch,
        acc: MTAccumulator<DirectProposal>,
        sign: Certificate<(Epoch, MTAccumulator<DirectProposal>)>,
    ) {
        self.prop_eq_epoch_map.insert(e, (acc, sign));
    }

    pub fn prop_from_hash(&self, hash: &Hash) -> Option<(Arc<DirectProposal>, Arc<Proof<DirectProposal>>)> {
        self.prop_hash_map.get(hash).map(|v| v.clone())
    }

    pub fn cleave_beacon_share(&mut self, 
        from: Replica
    ) -> Result<AggregatePVSS> {
        self.rand_beacon_pvss
            .get_mut(&from)
            .ok_or(format!("Cant cleave an empty random beacon buffer"))?
            .pop_front()
            .ok_or(format!("Cleaving an empty buffer").into())
    }

    /// Checks if we received an equivocating proposal
    /// Check the validity of the certificate first
    pub fn is_equivocation_prop(&self, 
        e: Epoch, 
        acc: &MTAccumulator<DirectProposal>,
    ) -> bool {
        if let Some((acc_known, _)) = self.prop_eq_epoch_map.get(&e) {
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
        if let Some((acc_known, _)) = self.sync_cert_eq_epoch_map.get(&e) {
            return acc.hash != acc_known.hash;
        }
        return false;
    }

    /// Checks if we received an equivocating proposal
    /// Check the validity of the certificate first
    pub fn is_equivocation_resp_cert(&self, 
        e: Epoch, 
        acc: &MTAccumulator<RespCertProposal>,
    ) -> bool {
        // No equivocating sync_certs were found
        if let Some((acc_known, _)) = self.resp_cert_eq_epoch_map.get(&e) {
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
        mut c: Certificate<Vote>,
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

    /// Used to determine whether we will verify this vote or not
    pub fn num_sync_votes(&self, e: &Epoch) -> usize {
        if let Some(len) = self.sync_vote_map
            .get(e)
            .map(|(_, y)| y.len()) 
        {
            return len;
        }
        return 0;
    }

    /// Add a responsive vote to storage
    /// If an equivocation is detected, the vote will not be added, and the option will be non-empty
    pub fn add_resp_vote(&mut self, 
        from: Replica, 
        v: Vote, 
        mut c: Certificate<Vote>
    ) -> Option<()> {
        if let Some((vote, cert)) = self.resp_vote_map.get_mut(&v.epoch()) {
            if v.proposal_hash() != vote.proposal_hash() {
                return Some(());
            }
            cert.add_signature(from, c.sigs.remove(&from).unwrap());
        } else {
            self.resp_vote_map.insert(v.epoch(), (v,c));
        }
        None
    }

    /// Used to determine whether we will verify this vote or not
    pub fn num_resp_votes(&self, e: &Epoch) -> usize {
        if let Some(len) = self.resp_vote_map
            .get(e)
            .map(|(_, y)| y.len()) 
        {
            return len;
        }
        return 0;
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
    
    /// Tries to create a resp cert for the epoch
    pub fn cleave_resp_cert(&mut self, 
        e: Epoch,
        num_sigs: usize,
    ) -> Option<(Vote, Certificate<Vote>)> {
        // SAFETY: Should not error, since we try cleaving only after adding a vote
        if self.resp_vote_map[&e].1.len() >= num_sigs {
            return Some(
                self.resp_vote_map.get(&e)
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

    /// Add resp cert to the storage
    /// Check for equivocations first
    pub fn add_resp_cert(&mut self, 
        v:Vote,
        c: Certificate<Vote>,
    )
    {
        self.resp_vote_map.insert(v.epoch(), (v,c));
    }

}
