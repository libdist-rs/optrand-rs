use crate::{Context, ShareGatherer};
use types::{Replica, GENESIS_BLOCK, ProtocolMsg, Storage, Certificate, CertType, SyncCertMsg, SyncVote};
use std::sync::Arc;
use crypto::DecompositionProof;
use config::Node;
use tokio::sync::mpsc::UnboundedSender;
use fnv::FnvHashMap as HashMap;

impl Context {
    /// Consume the config and take over it
    pub fn new(
        config: Node,
        net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,
    ) -> Self {
        let n = config.num_nodes;
        let sk = config.get_secret_key();
        let genesis_block = Arc::new(GENESIS_BLOCK);
        let mut c = Context {
            config,
            my_secret_key: sk,
            pub_key_map: HashMap::default(),
            net_send: net_send,
            storage: Storage::new(n),
            /// The height and next leader are both 1 because the genesis block
            /// is of height 0 and its author is replica 0
            epoch: 0,
            last_leader: 0,
            highest_block: genesis_block.clone(),
            last_leader_epoch: 0,

            future_messages1: HashMap::default(),
            future_messages2: HashMap::default(),
            future_messages3: HashMap::default(),
            propose_shard_self_sent: false,
            resp_cert_shard_self_sent: false,
            sync_cert_shard_self_sent: false,
            propose_shard_others_sent: false,
            resp_cert_shard_others_sent: false,
            sync_cert_shard_others_sent: false,
            propose_received_directly: false,
            resp_cert_received_directly: false,
            sync_cert_received_directly: false,
            is_epoch_correct: false,
            propose_timeout: false,
            equivocation_detected: false,

            propose_gatherer: ShareGatherer::new(n),
            resp_cert_gatherer: ShareGatherer::new(n),
            sync_cert_gatherer: ShareGatherer::new(n),
            // commit_gatherer: ShareGatherer::new(n),

            pvss_shares: Vec::new(),
            pvss_indices: Vec::new(),
            decomps: HashMap::default(),
            my_decomps: HashMap::default(),
            resp_votes: Certificate::empty_cert(),
            sync_votes: Certificate::empty_cert(),
            ack_votes: Certificate::empty_cert(),
            responsive_timeout: false,
            sync_commit_timeout: false,
            ack_msg: None,
            started_sync_timer: false,
            epoch_block_lock: None,
            reconstruction_shares: vec![None; n],
            num_shares: 0,
            last_reconstruction_round: 0,
            current_round_reconstruction_vector: None,
            propose_received: None,
            resp_cert_received: None,
            sync_cert_received: None,
            highest_committed_block: genesis_block.clone(),
            highest_cert: CertType::Sync(SyncCertMsg{
                cert: Certificate::empty_cert(),
                sync_vote: SyncVote{
                    block_hash: genesis_block.hash,
                    epoch: 0,
                }
            }),
        };
        for k in c.config.sharings.keys() {
            let decomps = (0..c.config.num_nodes).map(|_i| {
                DecompositionProof{
                    comms: Vec::new(),
                    encs: Vec::new(),
                    idx: 0,
                    indices: Vec::new(),
                    proof: Vec::new(),
                }
            }).collect();
            c.decomps.insert(k.clone(), decomps);
        }
        c.storage
            .committed_blocks_by_hash
            .insert(GENESIS_BLOCK.hash, genesis_block.clone());
        c.storage
            .committed_blocks_by_ht
            .insert(0, genesis_block);
        c.pub_key_map = c.config.get_public_key_map();
        c
    }

    /// Returns the number of nodes 
    pub fn num_nodes(&self) -> usize {
        self.config.num_nodes
    }

    /// Returns the f (faults)
    pub fn num_faults(&self) -> usize {
        self.config.num_faults
    }

    /// Returns the delta configured for this instance
    /// Delta is in ms
    pub fn delta(&self) -> u64 {
        self.config.delta
    }

    /// Returns the id of this instance
    pub fn id(&self) -> Replica {
        self.config.id
    }

    /// Returns the next leader
    /// TODO - Remove bad leaders from the system
    pub fn next_leader(&self) -> Replica {
        self.next_of(self.last_leader)
    }

    /// What is the next leader, if prev is the current leader
    pub fn next_of(&self, prev: Replica) -> Replica {
        (prev + 1) % self.num_nodes()
    }

    /// Epoch reset contains the things that need to be reset in every epoch
    pub fn epoch_reset(&mut self) {
        self.propose_gatherer.clear();
        self.propose_received_directly = false;
        self.propose_shard_self_sent = false;
        self.propose_shard_others_sent = false;
        self.is_epoch_correct = false;
        self.propose_timeout = false;
        self.equivocation_detected = false;
        self.resp_cert_gatherer.clear();
        self.resp_votes = Certificate::empty_cert();
        self.sync_votes = Certificate::empty_cert();
        self.resp_cert_shard_others_sent = false;
        self.resp_cert_shard_self_sent = false;
        self.resp_cert_received_directly = false;
        self.sync_cert_shard_others_sent = false;
        self.sync_cert_shard_self_sent = false;
        self.sync_cert_received_directly = false;
        self.ack_msg = None;
        self.ack_votes = Certificate::empty_cert();
        self.responsive_timeout = false;
        self.sync_commit_timeout = false;
        self.started_sync_timer = false;
        self.epoch_block_lock = None;
        self.num_shares = 0;
        self.reconstruction_shares = vec![None; self.num_nodes()];
        self.propose_received = None;
        self.resp_cert_received = None;
        self.sync_cert_received = None;
    }

    /// Compute 3n/4+1 
    pub const fn optimistic(&self) -> usize {
        ((3*self.config.num_nodes)/4) + 1
    } 
}
