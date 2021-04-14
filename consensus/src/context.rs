use super::accumulator::ShareGatherer;

use crypto::{DecompositionProof, PVSSVec, hash::Hash};
use fnv::FnvHashMap as HashMap;

use tokio::{sync::mpsc::UnboundedSender, time::Instant};
use config::Node;
use std::sync::Arc;
use types::{Block, Certificate, Epoch, GENESIS_BLOCK, Height, ProtocolMsg, Replica, Storage};

pub struct Context {
    // Hold on to the config
    pub(crate) config: Node,
    // Needs to be generated from the config
    pub my_secret_key: crypto_lib::Keypair,
    pub pub_key_map: HashMap<Replica, crypto_lib::PublicKey>,

    /// Network interface
    pub net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,

    /// Storage for all the blocks
    pub storage: Storage,
    /// Decomposition proofs to be sent to all the nodes while proposing
    pub decomps: HashMap<Hash, Vec<DecompositionProof>>,
    /// Decomposition proofs I received for an epoch
    pub my_decomps: HashMap<Hash, DecompositionProof>,

    /// PVSS Shares received for my next epoch
    pub pvss_shares: Vec<PVSSVec>,
    pub pvss_indices: Vec<Replica>,

    pub height: Height,
    pub epoch: Epoch,
    pub last_leader: Replica,

    /// The latest certificate seen
    pub highest_cert: Arc<Certificate>,
    pub highest_height: Height,
    pub locked_block: Arc<Block>,
    pub last_leader_epoch: Epoch,

    /// Set when I get my shard and send it to all the nodes
    pub propose_shard_self_sent: bool,
    /// Set when I reconstruct or obtain the full block directly and send everyone their shares
    pub propose_shard_others_sent: bool,
    // pub vote_cert_shard_sent: bool,
    // pub commit_shard_sent: bool,
    pub propose_received_directly: bool,
    pub propose_gatherer: ShareGatherer,
    /// Should we for this epoch or not?
    pub is_epoch_correct: bool,
    /// Did 4\Delta pass and we did not receive a proposal from the leader
    pub propose_timeout: bool,
    /// Did we detect any equivocation so far
    pub equivocation_detected: bool,

    // pub vote_cert_gatherer: ShareGatherer,
    // pub commit_gatherer: ShareGatherer,

    // Timers
    /// Epoch Timer
    /// This is actually the instant when the next timer will start
    /// For example, if \delta = 1 min, and if the protocol starts at 12PM, in epoch 1 epoch_timer is 12:11 PM, in epoch 2 epoch_timer is 12:22 PM, and so on.
    pub epoch_timer: Instant,
}

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
            height: 0,
            epoch: 0,
            last_leader: 0,
            locked_block: genesis_block.clone(),
            highest_cert: Arc::new(Certificate::empty_cert()),
            highest_height: 0,
            last_leader_epoch: 0,

            propose_shard_self_sent: false,
            propose_shard_others_sent: false,
            propose_received_directly: false,
            is_epoch_correct: false,
            propose_timeout: false,
            equivocation_detected: false,

            propose_gatherer: ShareGatherer::new(n),
            // vote_cert_gatherer: ShareGatherer::new(n),
            // commit_gatherer: ShareGatherer::new(n),

            epoch_timer: tokio::time::Instant::now(),
            pvss_shares: Vec::new(),
            pvss_indices: Vec::new(),
            decomps: HashMap::default(),
            my_decomps: HashMap::default(),
        };
        for k in c.config.sharings.keys() {
            let decomps = (0..c.config.num_nodes).map(|i| {
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
    }
}
