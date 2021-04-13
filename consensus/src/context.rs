use super::accumulator::ShareGatherer;

use fnv::FnvHashMap as HashMap;

use tokio::sync::mpsc::UnboundedSender;
use config::Node;
use std::sync::Arc;
use types::{
    Block, Certificate, Height, ProtocolMsg, Replica, Storage, GENESIS_BLOCK,
};

pub struct Context {
    // Hold on to the config
    config: Node,
    // Needs to be generated from the config
    pub my_secret_key: crypto_lib::Keypair,
    pub pub_key_map: HashMap<Replica, crypto_lib::PublicKey>,

    pub net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,

    pub storage: Storage,
    pub height: Height,
    pub epoch: Height,
    pub last_leader: Replica,
    pub locked_block: Arc<Block>,

    pub highest_cert: Certificate,
    pub highest_height: Height,

    pub propose_share_sent: bool,
    pub vote_cert_share_sent: bool,
    pub commit_share_sent: bool,

    pub propose_gatherer: ShareGatherer,
    pub vote_cert_gatherer: ShareGatherer,
    pub commit_gatherer: ShareGatherer,
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
            highest_cert: GENESIS_BLOCK.certificate,
            highest_height: 0,

            propose_share_sent: false,
            vote_cert_share_sent: false,
            commit_share_sent: false,

            propose_gatherer: ShareGatherer::new(n),
            vote_cert_gatherer: ShareGatherer::new(n),
            commit_gatherer: ShareGatherer::new(n),
        };
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
}
