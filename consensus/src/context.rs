use super::accumulator::ShareGatherer;

use types::{AggregatePVSS, DecompositionProof, PVSSVec, Share};
use crypto::{hash::Hash};
use fnv::FnvHashMap as HashMap;

use tokio::{sync::mpsc::UnboundedSender, time::Instant};
use config::Node;
use std::sync::Arc;
use types::{AckMsg, Block, CertType, Certificate, Epoch, Proposal, ProtocolMsg, Replica, ResponsiveCertMsg, Storage, SyncCertMsg};

pub struct Context {
    /// Our config file from the command line
    pub(crate) config: Node,

    /// Secret key that we will use to sign messages for the protocol
    pub(crate) my_secret_key: crypto_lib::Keypair,
    /// Everyone's public keys
    pub(crate) pub_key_map: HashMap<Replica, crypto_lib::PublicKey>,

    /// Network interface
    pub(crate) net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,

    /// Storage for all the blocks
    pub(crate) storage: Storage,

    /// Decomposition proofs to be sent to all the nodes while proposing
    pub(crate) decomps: HashMap<Hash, Vec<DecompositionProof>>,
    /// Decomposition proofs I received for an epoch
    pub(crate) my_decomps: HashMap<Hash, DecompositionProof>,

    /// PVSS Shares received for my next epoch
    pub pvss_shares: Vec<PVSSVec>,
    /// People who sent these shares
    pub pvss_indices: Vec<Replica>,

    /// The current epoch
    pub epoch: Epoch,
    /// The current leader
    pub last_leader: Replica,
    /// The latest certificate seen. NOTE that the highest_cert and the locked block are updated at the same time.
    pub highest_cert: CertType,
    /// The locked block. NOTE that the locked_block and the highest_cert are updated at the same time.
    pub highest_block: Arc<Block>,
    /// The first block observed for this epoch
    pub epoch_block_lock: Option<Arc<Block>>,
    /// The highest committed block
    pub highest_committed_block: Arc<Block>,

    /// This is the last epoch I was a leader of
    pub last_leader_epoch: Epoch,

    /// Did I send my shards to everyone
    pub propose_shard_self_sent: bool,
    /// Did I send my shards to everyone
    pub resp_cert_shard_self_sent: bool,
    /// Did I send my shards to everyone
    pub sync_cert_shard_self_sent: bool,
    
    /// Did I send everyone their shards
    pub propose_shard_others_sent: bool,
    /// Did I send everyone their shards
    pub resp_cert_shard_others_sent: bool,
    /// Did I send everyone their shards
    pub sync_cert_shard_others_sent: bool,
    
    // Whether we received objects directly
    pub propose_received_directly: bool,
    // Whether we received objects directly
    pub resp_cert_received_directly: bool,
    // Whether we received objects directly
    pub sync_cert_received_directly: bool,

    /// Whether we should stop processing deliver messages
    pub propose_received: Option<Arc<Proposal>>,
    /// Whether we should stop processing deliver messages
    pub resp_cert_received: Option<Arc<ResponsiveCertMsg>>,
    /// Whether we should stop processing deliver messages
    pub sync_cert_received: Option<Arc<SyncCertMsg>>,

    /// Should we vote for this epoch or not?
    pub is_epoch_correct: bool,

    /// Did 4\Delta pass and we did not receive a proposal from the leader
    pub propose_timeout: bool,
    /// Did 9\Delta pass and we did not receive a responsive certificate from the leader
    pub responsive_timeout: bool,
    /// Did 8\Delta pass and we did not receive any certificate
    pub sync_commit_timeout: bool,
    /// Did we start the 2\Delta timer for committing synchronously
    pub started_sync_timer: bool,

    /// Did we detect any equivocation so far
    pub equivocation_detected: bool,

    /// The responsive votes received so far
    pub resp_votes: Certificate,
    /// The synchronous votes received so far
    pub sync_votes: Certificate,
    
    /// Shards to gather the proposal
    pub propose_gatherer: ShareGatherer,
    /// Shards to gather the responsive certificate
    pub resp_cert_gatherer: ShareGatherer,
    /// Shards to gather the synchronous certificate
    pub sync_cert_gatherer: ShareGatherer,

    /// The number of ack_votes received for this epoch
    pub ack_votes: Certificate,
    /// The ack message for which we got these votes
    pub ack_msg: Option<AckMsg>,

    /// Valid secret shares received to reconstruct for this round
    pub reconstruction_shares: Vec<Option<Share>>,
    /// Number of shares in reconstruction shares
    pub num_shares: usize,
    /// Last epoch for which we finished reconstruction
    /// This is used to determine whether or not to do reconstruction when entering a new epoch
    pub last_reconstruction_round: Epoch,
    /// The vector which we are supposed to reconstruct for this round
    pub current_round_reconstruction_vector: Option<Arc<AggregatePVSS>>,

    /// Future messages for proposals
    pub future_messages1: HashMap<Epoch, (Replica, ProtocolMsg)>,
    /// Future messages for responsive certificates 
    pub future_messages2: HashMap<Epoch, (Replica, ProtocolMsg)>,
    /// Future messages for ack messages
    pub future_messages3: HashMap<Epoch, Vec<(Replica,ProtocolMsg)>>,

    /// Last beacon time
    pub last_beacon_time: Instant,
}