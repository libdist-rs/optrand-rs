use config::Node;
use crypto::{rand::prelude::StdRng, std_rng};
use crypto_lib::{Keypair, PublicKey};
use types::{Block, Certificate, DirectProposal, Epoch, MTAccumulatorBuilder, Replica, RespCertProposal, START_EPOCH, Storage, SyncCertProposal, Vote, reed_solomon_threshold};
use fnv::FnvHashMap as HashMap;

use crate::{ThreadReceiver, ThreadSender};

use super::{BeaconContext, LeaderContext, RoundContext};

/// Builds all the messages for the protocol
pub struct OptRandStateMachine {
    // General data
    pub(crate) config: Node,
    pub(crate) sk: Keypair,
    pub(crate) pk_map: HashMap<Replica, PublicKey>,

    // Round state
    pub(crate) epoch: Epoch,
    pub(crate) rnd_ctx: RoundContext,
    pub(crate) highest_certificate: (
        Certificate<Vote>, 
        std::sync::Arc<Block>,
        Vote,
    ),

    // pub(crate) share_generator: PvecReceiver,
    pub(crate) leader_thread_sender: ThreadSender,
    pub leader_thread_receiver: ThreadReceiver,

    /// Beacon PVSS Shares
    pub(crate) beacon_ctx: BeaconContext,

    // Helpers
    pub(crate) prop_acc_builder: MTAccumulatorBuilder<DirectProposal>,
    pub(crate) sync_cert_acc_builder: MTAccumulatorBuilder<SyncCertProposal>,
    pub(crate) resp_cert_acc_builder: MTAccumulatorBuilder<RespCertProposal>,
    
    // Leader context
    pub(crate) leader_ctx: LeaderContext,

    // Randomness for Crypto
    pub(crate) rng: StdRng,

    // Permanent storage
    pub(crate) storage: Storage,
}

impl OptRandStateMachine {
    pub fn new(
        mut config: Node,
        ch: (ThreadSender, ThreadReceiver),
    ) -> Self {
        let sk = config.get_secret_key();
        let pk_map = config.get_public_key_map();
        let (storage, gen_arc) = {
            let rand_queue = std::mem::take(&mut config.rand_beacon_queue);
            let mut t = Storage::new(config.num_nodes, rand_queue);
            t.add_delivered_block(Block::GENESIS_BLOCK);
            let gen_arc = t.get_delivered_block_by_height(Block::GENESIS_BLOCK.height()).expect("Could not find genesis block even after adding it to the storage");
            t.commit_block(gen_arc.clone())
                .expect("Failed to commit the genesis block");
            (t, gen_arc)
        };
        let f = reed_solomon_threshold(config.num_nodes)-1;
        let mut prop_acc_builder = MTAccumulatorBuilder::new();
        prop_acc_builder.set_f(f);
        prop_acc_builder.set_n(config.num_nodes);
        let mut sync_cert_acc_builder = MTAccumulatorBuilder::new();
        sync_cert_acc_builder
            .set_n(config.num_nodes)
            .set_f(f);
        let mut resp_cert_acc_builder = MTAccumulatorBuilder::new();
        resp_cert_acc_builder
            .set_n(config.num_nodes)
            .set_f(f);
        let leader_ctx = LeaderContext::new(config.num_nodes);
        
        Self {
            config,
            epoch: START_EPOCH,
            sk: sk.clone(),
            highest_certificate: (Certificate::default(), gen_arc, Vote::GENESIS),
            rng: std_rng(),
            rnd_ctx: RoundContext::default(),
            pk_map,
            storage,
            prop_acc_builder,
            sync_cert_acc_builder,
            resp_cert_acc_builder,
            beacon_ctx: BeaconContext::default(),
            leader_ctx,
            leader_thread_sender: ch.0,
            leader_thread_receiver: ch.1,
        }
    }


}
