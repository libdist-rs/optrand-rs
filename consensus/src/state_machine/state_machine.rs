use config::Node;
use crypto::{rand::prelude::StdRng, std_rng};
use crypto_lib::{Keypair, PublicKey};
use types::{Beacon, Block, Certificate, DirectProposal, Epoch, MTAccumulator, MTAccumulatorBuilder, Proposal, ProposalData, Replica, START_EPOCH, SignatureBuilder, Storage, SyncCertProposal, Vote};
use fnv::FnvHashMap as HashMap;

use crate::RoundContext;

/// Builds all the messages for the protocol
pub struct OptRandStateMachine {
    // General data
    pub(crate) config: Node,
    pub(crate) sk: Keypair,
    pub(crate) pk_map: HashMap<Replica, PublicKey>,

    // Round state
    pub(crate) epoch: Epoch,
    pub(crate) rnd_ctx: RoundContext,
    pub(crate) latest_beacon: Option<Beacon>,
    pub(crate) highest_certificate: (
        Certificate<Vote>, 
        std::sync::Arc<Block>,
        Vote,
    ),

    // Helpers
    pub(crate) prop_acc_builder: MTAccumulatorBuilder<DirectProposal>,
    pub(crate) sync_cert_acc_builder: MTAccumulatorBuilder<SyncCertProposal>,
    // pub(crate) prop_sig_builder: SignatureBuilder<MTAccumulator<Proposal>>,

    // Randomness for Crypto
    pub(crate) rng: StdRng,

    // Permanent storage
    pub(crate) storage: Storage,
}

impl OptRandStateMachine {
    pub fn new(config: Node) -> Self {
        let sk = config.get_secret_key();
        let pk_map = config.get_public_key_map();
        let (storage, gen_arc) = {
            let mut t = Storage::new(config.num_nodes);
            t.add_delivered_block(Block::GENESIS_BLOCK);
            let gen_arc = t.get_delivered_block_by_height(Block::GENESIS_BLOCK.height()).expect("Could not find genesis block even after adding it to the storage");
            t.commit_block(gen_arc.clone())
                .expect("Failed to commit the genesis block");
            (t, gen_arc)
        };
        let mut prop_acc_builder = MTAccumulatorBuilder::new();
        prop_acc_builder.set_f(config.num_faults);
        prop_acc_builder.set_n(config.num_nodes);
        let mut sync_cert_acc_builder = MTAccumulatorBuilder::new();
        sync_cert_acc_builder
            .set_n(config.num_nodes)
            .set_f(config.num_faults);
        Self {
            config,
            epoch: START_EPOCH,
            sk: sk.clone(),
            // prop_sig_builder: SignatureBuilder::new(sk),
            latest_beacon: None,
            highest_certificate: (Certificate::default(), gen_arc, Vote::GENESIS),
            rng: std_rng(),
            rnd_ctx: RoundContext::default(),
            pk_map,
            storage,
            prop_acc_builder,
            sync_cert_acc_builder,
        }
    }


}
