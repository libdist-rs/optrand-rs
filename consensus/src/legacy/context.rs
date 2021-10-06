use fnv::FnvHashMap as HashMap;

use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender};
use config::Node;
use types_upstream::WireReady;
use std::{collections::VecDeque, sync::Arc};
use types::{Block, CertType, Certificate, PVSSVec, ProtocolMsg, Replica, Storage};
use crate::{VerifyReceiver, events::Event, round::RoundContext};

pub struct Context {
    /// Our config file from the command line
    pub(crate) config: Node,

    /// Secret key that we will use to sign messages for the protocol
    pub(crate) my_secret_key: crypto_lib::Keypair,

    /// Everyone's public keys
    pub(crate) pub_key_map: HashMap<Replica, crypto_lib::PublicKey>,

    /// Network interface
    pub(crate) net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,

    /// Storage for all the data
    pub(crate) storage: Storage,

    /// Event Queue
    pub(crate) ev_queue: VecDeque<Event>,

    /// The context for one epoch/round
    pub(crate) round_ctx: RoundContext,

    /// A task that produces new pvss shares
    pub(crate) sh_out: Receiver<PVSSVec>,

    /// A task that verifies shares
    pub(crate) sh_verifier: VerifyReceiver,

    /// A task that returns verified shares
    pub(crate) verified_shares: Receiver<(Replica, PVSSVec)>,
    
    /// This will be used by other tasks to notify that a share is verified
    pub(crate) verified_shares_recv: Sender<(Replica, PVSSVec)>,

    /// The block with the highest certificate seen so far
    pub(crate) highest_block: Arc<Block>,

    /// The highest certificate seen so far
    pub(crate) highest_cert: Arc<CertType>,
}

impl Context {
    pub(crate) fn send_message(&mut self, to:Replica, msg: ProtocolMsg) {
        if self.id() == to {
            let init_msg = msg.init();
            if let ProtocolMsg::InvalidMessage = init_msg {
                panic!("Self init should not be invalid");
            }
            self.ev_queue.push_back(Event::NewMsgIn(to, init_msg));
        } else {
            self.net_send.send((to, Arc::new(msg))).unwrap();
        }
    }

    pub(crate) fn broadcast(&mut self, msg: ProtocolMsg) {
        let init_msg = msg.clone().init();
        if let ProtocolMsg::InvalidMessage = init_msg {
            panic!("Self init should not be invalid");
        }
        self.ev_queue.push_back(Event::NewMsgIn(self.id(), init_msg));
        self.net_send.send((self.num_nodes(), Arc::new(msg))).unwrap();
    } 
}