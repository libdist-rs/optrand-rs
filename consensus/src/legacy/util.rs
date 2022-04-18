use crate::{Context, VerifyReceiver, round::RoundContext};
use types::{Certificate, GENESIS_BLOCK, GENESIS_CERT, PVSSVec, ProtocolMsg, Replica, Storage};
use std::{collections::VecDeque, mem, sync::Arc};
use config::Node;
use tokio::sync::mpsc::{Receiver, UnboundedSender, channel};
use fnv::FnvHashMap as HashMap;

impl Context {
    /// Consume the config and take over it
    pub fn new(
        mut config: Node,
        net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,
        sh_out: Receiver<PVSSVec>,
        sh_verifier: VerifyReceiver,
    ) -> Self {
        let n = config.num_nodes;
        let sk = config.get_secret_key();
        let genesis_block = Arc::new(GENESIS_BLOCK);
        let beacon_queue = mem::take(&mut config.rand_beacon_queue);
        let future_buffer = mem::take(&mut config.beacon_sharing_buffer);
        let (sin, sout) = channel(config.num_nodes*config.num_nodes);
        let mut c = Context {
            config,
            my_secret_key: sk,
            net_send,
            storage: Storage::new(n),
            round_ctx: RoundContext::new(),
            sh_out,
            sh_verifier,
            verified_shares: sout,
            verified_shares_recv: sin,
            highest_block: genesis_block.clone(),
            ev_queue: VecDeque::new(),
            pub_key_map: HashMap::default(),
            highest_cert: Arc::new(GENESIS_CERT),
        };
        for (replica, aggs) in beacon_queue {
            c
                .storage
                .rand_beacon_queue
                .insert(replica, aggs);
        }
        for (replica, vecs) in future_buffer {
            c
                .storage
                .next_proposal_pvss_sharings
                .insert(replica, vecs);
        }
        c.storage
            .add_new_block(GENESIS_BLOCK);
        c.storage
            .commit_new_block(genesis_block);

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
        self.next_of(self.round_ctx.current_leader)
    }

    /// What is the next leader, if prev is the current leader
    pub fn next_of(&self, prev: Replica) -> Replica {
        (prev + 1) % self.num_nodes()
    }

    /// Compute 3n/4+1 
    pub const fn optimistic(&self) -> usize {
        ((3*self.config.num_nodes)/4) + 1
    } 
}
