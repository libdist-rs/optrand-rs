use types::{ProtocolMsg, SignedShard};

use crate::Context;
use std::sync::Arc;

impl Context {
    /// Deliver propose self
    pub async fn deliver_propose_self(&mut self, shard: Vec<u8>, auth: SignedShard)
    {
        self.net_send.send((self.num_nodes(),
            Arc::new(ProtocolMsg::DeliverPropose(shard, auth, self.config.id))
        )).unwrap();
    }
}