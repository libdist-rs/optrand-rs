use types::{ProtocolMsg, SignedShard};

use crate::Context;
use std::sync::Arc;

impl Context {
    /// Deliver propose self; Send my shard to everyone
    pub async fn deliver_propose_self(&mut self, shard: Vec<u8>, auth: SignedShard)
    {
        self.net_send.send((self.num_nodes(),
            Arc::new(ProtocolMsg::DeliverPropose(shard, auth, self.config.id))
        )).unwrap();
        self.propose_shard_self_sent = true;
    }

    /// Deliver responsive cert self; Send my shard to everyone
    pub async fn deliver_resp_cert_self(&mut self, shard:Vec<u8>, auth: SignedShard) {
        self.net_send.send((self.num_nodes(),
            Arc::new(ProtocolMsg::DeliverResponsiveCert(shard, auth, self.config.id))
        )).unwrap();
        self.resp_cert_shard_self_sent = true;
    }

    /// Deliver sync cert self. Send my shard to everyone
    pub async fn deliver_sync_cert_self(&mut self, shard:Vec<u8>, auth: SignedShard) {
        self.net_send.send((self.num_nodes(),
            Arc::new(ProtocolMsg::DeliverSyncCert(shard, auth, self.config.id))
        )).unwrap();
        self.sync_cert_shard_self_sent = true;
    }
}