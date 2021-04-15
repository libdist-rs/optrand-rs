use tokio_util::time::DelayQueue;
use types::{DataWithAcc, ProtocolMsg, ResponsiveCertMsg};
use std::sync::Arc;
use crate::{Context, Event, get_sign};



impl Context {
    /// A function called on receiving a shard or on receiving the responsive certificate
    pub async fn do_deliver_sync_cert(&mut self, acc: DataWithAcc, shards: Vec<Vec<u8>>, dq: &mut DelayQueue<Event>) {
        let myid = self.config.id;
        let my_shard_auth = get_sign(&acc, myid);
        // Sending my shard; Execute once every epoch
        if !self.sync_cert_shard_self_sent {
            self.deliver_sync_cert_self(shards[myid].clone(), 
                my_shard_auth.clone()).await;
        }
        if self.sync_cert_shard_others_sent {
            return;
        }
        for i in 0..self.config.num_nodes {
            if myid == i {
                continue;
            }
            let your_shard_auth = get_sign(&acc, i);
            // Sending your shard
            self.net_send.send(
                (i,
                    Arc::new(ProtocolMsg::DeliverSyncCert(
                        shards[i].clone(),
                        your_shard_auth,
                        i
                    ))
                )
            ).unwrap();
        }
        self.sync_cert_shard_others_sent = true;
    }

    /// Received responsive certificate directly
    pub async fn receive_sync_cert_direct(&mut self, rcert: ResponsiveCertMsg, cert: DataWithAcc, dq: &mut DelayQueue<Event>) {
        
    }
}