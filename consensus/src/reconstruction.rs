use std::sync::Arc;
use crypto::Decryption;
use types::{Epoch, ProtocolMsg, Replica};
use crate::context::Context;

impl Context {
    /// Start the reconstruction for this round, caller must ensure that this is invoked only once in every epoch
    pub async fn do_reconstruction(&mut self, ep: Epoch) {
        let mut queue = self.config.rand_beacon_queue.remove(&self.last_leader).unwrap();
        let sharing = queue.pop_front().unwrap();
        self.config.rand_beacon_queue.insert(self.last_leader, queue);
        let pvec = self.config.sharings.get(&sharing).unwrap();
        let my_share = self.config.pvss_ctx.decrypt_share(&pvec.encs[self.id()], &self.my_secret_key, &mut crypto::std_rng());
        self.net_send.send((self.num_nodes(),
            Arc::new(ProtocolMsg::RawBeaconShare(ep, my_share.clone())),
        )).unwrap();
        // Include my share
        self.on_recv_share(ep, self.id(), my_share).await;
    }

    /// on_recv_share called when a new share is received
    pub async fn on_recv_share(&mut self, ep: Epoch, origin: Replica, share: Decryption) {
        // Are we supposed to be dealing with this epoch?
        // A Byzantine leader may send shares for later epochs to try to get the nodes to reconstruct, be careful here.
        // Did we already finish reconstruction for this epoch?
        // If we finished this round, discard extra stale shares
        if ep != self.last_reconstruction_round + 1 {
            return;
        }
        // Check for validity
        // What are we supposed to be reconstructing?
        let pvec = self.current_round_reconstruction_vector.as_ref().unwrap();
        if let Some(err) = self.config.pvss_ctx.verify_share(origin, &pvec.encs[origin], &share, &self.pub_key_map[&origin]) {
            log::warn!("Share verification failed with {:?}", err);
        }
        self.reconstruction_shares[origin] = Some(share);
        self.num_shares += 1;
        if self.num_shares < self.num_faults() + 1 {
            return;
        }
        // Time for reconstruction
        log::info!("Trying reconstruction now");
    }
}