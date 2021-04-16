use std::sync::Arc;
use crypto::{Beacon, Decryption};
use tokio_util::time::DelayQueue;
use types::{Epoch, ProtocolMsg, Replica};
use crate::{context::Context, events::Event};
use tokio::time::{Duration, Instant};

impl Context {
    /// Start the reconstruction for this round, caller must ensure that this is invoked only once in every epoch
    pub fn do_reconstruction(&mut self, ep: Epoch, dq:&mut DelayQueue<Event>) {
        if let None = self.current_round_reconstruction_vector.as_ref() {
            // We may have committed a block too eagerly.
            // We do not have the old sharing yet
            return;
        }
        let pvec = self.current_round_reconstruction_vector.as_ref().unwrap();
        let my_share = self.config.pvss_ctx.decrypt_share(&pvec.encs[self.id()], &self.my_secret_key, &mut crypto::std_rng());
        self.net_send.send((self.num_nodes(),
            Arc::new(ProtocolMsg::RawBeaconShare(ep, my_share.clone())),
        )).unwrap();
        // Include my share
        self.on_recv_share(ep, self.id(), my_share, dq);
    }

    /// on_recv_share called when a new share is received
    pub fn on_recv_share(&mut self, ep: Epoch, origin: Replica, share: Decryption, dq:&mut DelayQueue<Event>) {
        // Are we supposed to be dealing with this epoch?
        // A Byzantine leader may send shares for later epochs to try to get the nodes to reconstruct, be careful here.
        // Did we already finish reconstruction for this epoch?
        // If we finished this round, discard extra stale shares
        if ep != self.epoch {
            return;
        }
        // Check for validity
        // What are we supposed to be reconstructing?
        let pvec = self.current_round_reconstruction_vector.as_ref().unwrap();
        if let Some(err) = self.config.pvss_ctx.verify_share(origin, &pvec.encs[origin], &share, &self.pub_key_map[&origin]) {
            log::warn!("Share verification failed with {:?}", err);
        }
        self.reconstruction_shares[origin] = Some(share.dec);
        self.num_shares += 1;
        if self.num_shares < self.num_faults() + 1 {
            return;
        }
        // Time for reconstruction
        log::debug!("Trying reconstruction now");
        let b= self.config.pvss_ctx.reconstruct(&self.reconstruction_shares);
        let time_d = Instant::now().duration_since(self.last_beacon_time);
        log::info!("Got {} beacon in {}", ep, time_d.as_millis());
        self.last_beacon_time = Instant::now();
        self.finish_reconstruction(b, dq);
    }

    /// Finish reconstruction is a signal that we have a beacon. Broadcast the beacon to everyone and start the next round if possible.
    pub fn finish_reconstruction(&mut self, b: Beacon, dq:&mut DelayQueue<Event>) {
        self.last_reconstruction_round = self.epoch + 1;
        // Broadcast the beacon
        self.net_send.send((self.num_nodes(),// Because multicast
            Arc::new(
                ProtocolMsg::RawBeaconReady(self.epoch, b))
            )
        ).unwrap();
        // If elligible start the next epoch
        if self.highest_block.height == self.epoch {
            log::debug!("Ending epoch because of reconstruction");
            log::debug!("Starting next epoch");
            dq.insert(Event::EpochEnd(self.epoch), Duration::from_nanos(1));
        }
    }

    /// We received a beacon from someone else, handle it here
    pub fn on_recv_beacon(&mut self, ep:Epoch, b: Beacon, dq:&mut DelayQueue<Event>) {
        if ep != self.epoch || self.last_reconstruction_round != ep{
            return;
        }
        // Check if this is the correct beacon
        if !self.config.pvss_ctx.check_beacon(&b, &self.current_round_reconstruction_vector.as_ref().unwrap().comms) {
            log::warn!("Incorrect beacon received");
            return;
        }
        log::info!("Got {} beacon", ep);
        self.finish_reconstruction(b, dq);
    }
}