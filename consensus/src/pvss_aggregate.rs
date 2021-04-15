use crypto::{AggregatePVSS, DecompositionProof, PVSSVec};
use types::{Epoch, ProtocolMsg, Replica};
use std::sync::Arc;

use crate::Context;

impl Context {
    /// Do aggregation is called when t+1 shares are verified and ready
    /// In this function, we aggregate them and send it to all the nodes
    pub async fn do_aggregation(&mut self) {
        let myid = self.config.id;
        let (comb_pvss, comb_proof) = self.config.pvss_ctx.aggregate(&self.pvss_indices, &self.pvss_shares);
        for i in 0..self.num_nodes() {
            if i == myid {
                continue;
            }
            self.net_send.send((i, 
                Arc::new(ProtocolMsg::RawPVSSSharingReady(self.id(), comb_pvss.clone(), comb_proof[i].clone()))
            )).unwrap();
        }
        self.pvss_indices.clear();
        self.pvss_shares.clear();
        let h = crypto::hash::ser_and_hash(&comb_pvss);
        let mut queue = self.config.beacon_sharing_buffer.remove(&myid).unwrap();
        queue.push_back(h);
        self.config.beacon_sharing_buffer.insert(myid, queue);
        self.config.sharings.insert(h, comb_pvss);
        self.decomps.insert(h, comb_proof);
    }

    /// This is called when sharings are sent to me to propose in the next round
    pub async fn new_epoch_sharing(&mut self, sender: Replica, pvec: PVSSVec) {
        let num_shares = self.pvss_shares.len();
        // These shares are meant for me to propose in the next round
        if num_shares > self.config.num_faults + 1 {
            // We have sufficient shares
            return;
        }
        // Verify that the PVSS vector is correct
        if let Some(err) = self.config.pvss_ctx.verify_sharing(&pvec, &self.pub_key_map[&sender]) {
            log::warn!("Got an invalid sharing from {} with error {:?}", sender, err);
            return;
        }
        self.pvss_indices.push(sender);
        self.pvss_shares.push(pvec);
        if num_shares == self.config.num_faults {
            // Aggregate them
            self.do_aggregation().await;
        }
    }

    /// This is called when I receive an aggregate pvss vector from someone for a future round
    pub async fn new_sharing_ready(&mut self, origin: Replica, pvec: AggregatePVSS, proof: DecompositionProof) {
        if let Some(err) = self.config.pvss_ctx.decomp_verify(&pvec, &proof, &self.pub_key_map) {
            log::warn!("Got an incorrect aggregation {:?}", err);
            return;
        }
        // Add pvss_sharing to the config
        if let Some(err) = self.config.pvss_ctx.pverify(&pvec) {
            log::warn!("Got an incorrect aggregation; pverify failed {:?}", err);
            return;
        }
        // Add this for this node's next epoch
        let h = crypto::hash::ser_and_hash(&pvec);
        let mut queue = self.config.beacon_sharing_buffer.remove(&origin).unwrap();
        queue.push_back(h);
        self.config.beacon_sharing_buffer.insert(origin, queue);
        self.config.sharings.insert(h, pvec);
        self.my_decomps.insert(h, proof);
    }
}