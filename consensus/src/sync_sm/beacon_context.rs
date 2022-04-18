use std::collections::VecDeque;

use crypto::{DSSPublicKey, hash::Hash};
use fnv::FnvHashMap as HashMap;
use types::{AggregatePVSS, Beacon, DbsContext, Decryption, Epoch, Replica, Result, Share};

#[derive(Debug, Default)]
pub(crate) struct BeaconContext {
    /// These are the beacons for every epoch 
    /// Specified as O_r in the protocol
    epoch_beacons: HashMap<Epoch, Beacon>,
    /// The pvss that we will be checking decryptions against in every epoch
    epoch_pvss: HashMap<Epoch, AggregatePVSS>,
    /// Unverified shares received for epochs before we reach the epoch
    unverified_epoch_shares: HashMap<Epoch, VecDeque<(Replica, Decryption)>>,
    /// Verified shares for an epoch
    verified_epoch_shares: HashMap<Epoch, Vec<Option<Share>>>,
    /// Number of verified shares received for an epoch
    num_verified_shares: HashMap<Epoch, usize>,

    /// This contains the storage for all the beacons
    pvss_store: HashMap<Hash, AggregatePVSS>,
}

impl BeaconContext {
    pub(crate) fn add_epoch_pvss(&mut self, 
        e: Epoch,
        pvec: AggregatePVSS,
        num_nodes: usize,
    ) 
    {
        self.epoch_pvss.insert(e, pvec);
        if !self.unverified_epoch_shares.contains_key(&e) {
            self.unverified_epoch_shares.insert(e, VecDeque::new());
        }
        self.num_verified_shares.insert(e, 0);

        let mut deq = Vec::with_capacity(num_nodes);
        deq.resize(num_nodes, None);
        self.verified_epoch_shares.insert(e, deq);
    }

    /// `thresh` should be f
    pub(crate) fn add_beacon_share(&mut self,
        dbs_ctx: &DbsContext,
        myid: Replica,
        pk_map: &HashMap<Replica, DSSPublicKey>,
        e: Epoch,
        from: Replica,
        dec: Decryption,
        num_faults: usize,
    ) -> Result<Option<Beacon>>
    {
        // Already finished this epoch, move on
        if self.epoch_beacons.contains_key(&e) {
            return Ok(None);
        }

        // Are we ready for Epoch e
        if !self.epoch_pvss.contains_key(&e) {
            // We are not ready for epoch e
            if self.unverified_epoch_shares.contains_key(&e) {
                self.unverified_epoch_shares
                    .get_mut(&e)
                    .ok_or(format!("We just added a vec if there wasn't one"))?
                    .push_back((from, dec));
            } else {
                let mut vec = VecDeque::new();
                vec.push_back((from, dec));
                self.unverified_epoch_shares.insert(e, vec);
            }
            return Ok(None)
        }
        // We are ready for epoch e (Then unverified and verified for e are set)
        // 1) Take this share and verify it 
        // 2) Take other verified shares, and add it to the verified shares
        // 3) Try reconstruction

        // Step 1.1: Get the pvss vec
        let pvss = self.epoch_pvss
            .get(&e)
            .ok_or(
                format!("We just checked if have the epoch pvss or not")
            )?;
        if from != myid {
            // Otherwise check if this share is valid
            if let Some(err) = dbs_ctx.verify_share(
                from, 
                &pvss.encs[from], 
                &dec, 
                &pk_map[&from]) 
            {
                return Err(format!("Crypto Error: {:?}", err).into());
            }
        }
        let verified = self.verified_epoch_shares
            .get_mut(&e)
            .ok_or(
                format!("We are ready for e, we must have inserted it in add_epoch_pvss")
            )?;
        let num_verified = self.num_verified_shares
            .get_mut(&e)
            .ok_or(
                format!("We are ready for e, we must have inserted it in add_epoch_pvss")
            )?;
        verified[myid] = Some(dec.dec);
        *num_verified += 1;

        if *num_verified > num_faults {
            return self.reconstruct(e, dbs_ctx);
        }

        // Step 2
        while let Some((from_unv, dec_unv)) = self.unverified_epoch_shares.get_mut(&e).unwrap().pop_front() {
            if let Some(err) = dbs_ctx.verify_share(
                from_unv, 
                &pvss.encs[from_unv], 
                &dec_unv, 
                &pk_map[&from_unv]) 
            {
                log::warn!("Crypto Error when verifying a beacon share for {}: {:?}", from_unv, err);
                continue;
            }
            verified[from_unv] = Some(dec_unv.dec);
            *num_verified += 1;
            if *num_verified > num_faults {
                // Do reconstruction
                return self.reconstruct(e, dbs_ctx);
            }
        }
        // Unfortunately we did not succeed in reconstructing
        Ok(None)
    }

    /// Call after checking that there are t+1 shares
    fn reconstruct(&mut self, e: Epoch, dbs_ctx: &DbsContext) -> Result<Option<Beacon>>
    {
        let shares = self.verified_epoch_shares
            .remove(&e)
            .ok_or(format!("Must call reconstruct after having t+1 shares"))?;
        let beacon = dbs_ctx.reconstruct(&shares);
        self.epoch_beacons.insert(e, beacon.clone());
        self.epoch_pvss.remove(&e);
        self.verified_epoch_shares.remove(&e);
        self.unverified_epoch_shares.remove(&e);
        return Ok(Some(beacon))
    }
}