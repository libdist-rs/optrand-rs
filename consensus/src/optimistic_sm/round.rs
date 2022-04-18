use crypto::hash::Hash;
use fnv::FnvHashMap as HashMap;
use types::{AckData, Codeword, DeliverData, DirectProposal, PVSSVec, Replica, RespCertProposal, Result, SyncCertProposal, from_codewords, resp_threshold};
use types_upstream::WireReady;


#[derive(Debug, Default)]
pub struct RoundContext {
}

impl RoundContext {
    /// Resets the round context to its default value
    pub fn reset(&mut self, num_nodes: usize) {
        std::mem::take(self);
    }
}