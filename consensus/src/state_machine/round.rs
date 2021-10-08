use types::{Codeword, DeliverData, DirectProposal, PVSSVec, Proposal, ProposalData, Replica, Result, SyncCertProposal, from_codewords};
use types_upstream::WireReady;


#[derive(Debug, Default)]
pub struct RoundContext {

    /// Set to true for an epoch by the leader to indicate that we should stop waiting for certificates and start proposing
    pub(crate) status_time_over: bool,

    /// Set to true for an epoch to indicate that the deadline to propose has passed
    pub(crate) stop_accepting_proposals: bool,

    /// Set to true for an epoch to indicate that the deadline to accept sync certs has passed
    pub(crate) stop_accepting_sync_certs: bool,

    /// Set to true for an epoch to indicate that
    /// 1. We received the proposal on time, and
    /// 2. We received the proposal directly from the leader for the current epoch
    pub(crate) received_proposal_directly: bool,

    /// Set to true to indicate that we received a sync certificate directly
    pub(crate) received_sync_cert_directly: bool,

    propose_deliver_share: Vec<Option<Codeword<DirectProposal>>>,
    num_propose_deliver_shares: usize,
    propose_cleaved_once: bool,

    sync_cert_deliver_share: Vec<Option<Codeword<SyncCertProposal>>>,
    num_sync_cert_deliver_shares: usize,
    sync_cert_cleaved_once: bool,

    /// The shares we received to propose the beacon for this beacon
    /// Used by the leader
    round_shares: Vec<PVSSVec>,
    /// The indices of the nodes who sent the shares
    indices: Vec<Replica>,
}

impl RoundContext {
    /// Resets the round context to its default value
    pub fn reset(&mut self, num_nodes: usize) {
        std::mem::take(self);
        self.propose_deliver_share.resize(num_nodes, None);
    }

    pub fn add_round_share(&mut self, from: Replica, pvec: PVSSVec) {
        self.round_shares.push(pvec);
        self.indices.push(from);
    }

    pub(crate) fn num_beacon_shares(&self) -> usize {
        self.indices.len()
    }

    pub(crate) fn cleave_beacon_shares(&mut self) -> (Vec<PVSSVec>, Vec<usize>) {
        (
            std::mem::take(&mut self.round_shares),
            std::mem::take(&mut self.indices)
        )
    }

    pub fn add_propose_deliver_share(&mut self, from: Replica, d: DeliverData<DirectProposal>) {
        if !self.propose_cleaved_once {
            self.propose_deliver_share[from] = Some(d.shard);
            self.num_propose_deliver_shares += 1;
        }
    }

    pub(crate) fn cleave_propose_from_deliver(&mut self, 
        num_nodes: usize, 
        recon_th: usize
    ) -> Option<Result<DirectProposal>> {
        if self.propose_cleaved_once {
            return None;
        }
        if self.num_propose_deliver_shares == recon_th {
            let vec = std::mem::take(&mut self.propose_deliver_share);
            self.propose_cleaved_once = true;
            let res =  
                from_codewords(vec, 
                    num_nodes, 
                    recon_th);
            let prop = if let Err(..) = &res {
                return Some(res);
            } else {
                res.unwrap()
            };
            return Some(Ok(prop.init()));
        }
        None
    }

    pub fn add_sync_cert_deliver_share(&mut self, from: Replica, d: DeliverData<SyncCertProposal>) {
        if !self.sync_cert_cleaved_once {
            self.sync_cert_deliver_share[from] = Some(d.shard);
            self.num_sync_cert_deliver_shares += 1;
        }
    }

    pub(crate) fn cleave_sync_cert_from_deliver(&mut self, 
        num_nodes: usize, 
        recon_th: usize
    ) -> Option<Result<SyncCertProposal>> {
        if self.sync_cert_cleaved_once {
            return None;
        }
        if self.num_sync_cert_deliver_shares == recon_th {
            let vec = std::mem::take(&mut self.sync_cert_deliver_share);
            self.sync_cert_cleaved_once = true;
            let res =  
                from_codewords(vec, 
                    num_nodes, 
                    recon_th);
            let prop = if let Err(..) = &res {
                return Some(res);
            } else {
                res.unwrap()
            };
            return Some(Ok(prop.init()));
        }
        None
    }

}