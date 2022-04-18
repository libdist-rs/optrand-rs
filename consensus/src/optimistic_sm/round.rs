use crypto::hash::Hash;
use fnv::FnvHashMap as HashMap;
use types::{AckData, Codeword, DeliverData, DirectProposal, PVSSVec, Replica, RespCertProposal, Result, SyncCertProposal, from_codewords, resp_threshold};
use types_upstream::WireReady;


#[derive(Debug, Default)]
pub struct RoundContext {

    /// Set to true for an epoch by the leader to indicate that we should stop waiting for certificates and start proposing
    pub(crate) status_time_over: bool,

    /// Set to true for an epoch to indicate that the deadline to propose has passed
    pub(crate) stop_accepting_proposals: bool,

    /// Set to true for an epoch to indicate that the deadline to accept sync certs has passed
    pub(crate) stop_accepting_sync_certs: bool,

    /// Set to true for an epoch to indicate that the deadline to accept acks has passed
    pub(crate) stop_accepting_acks: bool,

    /// Set to true for an epoch to indicate that
    /// 1. We received the proposal on time, and
    /// 2. We received the proposal directly from the leader for the current epoch
    pub(crate) received_proposal_directly: bool,

    /// Set to true to indicate that we received a sync certificate directly
    pub(crate) received_sync_cert_directly: bool,
    /// Set to true to indicate that we received a responsive certificate directly
    pub(crate) received_resp_cert_directly: bool,

    propose_deliver_share: Vec<Option<Codeword<DirectProposal>>>,
    num_propose_deliver_shares: usize,
    propose_cleaved_once: bool,

    sync_cert_deliver_share: Vec<Option<Codeword<SyncCertProposal>>>,
    num_sync_cert_deliver_shares: usize,
    sync_cert_cleaved_once: bool,

    resp_cert_deliver_share: Vec<Option<Codeword<RespCertProposal>>>,
    num_resp_cert_deliver_shares: usize,
    resp_cert_cleaved_once: bool,

    /// A mapping of the prop_hash to the number of acks supporting it
    acks: HashMap<Hash, usize>,
    pub(crate) enough_acks_for_epoch: bool,

    /// The shares we received to propose the beacon for this beacon
    /// Used by the leader
    round_shares: Vec<PVSSVec>,
    /// The indices of the nodes who sent the shares
    indices: Vec<Replica>,

    /// Used to measure time
    tick: Option<std::time::Instant>,
}

impl RoundContext {
    /// Resets the round context to its default value
    pub fn reset(&mut self, num_nodes: usize) {
        std::mem::take(self);
        self.propose_deliver_share.resize(num_nodes, None);
        self.sync_cert_deliver_share.resize(num_nodes, None);
        self.resp_cert_deliver_share.resize(num_nodes, None);
        self.tick = Some(std::time::Instant::now());
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
                    recon_th-1);
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
                    recon_th-1);
            let prop = if let Err(..) = &res {
                return Some(res);
            } else {
                res.unwrap()
            };
            return Some(Ok(prop.init()));
        }
        None
    }


    pub fn add_resp_cert_deliver_share(&mut self, from: Replica, d: DeliverData<RespCertProposal>) {
        if !self.resp_cert_cleaved_once {
            self.resp_cert_deliver_share[from] = Some(d.shard);
            self.num_resp_cert_deliver_shares += 1;
        }
    }

    pub(crate) fn cleave_resp_cert_from_deliver(&mut self, 
        num_nodes: usize, 
        recon_th: usize
    ) -> Option<Result<RespCertProposal>> {
        if self.resp_cert_cleaved_once {
            return None;
        }
        if self.num_resp_cert_deliver_shares == recon_th {
            let vec = std::mem::take(&mut self.resp_cert_deliver_share);
            self.resp_cert_cleaved_once = true;
            let res =  
                from_codewords(vec, 
                    num_nodes, 
                    recon_th-1);
            let prop = if let Err(..) = &res {
                return Some(res);
            } else {
                res.unwrap()
            };
            return Some(Ok(prop.init()));
        }
        None
    }

    pub(crate) fn add_ack(&mut self, 
        _from: Replica, 
        num_nodes: usize,
        ack: AckData,
    ) -> Result<Option<()>> {
        if self.enough_acks_for_epoch {
            return Ok(None);
        }
        let count = if let Some(x) = self.acks.get_mut(ack.prop_hash()) {
            *x += 1;
            *x
        } else {
            self.acks.insert(*ack.prop_hash(), 1);
            1
        };
        if count == resp_threshold(num_nodes) {
            self.enough_acks_for_epoch = true;
            return Ok(Some(()))
        }
        Ok(None)
    }

    /// Start the timer
    pub fn start_timer(&mut self)
    {
        self.tick = Some(std::time::Instant::now());
    }

    /// Only leaders should call this
    /// Stop the timer and report the time
    pub(crate) fn stop_and_measure(&mut self) -> std::time::Duration {
        let now = std::time::Instant::now();
        now.duration_since(self.tick.clone().unwrap())
    }
}