use types::*;
use std::sync::Arc;
use crate::{ShareGatherer, Context};

#[derive(Default)]
pub struct RoundContext {
    /// The current epoch
    pub epoch: Epoch,
    /// The current leader
    pub current_leader: Replica,
    
    /// Did I send my shards to everyone
    pub propose_shard_self_sent: bool,
    /// Did I send my shards to everyone
    pub resp_cert_shard_self_sent: bool,
    /// Did I send my shards to everyone
    pub sync_cert_shard_self_sent: bool,
    
    /// Did I send everyone their shards
    pub propose_shard_others_sent: bool,
    /// Did I send everyone their shards
    pub resp_cert_shard_others_sent: bool,
    /// Did I send everyone their shards
    pub sync_cert_shard_others_sent: bool,
    
    // Whether we received objects directly
    pub propose_received_directly: bool,
    // Whether we received objects directly
    pub resp_cert_received_directly: bool,
    // Whether we received objects directly
    pub sync_cert_received_directly: bool,
    
    /// Whether we should stop processing deliver messages
    pub propose_received: Option<Arc<Proposal>>,
    /// Whether we should stop processing deliver messages
    pub resp_cert_received: Option<Arc<ResponsiveCertMsg>>,
    /// Whether we should stop processing deliver messages
    pub sync_cert_received: Option<Arc<SyncCertMsg>>,

    /// Should we vote for this epoch or not?
    pub is_epoch_correct: bool,

    /// Did 4\Delta pass and we did not receive a proposal from the leader
    pub propose_timeout: bool,
    /// Did 9\Delta pass and we did not receive a responsive certificate from the leader
    pub responsive_timeout: bool,
    /// Did 8\Delta pass and we did not receive any certificate
    pub sync_commit_timeout: bool,
    /// Did we start the 2\Delta timer for committing synchronously
    pub started_sync_timer: bool,

    /// Did we detect any equivocation so far
    pub equivocation_detected: bool,

    /// The responsive votes received so far
    pub resp_votes: Certificate,
    /// The synchronous votes received so far
    pub sync_votes: Certificate,
    
    /// Shards to gather the proposal
    pub propose_gatherer: ShareGatherer,
    /// Shards to gather the responsive certificate
    pub resp_cert_gatherer: ShareGatherer,
    /// Shards to gather the synchronous certificate
    pub sync_cert_gatherer: ShareGatherer,

    /// The number of ack_votes received for this epoch
    pub ack_votes: Certificate,
    /// The ack message for which we got these votes
    pub ack_msg: Option<AckMsg>,

    /// We can propose in an epoch using two paths:
    /// 1. Via already having the certificate for the previous epoch
    /// 2. After 2\Delta timeout
    /// The event queue may deliver a propose after one of the paths succeeds, so we need to ensure that the other path also doesn't propose to prevent equivocation
    pub already_proposed: bool,
    /// We may get t+1 pvss after a timeout, so we want to retain that state for the epoch
    pub status_timed_out: bool,
}

impl RoundContext {
    pub(crate) fn new() -> Self {
        let mut x = Self {
            epoch: START_EPOCH,
            ..Default::default()
        };
        x.reset();
        x
    }

    /// Reset the context for the round
    pub(crate) fn reset(&mut self) {
        self.propose_shard_self_sent = false;
        self.resp_cert_shard_self_sent = false;
        self.sync_cert_shard_self_sent = false;

        self.propose_shard_others_sent = false;
        self.resp_cert_shard_others_sent = false;
        self.sync_cert_shard_others_sent = false;

        self.propose_received_directly = false;
        self.resp_cert_received_directly = false;
        self.sync_cert_received_directly = false;

        self.propose_received = None;
        self.resp_cert_received = None;
        self.sync_cert_received = None;

        self.is_epoch_correct = true;

        self.propose_timeout = false;
        self.responsive_timeout = false;
        self.sync_commit_timeout = false;
        self.started_sync_timer = false;

        self.equivocation_detected = false;

        self.resp_votes = Certificate::empty_cert();
        self.sync_votes = Certificate::empty_cert();

        self.propose_gatherer.clear();
        self.resp_cert_gatherer.clear();
        self.sync_cert_gatherer.clear();

        self.ack_votes = Certificate::empty_cert();
        self.ack_msg = None;

        self.already_proposed = false;
        self.status_timed_out = false;
    }

    /// Next resets the context and increases the epoch counter
    pub(crate) fn next(&mut self) {
        self.epoch = self.epoch + 1;
        self.reset();
    }
}

impl Context {
    #[inline]
    pub(crate) fn epoch(&self) -> Epoch {
        self.round_ctx.epoch
    }

    #[inline]
    pub(crate) fn leader(&self) -> Replica {
        self.round_ctx.current_leader
    }
}