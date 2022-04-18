use std::sync::Arc;
use types::*;
use crypto::hash::Hash;

/// All optrand events are defined here
#[derive(Debug,Clone)]
#[non_exhaustive]
pub(crate) enum Event {
    LoopBack(ProtocolMsg),
    // TODO: If clearing works, remove the Epoch in every tuple

    // Timers and Timeouts for epochs
    /// When epoch_timer(e) = 0
    EpochTimeOut(Epoch),
    /// Start proposing at epoch_timer(e) = 9\Delta if we haven't already
    /// This is used to wait for a proposal for the highest certificate
    ProposeWaitTimeOut(Epoch),
    /// When epoch timer(e) = 7\Delta
    StopAcceptingProposals(Epoch),
    /// Scheduled 2\Delta time since we received the first valid proposal
    /// When this timesout, send <sync-vote_r, H(Bh), r>_pi to Lr
    SyncVoteWaitTimeOut(Epoch, Hash),
    /// When epoch timer(e) = 2\Delta
    StopAcceptingAck(Epoch),
    /// When epoch timer(e) = 3\Delta
    StopSyncCommit(Epoch),
    /// When 2\Delta passes after sync voting
    /// Holds the epoch and the hash of the proposal
    Commit(Epoch, Hash),

    // New message events
    Status(Vote, Certificate<Vote>),
    Propose(DirectProposal, Proof<DirectProposal>),
    DeliverPropose(Replica, DeliverData<DirectProposal>),
    SyncVote(Vote, Certificate<Vote>),
    RespVote(Vote, Certificate<Vote>),
    SyncCert(SyncCertProposal, Proof<SyncCertProposal>),
    RespCert(RespCertProposal, Proof<RespCertProposal>),
    DeliverSyncCert(Replica, DeliverData<SyncCertProposal>),
    DeliverRespCert(Replica, DeliverData<RespCertProposal>),
    Ack(AckData, Certificate<AckData>),
    BeaconShare(Epoch, Decryption),
    BeaconReady(Epoch, Beacon),

    // Other meta events
    NewEpoch(Epoch),
}