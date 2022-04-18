use types::{AckData, Beacon, Certificate, Decryption, DeliverData, DirectProposal, Epoch, Proof, Replica, RespCertProposal, SyncCertProposal, Vote};
use crypto::hash::Hash;

use crate::ThreadRecvMsg;

/// All optrand events are defined here
#[derive(Debug,Clone)]
#[non_exhaustive]
pub(crate) enum Event {
    // Timers and Timeouts for epochs
    // TODO: If clearing works, remove the Epoch in every tuple
    TimeOut(TimeOutEvent),

    // New message events
    Message(Replica, NewMessage),

    // Other meta events
    NewEpoch(Epoch),

    OptimizerEvent(ThreadRecvMsg),
}

#[derive(Debug, Clone)]
pub(crate) enum NewMessage {
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
}

#[derive(Debug, Clone)]
pub(crate) enum TimeOutEvent {
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
}