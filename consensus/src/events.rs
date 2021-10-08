use types::{Beacon, Certificate, DeliverData, DirectProposal, Epoch, PVSSVec, Proof, Proposal, ProposalData, Replica, SyncCertProposal, Vote};
use crypto::hash::Hash;

/// All optrand events are defined here
#[derive(Debug,Clone)]
pub(crate) enum Event {
    // Timers and Timeouts for epochs
    // TODO: If clearing works, remove the Epoch in every tuple
    TimeOut(TimeOutEvent),

    // New message events
    Message(Replica, NewMessage),

    // Deliver events
    Deliver(Deliver),

    // Other meta events
    Commit(),
    Equivocation(),
    FastForwardEpoch(Epoch),
}

#[derive(Debug, Clone)]
pub enum Deliver {
    NewProposeDeliver(),
    NewResponsiveCertificateDeliver(),
    NewSyncCertificateDeliver(),
}

#[derive(Debug, Clone)]
pub enum NewMessage {
    Beacon(Beacon, Epoch),
    Epoch(Epoch),
    Status(Vote, Certificate<Vote>, PVSSVec),
    Propose(DirectProposal, Proof<DirectProposal>),
    DeliverPropose(Replica, DeliverData<DirectProposal>),
    ResponsiveVote(),
    SyncVote(Vote, Certificate<Vote>),
    ResponsiveCertificate(),
    SyncCert(SyncCertProposal, Proof<SyncCertProposal>),
    DeliverSyncCert(Replica, DeliverData<SyncCertProposal>),
    Ack(),
    BeaconShare(),
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
    StopResponsiveCommit(Epoch),
    /// When epoch timer(e) = 3\Delta
    StopSyncCommit(Epoch),
    /// When 2\Delta passes after sync voting
    /// Holds the epoch and the hash of the proposal
    Commit(Epoch, Hash),
}