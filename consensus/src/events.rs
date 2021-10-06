use crypto::hash::Hash;
use types::{Beacon, Certificate, Epoch, Height, PVSSVec, Proposal, ProtocolMsg, Replica};

/// All optrand events are defined here
#[derive(Debug)]
pub enum Event {
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
}

#[derive(Debug)]
pub enum Deliver {
    NewProposeDeliver(),
    NewResponsiveCertificateDeliver(),
    NewSyncCertificateDeliver(),
}

#[derive(Debug)]
pub enum NewMessage {
    NewBeacon(Beacon, Epoch),
    // NewCertificate(Certificate),
    NewEpoch(Epoch),
    NewStatus(),
    NewPropose(Proposal),
    NewResponsiveVote(),
    NewSyncVote(),
    NewResponsiveCertificate(),
    NewSyncCertificate(),
    NewAck(),
    NewBeaconShare(),
}

#[derive(Debug)]
pub enum TimeOutEvent {
    /// When epoch_timer(e) = 0
    EpochTimeOut(Epoch),
    /// Start proposing at epoch_timer(e) = 9\Delta if we haven't already
    /// This is used to wait for a proposal for the highest certificate
    ProposeWaitTimeOut(Epoch),
    /// When epoch timer(e) = 7\Delta
    StopAcceptingProposals(Epoch),
    /// Scheduled 2\Delta time since we received the first valid proposal
    /// When this timesout, send <sync-vote_r, H(Bh), r>_pi to Lr
    SyncVoteWaitTimeOut(Epoch),
    /// When epoch timer(e) = 2\Delta
    StopResponsiveCommit(Epoch),
    /// When epoch timer(e) = 3\Delta
    StopSyncCommit(Epoch),
}