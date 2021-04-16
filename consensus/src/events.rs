use crypto::hash::Hash;
use types::{Epoch, Height};

/// All optrand events are defined here
#[derive(PartialEq, Debug)]
pub enum Event {
    /// Start proposing, status round finished
    /// This event will be triggered if the leader of an epoch needs to wait for status messages before proposing
    Propose,
    /// An epoch has ended, start a new epoch
    /// This is an event notifying that we have finished an old epoch
    /// This can occur either by committing in epoch r-1 or timer for epoch r-1 expires
    EpochEnd(Epoch),
    /// ProposeTimeout tells whether we have timed out for proposing
    ProposeTimeout,
    /// VoteTimeout to send or not to send synchronous vote messages on the block hash
    VoteTimeout(Hash),
    /// Sync commit event is triggered when sync cert is observed
    SyncCommit(Height),
    /// Responsive Commit Timeout; Do not commit blocks after this
    ResponsiveCommitTimeout,
    /// Sync Commit Timeout; Do not synchronously commit after this
    SyncCommitTimeout,
    /// Sync Timer
    SyncTimer(Height), 
}

impl Event {
    pub fn to_string(&self) -> &'static str {
        match self {
            Event::Propose => "Propose",
            Event::EpochEnd(_) => "Epoch Ended",
            Event::ProposeTimeout => "Propose Timed out",
            Event::VoteTimeout(_) => "Vote Timed out",
            Event::ResponsiveCommitTimeout => "Responsive Commit timed out", 
            Event::SyncCommit(_) => "Synchronously committing epoch",
            Event::SyncCommitTimeout => "Sync Commit timed out",
            Event::SyncTimer(_) => "Sync timer for 2D finished"
        }
    }
}