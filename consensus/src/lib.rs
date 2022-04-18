use std::sync::Arc;

mod events;
pub(crate) use events::*;

pub mod sync_sm;
pub mod optimistic_sm;

mod ev_queue;
pub(crate) use ev_queue::*;

mod optimization;
pub use optimization::*;

// pub mod reconfig;

use types::{ProtocolMsg, ReconfigurationMsg, Replica};

pub type OutMsg = (Replica, Arc<ProtocolMsg>);
pub type CliOutMsg = Arc<ReconfigurationMsg>;