#[macro_use]
extern crate static_assertions;

use std::sync::Arc;

mod events;
pub(crate) use events::*;

pub mod optimistic_sm;

mod ev_queue;
pub(crate) use ev_queue::*;

use types::{ProtocolMsg, ReconfigurationMsg, Replica};

pub type OutMsg = (Replica, Arc<ProtocolMsg>);
pub type CliOutMsg = Arc<ReconfigurationMsg>;