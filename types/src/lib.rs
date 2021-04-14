mod msg;
pub use msg::*;

/// The height of the block
pub type Height = usize;
/// The replica id
pub type Replica = usize;
/// The round or epoch
pub type Epoch = usize;

pub type WireReadyDown = types_upstream::WireReady;
