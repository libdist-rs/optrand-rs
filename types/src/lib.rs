mod msg;
pub use msg::*;

/// The height of the block
pub type Height = usize;
/// The replica id
pub type Replica = usize;
/// The round or epoch
pub type Epoch = usize;

/// The Pairing curve family
pub type E = crypto::E;
pub type AggregatePVSS = crypto::AggregatePVSS<E>;
pub type DecompositionProof = crypto::DecompositionProof<E>;
pub type Decryption = crypto::Decryption<E>;
pub type PVSSVec = crypto::PVSSVec<E>;
pub type Beacon = crypto::Beacon<E>;
pub type DbsContext = crypto::DbsContext<E>;
pub type Share = crypto::Share<E>;
pub type Keypair = crypto::Keypair<E>;