mod msg;
use error::Error;
pub use msg::*;

pub mod error;

/// The height of the block
pub type Height = usize;
/// The replica id
pub type Replica = usize;
/// The round or epoch
pub type Epoch = usize;

/// The first epoch is 1
pub const START_EPOCH: Epoch = 0;

use ark_bls12_381::Bls12_381;
/// We will use Bls12_381 for OptRand
/// Other users of the crypto library can change the pairing curve accordingly
/// Available options: (Source: https://github.com/arkworks-rs/curves)
/// - Bls12_371
/// - Bls12_381
/// - Bn254
/// - bw6_761
/// - cp6_782 
/// - mnt4_298
/// - mnt4_753
/// - mnt6_298
/// - mnt6_753
pub type E = Bls12_381;

// Instantiate specific types for use in the rest of the codebase
pub type AggregatePVSS = crypto::AggregatePVSS<E>;
pub type DecompositionProof = crypto::DecompositionProof<E>;
pub type Decryption = crypto::Decryption<E>;
pub type PVSSVec = crypto::PVSSVec<E>;
pub type Beacon = crypto::Beacon<E>;
pub type DbsContext = crypto::DbsContext<E>;
pub type BeaconShare = crypto::Share<E>;
pub type Keypair = crypto::Keypair<E>;

pub type DirectProposal = Proposal<ProposalData>;
pub type SyncCertProposal = Proposal<SyncCertData>;

pub type Result<T> = std::result::Result<T, Error>;

#[macro_use]
extern crate derive_builder;