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

pub const fn threshold(tp: &Type, num_nodes: usize) -> usize {
    let is_odd = num_nodes & 1 == 1;
    match tp {
        Type::Sync if is_odd => (num_nodes+1)/2,
        Type::Sync => (num_nodes)/2,
        Type::Responsive => if num_nodes%4 == 0 {
            ((num_nodes-1)/4)+1
        } else {
            (num_nodes/4)+1
        }
    }
}


#[test]
fn test_sigs() {
    let sync_vote = Vote::default();
    assert_eq!(sync_vote.num_sigs(3), 2);
    assert_eq!(sync_vote.num_sigs(4), 2);
    assert_eq!(sync_vote.num_sigs(5), 3);
    let resp_vote = {
        let mut vote = VoteBuilder::default();
        vote
            .tp(Type::Responsive)
            .epoch(0)
            .prop_hash(crypto::hash::EMPTY_HASH)
            .build()
            .expect("Failed to build a vote")
    };
    assert_eq!(resp_vote.num_sigs(3), 1);
    assert_eq!(resp_vote.num_sigs(4), 1);
    assert_eq!(resp_vote.num_sigs(5), 2);
    assert_eq!(resp_vote.num_sigs(6), 2);
    assert_eq!(resp_vote.num_sigs(7), 2);
    assert_eq!(resp_vote.num_sigs(8), 2);
    assert_eq!(resp_vote.num_sigs(9), 3);
}


