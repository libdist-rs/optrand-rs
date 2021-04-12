mod ark_serde;
pub mod hash;

mod dleq;
pub use dleq::*;

mod dbs;
pub use dbs::*;

pub use rand;

mod context;
pub use context::*;

mod keypairs;
pub use keypairs::*;

mod errors;
pub use errors::*;

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_poly::univariate::DensePolynomial;
use rand::rngs::StdRng;
use rand::SeedableRng;

pub type Scalar = <Bls12_381 as PairingEngine>::Fr;
pub type Polynomial = DensePolynomial<Scalar>;
pub type G1 = <Bls12_381 as PairingEngine>::G1Affine;
pub type G2 = <Bls12_381 as PairingEngine>::G2Affine;
pub type G1P = <Bls12_381 as PairingEngine>::G1Projective;
pub type G2P = <Bls12_381 as PairingEngine>::G2Projective;
pub type GT = <Bls12_381 as PairingEngine>::Fqk;

pub type Secret = GT;
pub type Share = G1;
pub type Commitment = G2;

pub fn std_rng() -> StdRng {
    rand::rngs::StdRng::from_entropy()
}

mod test;

mod baseline;