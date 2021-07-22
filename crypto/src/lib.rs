mod ark_serde;
pub use ark_serde::*;

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

use ark_ec::{PairingEngine, AffineCurve};
use ark_std::UniformRand;
use ark_poly::univariate::DensePolynomial;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// The scalar field of the pairing groups
pub type Scalar<E> = <E as PairingEngine>::Fr;

/// A polynomial with the various coefficients in the Scalar Group
pub type Polynomial<E> = DensePolynomial<Scalar<E>>;

/// The target group GT of the pairing
pub type GT<E> = <E as PairingEngine>::Fqk;

/// The secret that we will be encoding
/// Also the beacon
pub type Secret<E> = GT<E>;

/// The Share type
pub type Share<E> = <E as PairingEngine>::G1Projective;
pub type Commitment<E> = <E as PairingEngine>::G2Affine;
pub type CommitmentP<E> = <E as PairingEngine>::G2Projective;
pub type SecretKey<E> = Scalar<E>;
pub type PublicKey<E> = <E as PairingEngine>::G1Projective;
/// The Encryption group is the same as the public key group
/// Which is G1 for type 3 pairings
pub type Encryptions<E> = PublicKey<E>;

pub fn std_rng() -> StdRng {
    rand::rngs::StdRng::from_entropy()
}

pub fn rand_h2_generator<R, E>(rng: &mut R) 
    -> E::G2Projective
    where R:Rng+?Sized, 
    E: PairingEngine,
{
    E::G2Affine::prime_subgroup_generator()
        .mul(E::Fr::rand(rng))
}

mod precomputes;
mod pvss;

mod test;

#[macro_use]
extern crate derive_builder;