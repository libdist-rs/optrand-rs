use rand::Rng;
use ark_ec::{AffineCurve, PairingEngine};
use ark_std::UniformRand;

use crate::{Scalar, PublicKey, SecretKey};


pub struct Keypair<E: PairingEngine> (pub SecretKey<E>, 
    pub PublicKey<E>);

impl<E> Keypair<E> 
where E: PairingEngine,
{
    pub fn generate_keypair<R>(rng: &mut R) -> Self
    where R: Rng + ?Sized,
    {
        let secret = Scalar::<E>::rand(rng);
        Self(secret,
            E::G1Affine::prime_subgroup_generator().mul(secret),
        )
    }
}