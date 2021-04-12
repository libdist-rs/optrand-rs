use rand::Rng;
use ark_ec::{ProjectiveCurve,AffineCurve};
use ark_std::UniformRand;

use crate::{G1,Scalar};

pub type SecretKey = Scalar;
pub type PublicKey = G1;

pub struct Keypair (pub SecretKey, pub PublicKey);

impl Keypair {
    pub fn generate_keypair<R>(rng: &mut R) -> Keypair
    where R: Rng + ?Sized,
    {
        let secret = Scalar::rand(rng);
        Keypair(secret,
            G1::prime_subgroup_generator().mul(secret).into_affine(),
        )
    }
}