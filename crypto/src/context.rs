use ark_ec::msm::{FixedBaseMSM, VariableBaseMSM};

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::ark_serde::{canonical_deserialize,canonical_serialize};
use crate::precomputes::Precomputation;
use crate::{Scalar, PublicKey};
use ark_ec::{AffineCurve, PairingEngine};
pub use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};
use ark_ff::PrimeField;

#[derive(Debug,Clone,Serialize, Deserialize, Default)]
#[serde(bound(deserialize = "Precomputation<E>: Default"))]
pub struct DbsContext<E> 
where E: PairingEngine,
{
    /// The generator h' as specified in the paper
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub h2p: E::G2Projective,

    /// n: The number of nodes in the system
    /// This value will be used for some useful precomputations
    pub(crate) n: usize,
    /// t: The number of faults tolerated by the system
    /// This value will be used for some useful precomputations
    pub(crate) t: usize,
    /// The ID of the node creating the signature
    pub(crate) origin: usize,

    /// PVSS Public keys of all the participants
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub(crate) public_keys: Vec<PublicKey<E>>,
    /// My private secret key
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub(crate) my_key: Scalar<E>,

    // Pre-computation optimizations
    // OPTIMIZATIONS: Pre-computed lagarange scalar inverses
    #[serde(default)]
    #[serde(skip)]
    pub(crate) optimizations: Precomputation<E>,
}

impl<E> DbsContext<E> 
where E:PairingEngine,
{
    /// Take h' as input from outside
    /// Otherwise when creating multiple contexts each one will have a different h2 resulting in different beacons being generated
    pub fn new<R>(r: &mut R, 
        h2: E::G2Projective,
        n:usize, 
        t: usize, 
        id: usize, 
        public_keys: Vec<PublicKey<E>>, 
        my_key: Scalar<E>
    ) -> Self 
    where R: Rng+?Sized,
    {
        assert!(n>2*t);
        assert!(public_keys.len() == n);
        let optimizations = Precomputation::new(n, t, h2, my_key, r);
        Self{
            h2p: h2,
            n,
            t,
            public_keys,
            origin:id,
            my_key,
            optimizations,
        }
    }

    /// To be called after reading from a file since serde will not serialize those elements properly
    /// Sets up the lagrange inverses, my_key_inverse and g,h, and a random codeword
    pub fn init<R>(&mut self, rng: &mut R) 
    where R:Rng + ?Sized,
    {
       self.optimizations = Precomputation::new(self.n, self.t, self.h2p, self.my_key, rng);
    }

    pub fn FBMultiScalarMulG1(&self, scalars: &[Scalar<E>]) -> Vec<E::G1Projective> {
        FixedBaseMSM::multi_scalar_mul(self.optimizations.scalar_bits, 
            self.optimizations.window_size, 
            &self.optimizations.g1_table,
            scalars 
        )
    }

    pub fn FBMultiScalarMulG2(&self, scalars: &[Scalar<E>]) -> Vec<E::G2Projective> {
        FixedBaseMSM::multi_scalar_mul(self.optimizations.scalar_bits, 
            self.optimizations.window_size, 
            &self.optimizations.g2_table,
            scalars 
        )
    }

    /// Multi-exponentiation code
    pub fn VBMultiScalarMul<G>(bases: &Vec<G>, 
        scalars: &[<<G as AffineCurve>::ScalarField as PrimeField>::BigInt]
    ) -> G::Projective
    where G: AffineCurve,
    {
        VariableBaseMSM::multi_scalar_mul(bases, scalars)
    }
}