use std::collections::HashMap;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::ark_serde::{canonical_deserialize,canonical_serialize};
use crate::{G1,G2,G2P, Scalar, PublicKey, Polynomial};
use ark_ec::AffineCurve;
use ark_std::UniformRand;
use ark_ff::{One, Field};
pub use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};

#[derive(Debug,Clone,Serialize, Deserialize)]
pub struct DbsContext {
    /// The generator g as specified in the paper
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub g: G1,
    /// The generator h as specified in the paper
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub h1: G2,
    /// The generator h' as specified in the paper
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub h2: G2P,
    /// n: The number of nodes in the system
    /// This value will be used for some useful precomputations
    pub(crate) n: usize,
    /// t: The number of faults tolerated by the system
    /// This value will be used for some useful precomputations
    pub(crate) t: usize,
    /// The ID of the node creating the signature
    pub(crate) origin: u16,
    /// PVSS Public keys of all the participants
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub(crate) public_keys: Vec<PublicKey>,
    /// My private secret key
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub(crate) my_key: Scalar,
    // OPTIMIZATIONS: Pre-computed lagarange scalar inverses
    #[serde(skip)]
    pub(crate) lagrange_inverses: HashMap<(usize,usize),Scalar>,
    /// OPTIMIZATIONS: Pre-computations for (n,t) degree check
    #[serde(skip)]
    pub(crate) codewords: Vec<Scalar>,
    /// OPTIMIZATIONS: Pre-compute sk^-1 for decryptions
    #[serde(skip)]
    pub(crate) my_key_inv: Scalar,
}

impl DbsContext {
    /// Take h' as input from outside
    /// Otherwise when creating multiple contexts each one will have a different h2 resulting in different beacons being generated
    pub fn new<R>(r: &mut R, 
        h2: G2P,
        n:usize, 
        t: usize, 
        id: u16, 
        public_keys: Vec<PublicKey>, 
        my_key: Scalar
    ) -> Self 
    where R: Rng+?Sized,
    {
        assert!(n>2*t);
        assert!(public_keys.len() == n);
        let vec: Vec<Scalar> = (0..n - t - 1).map(|_| Scalar::rand(r)).collect();
        let polynomial = Polynomial::from_coefficients_vec(vec);
        let indices: Vec<_> = (0..n).map(|i| (i, Scalar::from(i as u64 + 1))).collect();
        let codewords: Vec<Scalar> = indices
        .iter()
        .map(|&(i, scalar_i)| {
            indices
                .iter()
                .map(|&(j, scalar_j)| {
                    if j == i {
                        Scalar::one()
                    } else {
                        (scalar_i - scalar_j).inverse().unwrap()
                    }
                })
                .fold(Scalar::one(), |v, x| v * x)
                * polynomial.evaluate(&scalar_i)
        })
        .collect();
        let mut inv_map = HashMap::with_capacity(n*n);
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let scalar_i = Scalar::from((i+1) as u64);
                let scalar_j = Scalar::from((j+1) as u64);
                let inv = (scalar_i - scalar_j).inverse().unwrap();
                inv_map.insert((i,j), inv);
            }
        }

        DbsContext {
            g: G1::prime_subgroup_generator(),
            h1: G2::prime_subgroup_generator(),
            h2,
            n,
            t,
            public_keys,
            origin:id,
            codewords,
            my_key,
            lagrange_inverses: inv_map,
            my_key_inv: my_key.inverse().unwrap(),
        }
    }
}