use ark_ec::{PairingEngine, msm::FixedBaseMSM};
use fnv::FnvHashMap as HashMap;
use crate::{Scalar};
use ark_ec::AffineCurve;
use ark_ff::{Field, One, PrimeField};
use rand::{Rng};
use ark_poly::{UVPolynomial, Polynomial as PolyT};
use crate::Polynomial;
use ark_std::UniformRand;

#[derive(Debug, Clone, Builder)]
pub struct Precomputation<E: PairingEngine> {
    pub(crate) g1p: E::G1Projective,
    pub(crate) g2p: E::G2Projective,
    pub(crate) my_key_inv: Scalar<E>,
    pub(crate) scalar_bits: usize,
    pub(crate) window_size: usize,
    pub(crate) g1_table: Vec<Vec<E::G1Affine>>,
    pub(crate) g2_table: Vec<Vec<E::G2Affine>>,
    /// OPTIMIZATIONS: Pre-computations for (n,t) degree check
    pub(crate) lagrange_inverses: HashMap<(usize, usize),Scalar<E>>,
    /// OPTIMIZATIONS: Pre-compute sk^-1 for decryptions
    pub(crate) codewords: Vec<Scalar<E>>,
}

impl<E: PairingEngine> Precomputation<E> {
    pub fn new<R>(n: usize, 
        t: usize, 
        _h2: E::G2Projective, 
        my_key: Scalar<E>, 
        rng: &mut R) -> Self 
    where R: Rng + ?Sized,
    {
        let mut opt = PrecomputationBuilder::default();
        let scalar_bits = E::Fr::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(t + 1);
        let g1p = E::G1Affine::prime_subgroup_generator().into_projective();
        let g2p = E::G2Affine::prime_subgroup_generator().into_projective();
        opt
            .g1p(g1p)
            .g2p(g2p)
            .my_key_inv(my_key.inverse()
                .expect("Failed to compute the inverse of my secret key"))
            .lagrange_inverses(compute_inv_map::<E>(n))
            .codewords(random_codewords::<R, E>(n, t, rng))
            .scalar_bits(scalar_bits)
            .window_size(window_size)
            .g1_table(FixedBaseMSM::get_window_table(scalar_bits, window_size, g1p))
            .g2_table(FixedBaseMSM::get_window_table(scalar_bits, window_size, g2p))
                ;
        opt.build().expect("Failed to build the precomputation module")
    }
}

fn compute_inv_map<E:PairingEngine>(n:usize) -> HashMap<(usize, usize), Scalar<E>> 
{
    // let n_int = n as i128;
    let mut inv_map = HashMap::default();
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            let scalar_i = Scalar::<E>::from((i+1) as u64);
            let scalar_j = Scalar::<E>::from((j+1) as u64);
            let inv = (scalar_i - scalar_j).inverse().unwrap();
            inv_map.insert((i,j), inv);
        }
    }
    inv_map
}

fn random_codewords<R, E:PairingEngine>(n:usize, t:usize, rng:&mut R) -> Vec<Scalar<E>>
where R: Rng + ?Sized,
{
    let vec: Vec<_> = (0..n - t - 1)
        .map(|_| Scalar::<E>::rand(rng))
        .collect();
    
    let polynomial = 
        Polynomial::<E>::from_coefficients_vec(vec);
    let indices: Vec<_> = (0..n)
        .map(|i| (i, Scalar::<E>::from(i as u64 + 1)))
        .collect();

    let codewords: Vec<_> = indices
        .iter()
        .map(|&(i, scalar_i)| {
            indices
            .iter()
            .map(|&(j, scalar_j)| {
                if j == i {
                    Scalar::<E>::one()
                } else {
                    (scalar_i - scalar_j).inverse().unwrap()
                }
            })
            .fold(Scalar::<E>::one(), |v, x| v * x)
        * polynomial.evaluate(&scalar_i)
    })
    .collect();
    codewords
}

impl<E:PairingEngine> std::default::Default for Precomputation<E> {
    fn default() -> Self {
        let mut rng = crate::std_rng();
        Precomputation::new(4, 2, E::G2Projective::rand(&mut rng), Scalar::<E>::rand(&mut rng), &mut rng)
    }
}