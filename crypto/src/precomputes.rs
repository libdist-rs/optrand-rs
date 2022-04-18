use ark_ec::{PairingEngine, ProjectiveCurve, msm::FixedBaseMSM};
use fnv::FnvHashMap as HashMap;
use crate::{Keypair, PublicKey, Scalar};
use ark_ec::AffineCurve;
use ark_ff::{Field, One, PrimeField};
use rand::{Rng};
use ark_poly::{UVPolynomial, Polynomial as PolyT};
use crate::Polynomial;
use ark_std::UniformRand;

type Table1<E> = Vec<Vec<<E as PairingEngine>::G1Affine>>;
type Table2<E> = Vec<Vec<<E as PairingEngine>::G2Affine>>;

#[derive(Debug, Clone, Builder)]
pub struct Precomputation<E: PairingEngine> {
    pub(crate) g1p: E::G1Projective,
    pub(crate) g2p: E::G2Projective,
    pub(crate) g1_prepared: E::G1Prepared,
    pub(crate) g2_prepared: E::G2Prepared,
    pub(crate) h1_prepared: E::G1Prepared,
    pub(crate) _h2_prepared: E::G2Prepared,
    pub(crate) my_key_inv: Scalar<E>,
    pub(crate) scalar_bits: usize,
    pub(crate) window_size: usize,
    pub(crate) g1_table: Table1<E>,
    pub(crate) g2_table: Table2<E>,
    /// OPTIMIZATIONS: Pre-computations for (n,t) degree check
    pub(crate) lagrange_inverses: HashMap<(usize, usize),Scalar<E>>,
    /// OPTIMIZATIONS: Pre-compute sk^-1 for decryptions
    pub(crate) codewords: Vec<Scalar<E>>,
    /// OPTIMIZATIONS: Pre-compute tables for public keys
    pub(crate) pk_tables: Vec<Table2<E>>,
    pub(crate) pub_keys_p: Vec<E::G2Prepared>,
    /// OPTIMIZATIONS: Pre-compute lagranges for the gs check
    pub(crate) fixed_lagranges: Vec<Scalar<E>>,
}

impl<E: PairingEngine> Precomputation<E> {
    pub fn new<R>(n: usize, 
        t: usize, 
        h1: E::G1Projective, 
        h2: E::G2Projective, 
        my_key: Scalar<E>,
        pub_keys: Vec<PublicKey<E>>,
        rng: &mut R) -> Self 
    where R: Rng + ?Sized,
    {
        let mut opt = PrecomputationBuilder::default();
        let scalar_bits = E::Fr::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(t + 1);
        let g1p = E::G1Affine::prime_subgroup_generator().into_projective();
        let g2p = E::G2Affine::prime_subgroup_generator().into_projective();
        let pk_tables = (0..pub_keys.len()).map(|i| {
            FixedBaseMSM::get_window_table(scalar_bits, window_size, pub_keys[i])
        }).collect();
        let pub_keys_p : Vec<_>= (0..pub_keys.len()).map(|i| {
            pub_keys[i].into_affine().into()
        }).collect();
        let lagrange_inverses = compute_inv_map::<E>(n);

        let indices:Vec<_> = (0..t+1).map(|i| (i, Scalar::<E>::from(i as u64 + 1))).collect();
        let lagranges: Vec<_> = indices
        .iter()
        .map(|&(i, _scalar_i)| {
                indices
                    .iter()
                    .map(|&(j, scalar_j)| {
                        if j == i {
                            Scalar::<E>::one()
                        } else {
                            scalar_j * lagrange_inverses[&(j,i)]
                        }
                    })
                    .fold(Scalar::<E>::one(), |lambda, x| lambda * x)
        }).collect();

        opt
            .g1p(g1p)
            .g2p(g2p)
            .my_key_inv(my_key.inverse()
                .expect("Failed to compute the inverse of my secret key"))
            .lagrange_inverses(lagrange_inverses)
            .codewords(random_codewords::<R, E>(n, t, rng))
            .scalar_bits(scalar_bits)
            .window_size(window_size)
            .g1_table(FixedBaseMSM::get_window_table(scalar_bits, window_size, g1p))
            .g2_table(FixedBaseMSM::get_window_table(scalar_bits, window_size, g2p))
            .pk_tables(pk_tables)
            .pub_keys_p(pub_keys_p)
            .g1_prepared(g1p.into().into())
            .g2_prepared(g2p.into().into())
            ._h2_prepared(h2.into().into())
            .h1_prepared(h1.into().into())
            .fixed_lagranges(lagranges)
                ;
        opt.build().expect("Failed to build the precomputation module")
    }

    pub fn encyrpt(&self, id: usize, val: E::Fr) -> PublicKey<E> {
        let res = FixedBaseMSM::multi_scalar_mul(self.scalar_bits, 
            self.window_size, 
            &self.pk_tables[id],
            &[val] 
        );
        res[0]
    }
}

/// Compute a map containing the inverses
/// TODO(Optimize)
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

/// Generate random codewords for the pairing check
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
    /// The default implementation generates parameters for n=4, t=2
    fn default() -> Self {
        let mut rng = crate::std_rng();
        let (n,t) = (1,0);
        let pub_keys: Vec<_> = (0..n).map(|_i| {
            Keypair::<E>::generate_keypair(&mut rng).1
        }).collect();
        Precomputation::new(
            n, 
            t, 
            E::G1Projective::rand(&mut rng), 
            E::G2Projective::rand(&mut rng), 
            Scalar::<E>::rand(&mut rng),
            pub_keys, 
            &mut rng
        )
    }
}