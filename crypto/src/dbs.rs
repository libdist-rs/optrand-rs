use crate::{Commitment, DbsContext, DbsError, Dleq, Encryptions, Polynomial, Scalar, Share, SingleDleq, precomputes::Precomputation};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_poly::{Polynomial as Poly, UVPolynomial};
use rand::Rng;
use fnv::FnvHashMap as HashMap;
use crate::pvss::*;

impl<E> DbsContext<E> 
where E:PairingEngine,
{
    /// Creates a PVSS sharing for a random secret s\gets Zq
    /// Returns (v,c,pi)
    pub fn generate_shares<R>(
        &self,
        dss_sk: &crypto_lib::Keypair,
        rng: &mut R,
    ) -> PVSSVec<E>
    where
    R: Rng + ?Sized,
    {
        // Generate random co-efficients a0,a1,...,at
        let secret = Scalar::<E>::rand(rng);
        self.generate_share_for_point(dss_sk, rng, secret)       
    }

    /// Creates a PVSS sharing for a given secret s\gets Zq
    /// Returns (v,c,pi)
    pub fn generate_share_for_point<R>(
        &self,
        dss_sk: &crypto_lib::Keypair,
        mut rng: &mut R,
        secret: Scalar<E>,
    ) -> PVSSVec<E>
    where
    R: Rng + ?Sized,
    {
        let n = self.n;
        let t = self.t;

        let mut polynomial = Polynomial::<E>::rand(t, &mut rng);
        polynomial.coeffs[0] = secret;
        
        // s_i = p(i)
        let evaluations: Vec<_> = (0..n).map(|i| 
            polynomial.evaluate(&Scalar::<E>::from(i as u64 + 1))
        ).collect();

        // v_i = g1^s_i
        let commitments = self.fixed_base_scalar_mul_g1(&evaluations);
        
        // TODO(Optimize)
        // c_i = pk_i^{s_i}
        let encryptions: Vec<_> = (0..n).map(|i| {
            // self.public_keys[i].mul(evaluations[i].into_repr())
            self.optimizations.encyrpt(i, evaluations[i])
        }).collect();

        // dleq.prove(s_i,pki,e_i,g2,c_i)
        let proof:Vec<_> = (0..self.n).map(|i| {
            Dleq::<E::G1Projective, E::G2Projective, E::Fr>::prove( 
                &evaluations[i], 
                &self.optimizations.g1p, 
                &commitments[i],
                &self.public_keys[i], 
                &encryptions[i], 
                 dss_sk, rng)
        }).collect();

        // Convert commitments into affine form
        let commitments = commitments
            .iter()
            .map(|v| v.into_affine())
            .collect();

        let gs = self.optimizations.g1p.mul(secret.into_repr());
        let sok = SingleDleq::<E::G1Projective, Scalar<E>>::prove(
            &secret, 
            &self.optimizations.g1p, 
            &gs, 
            dss_sk, 
            rng
        );
        
        // Return commitments, encryptions, and DLEQ proofs
        PVSSVec {
            comms: commitments,
            encs: encryptions,
            proofs: proof,
            gs,
            sig_of_knowledge: sok,
        }
    }

    /// Verifies whether a given PVSS vector is valid
    /// Returns false if the verification fails
    pub fn verify_sharing(&self, 
        pvec: &PVSSVec<E>, 
        dss_pk: &crypto_lib::PublicKey
    ) -> Option<DbsError>
    {
        if !coding_check(&self.optimizations, &pvec.comms) {
            return Some(DbsError::CodingCheckFailed);
        }

        // OPTIMIZATION: Proof of knowledge check = Dleq = Pairing check
        // If this passes, we know that the pairing check will pass, so don't do pairings
        for i in 0..self.n {
            // Check if dleq(pi, g2, ci, pk, enc)
            if let Some(x) = Dleq::<E::G1Projective, E::G2Projective, E::Fr>::verify(
                &pvec.proofs[i], 
                &self.optimizations.g1p, 
                &pvec.comms[i].into_projective(), 
                &self.public_keys[i], 
                &pvec.encs[i], 
                dss_pk) 
            {
                log::error!("Got error from dleq checker {:?}", x);
                return Some(DbsError::DlogProofCheckFailed(i));
            }
        }

        // Reconstruct and check if the gs is correct
        let into_repr: Vec<_> = (0..self.t+1).map(|i| {
            self.optimizations.fixed_lagranges[i].into()
        }).collect();
        let res = DbsContext::<E>::var_base_scalar_mul(&pvec.comms[0..self.t+1].to_vec(), &into_repr);

        if res != pvec.gs {
            return Some(DbsError::InvalidGs)
        }

        // Check if dleq(pi, g, g^s)
        if let Some(x) = SingleDleq::verify(
            &pvec.sig_of_knowledge, 
            &self.optimizations.g1p, 
            &pvec.gs, 
            dss_pk) 
        {
            return Some(x)
        }
        None
    }
    
    /// Aggregate homomorphically combines all the PVSS vectors together
    /// WARNING: This operation is destructive and destroys the original shares
    ///          Clone the vector before using
    pub fn aggregate(&self,
        indices: &[usize], // whose shares are we combining
        pvec: Vec<PVSSVec<E>>,
    ) -> (AggregatePVSS<E>, DecompositionProof<E>) 
    {
        assert_eq!(indices.len(), pvec.len());

        // v_i = v1_i * v2_i * ... * vt+1_i
        let combined_encs = (0..self.n)
            .map(|i| { 
                (0..pvec.len())
                    .fold(E::G2Projective::zero(), 
                    |acc, j| {
                        acc + pvec[j].encs[i]
                    }
                )
            })
            .collect();
        
        // c_i = c1_i * c2_i * ... * ct+1_i
        let combined_comms = (0..self.n).map(
            |i| {(0..pvec.len()).fold(
                E::G1Projective::zero(), 
                |acc, j| {
                    acc + pvec[j].comms[i].into_projective()
                }
            ).into_affine()
        }).collect();
        
        // Combined public component
        let agg_pvss = AggregatePVSS{
            encs: combined_encs,
            comms: combined_comms,
        };
        // Decomposition proofs
        let mut dleq_proof = Vec::with_capacity(pvec.len());
        let mut gs_vec = Vec::with_capacity(pvec.len());
        for v in pvec {
            dleq_proof.push(v.sig_of_knowledge);
            gs_vec.push(v.gs);
        }

        let decomp_proof = DecompositionProof{
            indices: indices.to_vec(),
            dleq_proof,
            gs_vec,
        };

        (agg_pvss, decomp_proof)
    }
    
    /// pverify verifies if the public part of the combined PVSS vector is correct
    pub fn pverify(&self, agg_pvss: &AggregatePVSS<E>) -> Option<DbsError> 
    {
        // Coding check
        if !coding_check(&self.optimizations, 
            &agg_pvss.comms
        ) 
        {
            return Some(DbsError::CodingCheckFailed);
        }
        // Pairing check
        // OPTIMIZATION - Save 2 pairings (roughly 3-4ms) by not checking self value; we will already check this using decomposition proof
        for id in 0..self.n {
            if id == self.origin as usize {
                continue;
            }
            // e(g1, c_j) =? e(v_j, pk_j)
            if !DbsContext::<E>::reduced_pairing_check_part(
                self.optimizations.g1_prepared.clone(), 
                agg_pvss.encs[id].into().into(),
                (-agg_pvss.comms[id]).into(),
                self.optimizations.pub_keys_p[id].clone(),
            )
            // if E::pairing(agg_pvss.encs[id], self.optimizations.g2p)
            // != E::pairing(self.public_keys[id], agg_pvss.comms[id]) 
            {
                return Some(DbsError::PairingCheckFailed(id));
            }
        }
        None
    }
    
    /// decomp_verify checks if the decomposition proof received is correct
    pub fn decomp_verify(&self, 
        agg_pvss:&AggregatePVSS<E>, 
        agg_pi:&DecompositionProof<E>, 
        pk_map: &HashMap<usize, crypto_lib::PublicKey>
    ) -> Option<DbsError> 
    {
        let into_repr: Vec<_> = (0..self.t+1).map(|i| {
            self.optimizations.fixed_lagranges[i].into()
        }).collect();
        let res = DbsContext::<E>::var_base_scalar_mul(&agg_pvss.comms[0..self.t+1].to_vec(), &into_repr);
        
        let mut init = Commitment::<E>::zero().into_projective();
        for v in &agg_pi.gs_vec {
            init = init + v;
        }

        if res != init {
            return Some(DbsError::InvalidGs);
        }
        
        for i in 0..agg_pi.dleq_proof.len() {
            // Check if  dleq(pi, g1, g1^s)
            if let Some(x) = SingleDleq::verify(
                &agg_pi.dleq_proof[i], 
                &self.optimizations.g1p, 
                &agg_pi.gs_vec[i], 
                &pk_map[&agg_pi.indices[i]]
            ) {
                return Some(x);
            }
        }

        None
    }
    
    /// Decrypt an encryption meant for me
    /// OPTIMIZATION - Pairing is expensive, NIZKs are cheap
    /// Send a NIZK proof to avoid pairing checks
    pub fn decrypt_share<R>(&self, e: &Encryptions<E>, dss_sk: &crypto_lib::Keypair, rng:&mut R) -> Decryption<E>
    where R: Rng+?Sized,
    {
        // OPTIMIZATION - Precompute my_key.inverse
        let d = e.mul(self.optimizations.my_key_inv.into_repr());
        let pi = Dleq::<E::G2Projective, E::G2Projective, E::Fr>::prove(
            &self.my_key, 
            &self.optimizations.g2p, 
            &self.public_keys[self.origin as usize], 
            &d, 
            &e, 
            dss_sk, 
            rng);
        Decryption{
            dec: d,
            proof: pi,
        }
    }
    
    /// Verify the received share and check the NIZK proof to see if it was decrypted correctly
    pub fn verify_share(&self, 
        origin: usize,
        e: &Encryptions<E>, 
        dec: &Decryption<E>,
        dss_pk: &crypto_lib::PublicKey
    ) -> Option<DbsError> 
    {
        // Verify dleq(pi, g2p, pk, dec, enc)
        Dleq::verify(
            &dec.proof, 
            &self.optimizations.g2p, 
            &self.public_keys[origin], 
            &dec.dec, 
            e, 
            &dss_pk
        )
    }
    
    /// Reconstruct after obtaining t+1 valid decryptions
    /// Returns (B,S=e(B,h'))
    pub fn reconstruct(&self,
        decrypted_shares: &[Option<Share<E>>]
    ) -> Beacon<E>
    {
        let valid_share_indices: Vec<_> = (0..self.n)
        .filter(|&i| decrypted_shares[i].is_some())
        .map(|i| (i, Scalar::<E>::from(i as u64 + 1)))
        .collect();
        // OPTIMIZATIONS - Precompute (i-j)^-1 before hand
        // This is (n-1)^2 pre-computations, can be reduced to 2n pre-computations
        let secret = valid_share_indices
        .iter()
        .map(|&(i, _scalar_i)| {
            decrypted_shares[i].unwrap().mul(
                valid_share_indices
                    .iter()
                    .map(|&(j, scalar_j)| {
                        if j == i {
                            Scalar::<E>::one()
                        } else {
                            scalar_j * self.optimizations.lagrange_inverses[&(j,i)]
                        }
                    })
                    .fold(Scalar::<E>::one(), |lambda, x| lambda * x).into_repr(),
            )
        })
        .fold(E::G2Projective::zero(), |acc, x| acc + x);
        Beacon{
            beacon: E::pairing(self.h1p, secret), 
            value: secret,
        }
    }

    /// Check beacon checks if this is the correct beacon
    pub fn check_beacon(&self, b: &Beacon<E>, cvec: &[Commitment<E>]) -> bool {
        if E::pairing(self.h1p, b.value) != b.beacon {
            return false;
        }
        let mut counter = 0;
        let mut com_vec = Vec::with_capacity(self.t+1);
        for v in cvec {
            if counter > self.t +1 {
                break;
            }
            com_vec.push(v);
            counter += 1;
        }
        let valid_share_indices: Vec<_> = (0..self.t+1)
        .map(|i| (i, Scalar::<E>::from(i as u64 + 1)))
        .collect();
        let hs = valid_share_indices
        .iter()
        .map(|&(i, _scalar_i)| {
            com_vec[i].mul(
                valid_share_indices
                    .iter()
                    .map(|&(j, scalar_j)| {
                        if j == i {
                            Scalar::<E>::one()
                        } else {
                            scalar_j * self.optimizations.lagrange_inverses[&(j,i)]
                        }
                    })
                    .fold(Scalar::<E>::one(), |lambda, x| lambda * x).into_repr(),
            )
        })
        .fold(E::G1Projective::zero(), |acc, x| acc + x);
        // Check e(g'1,g2^s) = e(g'1^s,g2)
        DbsContext::<E>::reduced_pairing_check_part(
            self.optimizations.h1_prepared.clone(), 
            b.value.into().into(), 
            (-hs.into()).into(),
            self.optimizations.g2_prepared.clone(), 
        )
        // E::pairing(b.value, self.h2p) == E::pairing(self.optimizations.g1p, hs)
    } 
}

fn coding_check<E>(ctx: &Precomputation<E>, comms: &[Commitment<E>]) -> bool 
where E: PairingEngine
{
    let affine_pvss_comms: Vec<_> = (0..comms.len()).map(|i| {
        comms[i]
    }).collect();
    
    // Coding check
    let codes:Vec<_> = (0..ctx.codewords.len()).map(|i| {
        ctx.codewords[i].into()
    }).collect();
    let code_check = DbsContext::<E>::var_base_scalar_mul(&affine_pvss_comms, &codes);
    code_check == E::G1Projective::zero()
}