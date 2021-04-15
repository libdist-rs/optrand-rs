use crate::{Commitment, DbsContext, DbsError, Dleq, DleqProof, DleqProofSameG1, G1, G2, G2P, Polynomial, PublicKey, Scalar, Share, Secret, ark_serde::{canonical_deserialize, canonical_serialize}};
pub use ark_bls12_381::Bls12_381;
pub use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
pub use ark_ff::{Field, One, PrimeField, UniformRand, Zero, FromBytes};
pub use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};
pub use rand::{rngs::StdRng, Rng, SeedableRng};
use fnv::FnvHashMap as HashMap;
pub use std::{error::Error, fmt};
use serde::{Serialize, Deserialize};

/// The Encryption group is the same as the public key group
/// Which is G1 for type 3 pairings
pub type Encryptions = PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatePVSS {
    /// encs contains the combined encryptions c := (c1, c2, ..., cn)
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub encs: Vec<Encryptions>,
    /// comms contains the combined commitments v := (v1, v2, ..., vn)
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub comms: Vec<Commitment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompositionProof {
    /// The index in the combined vector for which this is a decomposition proof
    pub idx: usize,
    /// indices of the nodes whose shares we have combined
    pub indices: Vec<usize>,
    /// Constituent vi
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub comms: Vec<Commitment>,
    /// Constituent ci
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub encs: Vec<Encryptions>,
    /// A vector of dleq proofs for all constituent vi and ci for [n]
    pub proof: Vec<DleqProof>,
}

/// Decryption data structure that holds the decrypted share in G1 and 
/// [OPTIMIZATIONS] - proof of correct decryption (a DLEQ proof) to save pairing computations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decryption {
    /// The decrypted share
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub dec: Share,
    /// The proof that this share was decrypted correctly
    pub proof: DleqProofSameG1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Beacon (
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub Secret,
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub G1,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PVSSVec {
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub comms: Vec<Commitment>, 
    #[serde(serialize_with = "canonical_serialize")]
    #[serde(deserialize_with = "canonical_deserialize")]
    pub encs: Vec<Encryptions>,
    pub proofs: Vec<DleqProof>,
}

impl DbsContext {
    /// Creates a PVSS sharing for a random secret s\gets Zq
    /// Returns (v,c,pi)
    pub fn generate_shares<R>(
        &self,
        dss_sk: &crypto_lib::Keypair,
        rng: &mut R,
    ) -> PVSSVec
    where
    R: Rng + ?Sized,
    {
        let n = self.n;
        let t = self.t;
        // Generate random co-efficients a0,a1,...,at
        let vec: Vec<Scalar> = (0..t+1).map(|_i| Scalar::rand(rng)).collect();
        
        // Set Polynomial p(x) = a_0 + a_1x + a_2x^2 + ... + a_tx^t
        let polynomial = Polynomial::from_coefficients_vec(vec);
        // s_i = p(i)
        let evaluations: Vec<Scalar> = (0..n).map(|i| 
            polynomial.evaluate(&Scalar::from(i as u64 + 1))
        ).collect();
        // v_i = h^s_i
        let commitments: Vec<_> = (0..n).map(|i| {
            self.h1.mul(evaluations[i]).into_affine()
        }).collect();
        // c_i = pk_i^{s_i}
        let encryptions: Vec<_> = (0..n).map(|i| {
            self.public_keys[i].mul(evaluations[i]).into_affine()
        }).collect();
        // dleq.prove(s_i,g,c_i,h,v_i)
        let proof:Vec<_> = (0..self.n).map(|i| {
            Dleq::prove( &evaluations[i], &self.public_keys[i], &encryptions[i], &self.h1, &commitments[i], dss_sk, rng)
        }).collect();
        PVSSVec {
            comms: commitments,
            encs: encryptions,
            proofs: proof,
        }
    }

    /// Creates a PVSS sharing for a given secret s\gets Zq
    /// Returns (v,c,pi)
    pub fn generate_share_for_point<R>(
        &self,
        dss_sk: &crypto_lib::Keypair,
        rng: &mut R,
        secret: Scalar,
    ) -> PVSSVec
    where
    R: Rng + ?Sized,
    {
        let n = self.n;
        let t = self.t;
        // Generate random co-efficients a0,a1,...,at
        let vec: Vec<Scalar> = (0..t+1).map(|_i| {
            if _i == 0 {
                secret
            } else {
                Scalar::rand(rng)
            }
        }).collect();
        
        // Set Polynomial p(x) = a_0 + a_1x + a_2x^2 + ... + a_tx^t
        let polynomial = Polynomial::from_coefficients_vec(vec);
        // s_i = p(i)
        let evaluations: Vec<Scalar> = (0..n).map(|i| 
            polynomial.evaluate(&Scalar::from(i as u64 + 1))
        ).collect();
        // v_i = h^s_i
        let commitments: Vec<_> = (0..n).map(|i| {
            self.h1.mul(evaluations[i]).into_affine()
        }).collect();
        // c_i = pk_i^{s_i}
        let encryptions: Vec<_> = (0..n).map(|i| {
            self.public_keys[i].mul(evaluations[i]).into_affine()
        }).collect();
        // dleq.prove(s_i,g,c_i,h,v_i)
        let proof:Vec<_> = (0..self.n).map(|i| {
            Dleq::prove( &evaluations[i], &self.public_keys[i], &encryptions[i], &self.h1, &commitments[i], dss_sk, rng)
        }).collect();
        PVSSVec {
            comms: commitments,
            encs: encryptions,
            proofs: proof,
        }
    }
    
    /// Verifies whether a given PVSS vector is valid
    /// Returns false if the verification fails
    pub fn verify_sharing(&self, pvec: &PVSSVec, dss_pk: &crypto_lib::PublicKey) -> Option<DbsError>
    {
        // Coding check
        if (0..self.n).map(|i| {
            pvec.comms[i].mul(self.codewords[i])
        }).fold(G2P::zero(), |acc, c| {
            acc + c
        }) != G2P::zero()
        {
            return Some(DbsError::CodingCheckFailed);
        }
        // OPTIMIZATION: Proof of knowledge check = Dleq = Pairing check
        // If this passes, we know that the pairing check will pass, so don't do pairings
        for i in 0..self.n {
            if let Some(_) = Dleq::verify(&pvec.proofs[i], &self.public_keys[i], &pvec.encs[i], &self.h1, &pvec.comms[i], dss_pk) {
                return Some(DbsError::DlogProofCheckFailed(i));
            }
        }
        None
    }
    
    /// Aggregate homomorphically combines all the PVSS vectors together
    /// WARNING: This operation is destructive and destroys the original shares
    ///          Clone the vector before using
    pub fn aggregate(&self,
        indices: &[usize], // whose shares are we combining
        pvec: &[PVSSVec],
    ) -> (AggregatePVSS, Vec<DecompositionProof>) 
    {
        assert_eq!(indices.len(), pvec.len());
        // v_i = v1_i * v2_i * ... * vt+1_i
        let combined_encs = (0..self.n).map(|i| {
            (0..pvec.len()).fold(G1::zero(), |acc, j| acc + pvec[j].encs[i].clone())
        }).collect();
        
        // c_i = c1_i * c2_i * ... * ct+1_i
        let combined_comms = (0..self.n).map(|i| {
            (0..pvec.len()).fold(G2::zero(), |acc, j| acc + pvec[j].comms[i].clone())
        }).collect();
        
        // Combined public component
        let agg_pvss = AggregatePVSS{
            encs: combined_encs,
            comms: combined_comms,
        };
        // Decomposition proofs
        let agg_pi = (0..self.n).map(|i| {
            let proofs = (0..pvec.len()).map(|j| pvec[j].proofs[i].clone()).collect();
            let nencs = (0..pvec.len()).map(|j| pvec[j].encs[i].clone())
            .collect();
            let ncomms = (0..pvec.len()).map(|j| pvec[j].comms[i].clone())
            .collect();
            DecompositionProof {
                idx: i,
                indices: indices.to_vec(),
                proof: proofs,
                encs: nencs,
                comms: ncomms,
            }
        }).collect();
        (agg_pvss, agg_pi)
    }
    
    /// pverify verifies if the public part of the combined PVSS vector is correct
    pub fn pverify(&self, agg_pvss: &AggregatePVSS) -> Option<DbsError> 
    {
        // Coding check
        if (0..self.n).map(|i| {
            agg_pvss.comms[i].mul(self.codewords[i])
        }).fold(G2P::zero(), |acc, c| {
            acc + c
        }) != G2P::zero()
        {
            return Some(DbsError::CodingCheckFailed);
        }
        // Pairing check
        // OPTIMIZATION - Save 2 pairings (roughly 3-4ms) by not checking self value; we will already check this using decomposition proof
        for id in 0..self.n {
            if id == self.origin as usize {
                continue;
            }
            // e(c_j, h) = e() =? e(pk_j, v_j)
            if Bls12_381::pairing(agg_pvss.encs[id], self.h1)
            != Bls12_381::pairing(self.public_keys[id], agg_pvss.comms[id]) 
            {
                return Some(DbsError::PairingCheckFailed(id));
            }
        }
        None
    }
    
    /// decomp_verify checks if the decomposition proof received is correct
    pub fn decomp_verify(&self, 
        agg_pvss:&AggregatePVSS, 
        agg_pi:&DecompositionProof, 
        pk_map: &HashMap<usize, crypto_lib::PublicKey>
    ) -> Option<DbsError> 
    {
        assert!(agg_pi.indices.len() == agg_pi.comms.len());
        // Check if all the v multiply to v_i in agg_pvss
        let combined_v = (0..self.t+1).fold(G2::zero(), |acc,i| {
            acc + agg_pi.comms[i]
        });
        if combined_v != agg_pvss.comms[self.origin as usize] {
            return Some(DbsError::CommitmentNotDecomposing);
        }
        // Check if all the c multiply to c_i in agg_pvss
        let combined_c = (0..self.t+1).fold(G1::zero(), |acc,i| {
            acc + agg_pi.encs[i]
        });
        if combined_c != agg_pvss.encs[self.origin as usize] {
            return Some(DbsError::EncryptionNotDecomposing);
        }
        // Check DLEQ between vi and ci
        for id in 0..self.t+1 {
            if let Some(x) = Dleq::verify(&agg_pi.proof[id], &self.public_keys[self.origin as usize], &agg_pi.encs[id], &self.h1, &agg_pi.comms[id], &pk_map[&(agg_pi.indices[id])]) {
                return Some(x);
            }
        }
        None
    }
    
    /// Decrypt an encryption meant for me
    /// OPTIMIZATION - Pairing is expensive, NIZKs are cheap
    /// Send a NIZK proof to avoid pairing checks
    pub fn decrypt_share<R>(&self, e: &Encryptions, dss_sk: &crypto_lib::Keypair, rng:&mut R) -> Decryption
    where R: Rng+?Sized,
    {
        // OPTIMIZATION - Precompute my_key.inverse
        let d = e.mul(self.my_key_inv).into_affine();
        let pi = Dleq::prove_same_g1(&self.my_key, &self.g, &self.public_keys[self.origin as usize], &d, &e, dss_sk, rng);
        Decryption{
            dec: d,
            proof: pi,
        }
    }
    
    /// Verify the received share and check the NIZK proof to see if it was decrypted correctly
    pub fn verify_share(&self, 
        origin: usize,
        e: &Encryptions, 
        dec: &Decryption,
        dss_pk: &crypto_lib::PublicKey
    ) -> Option<DbsError> 
    {
        Dleq::verify_same_g1(
            &dec.proof, 
            &self.g, 
            &self.public_keys[origin], 
            &dec.dec, 
            e, 
            &dss_pk
        )
    }
    
    // Reconstruct after obtaining t+1 valid decryptions
    // Returns (B,S=e(B,h'))
    pub fn reconstruct(&self,
        decrypted_shares: &[Option<Share>]
    ) -> Beacon 
    {
        let valid_share_indices: Vec<_> = (0..self.n)
        .filter(|&i| decrypted_shares[i].is_some())
        .map(|i| (i, Scalar::from(i as u64 + 1)))
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
                            Scalar::one()
                        } else {
                            scalar_j * self.lagrange_inverses[&(j,i)]
                        }
                    })
                    .fold(Scalar::one(), |lambda, x| lambda * x),
            )
        })
        .fold(G1::zero().into_projective(), |acc, x| acc + x)
        .into_affine();
        Beacon(Bls12_381::pairing(secret, self.h2), secret)
    }

    /// Check beacon checks if this is the correct beacon
    pub fn check_beacon(&self, b: &Beacon, cvec: &[Commitment]) -> bool {
        if Bls12_381::pairing(b.1, self.h2) != b.0 {
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
        .map(|i| (i, Scalar::from(i as u64 + 1)))
        .collect();
        let hs = valid_share_indices
        .iter()
        .map(|&(i, _scalar_i)| {
            com_vec[i].mul(
                valid_share_indices
                    .iter()
                    .map(|&(j, scalar_j)| {
                        if j == i {
                            Scalar::one()
                        } else {
                            scalar_j * self.lagrange_inverses[&(j,i)]
                        }
                    })
                    .fold(Scalar::one(), |lambda, x| lambda * x),
            )
        })
        .fold(G2::zero().into_projective(), |acc, x| acc + x)
        .into_affine();
        Bls12_381::pairing(b.1, self.h1) == Bls12_381::pairing(self.g, hs)
    } 
}