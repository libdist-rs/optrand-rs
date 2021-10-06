#[cfg(test)]
mod keypair_tests {
    use ark_bls12_381::Bls12_381;
    use crate::{std_rng, Keypair};

    #[test]
    fn test_gen() {
        let mut rng = std_rng();
        let _ = Keypair::<Bls12_381>::generate_keypair(&mut rng);
    }
}


#[cfg(test)]
mod ctx_tests {
    use crate::{DbsContext, Keypair, std_rng, Scalar};
    use ark_bls12_381::Bls12_381;
    use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
    use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};
    use ark_std::UniformRand;
    use ark_ff::{PrimeField, to_bytes};
    use crypto_lib::hash::ser_and_hash;

    type E = Bls12_381;
    pub type Polynomial<E> = DensePolynomial<Scalar<E>>;

    #[test]
    fn test_gen() {
        let mut rng = std_rng();
        let h2 = <Bls12_381 as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<Bls12_381>::rand(&mut rng).into_repr());
        let n = 21;
        let t = 10;
        let keypairs:Vec<_> = (0..n).map(|_i| {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            kpair
        }).collect();
        let public_keys = (0..n).map(|i| {
            keypairs[i].1
        }).collect();
        let _ = DbsContext::<E>::new(&mut rng, h2, n, t, 0, public_keys, keypairs[0].0);
    }

    #[test]
    fn test_generation() {
        let mut rng = std_rng();
        let h2 = <Bls12_381 as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<Bls12_381>::rand(&mut rng).into_repr());
        let n = 21;
        let t = 10;
        let keypairs:Vec<_> = (0..n).map(|_i| {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            kpair
        }).collect();
        let public_keys = (0..n).map(|i| {
            keypairs[i].1
        }).collect();
        let dbs_ctx = DbsContext::<E>::new(&mut rng, h2, n, t, 0, public_keys, keypairs[0].0);

        let secret = Scalar::<E>::rand(&mut rng);

        // Generate random co-efficients a0,a1,...,at
        let vec: Vec<_> = (0..t+1).map(|i| {
            if i == 0 {
                secret
            } else {
                Scalar::<E>::rand(&mut rng)
            }
        }).collect();
        
        // Set Polynomial p(x) = a_0 + a_1x + a_2x^2 + ... + a_tx^t
        let polynomial = Polynomial::<E>::from_coefficients_vec(vec);
        
        // s_i = p(i)
        let evaluations: Vec<_> = (0..n).map(|i| 
            polynomial.evaluate(&Scalar::<E>::from(i as u64 + 1))
        ).collect();

        // v_i = g2^s_i
        let left_commitments = dbs_ctx.fixed_base_scalar_mul_g2(&evaluations);
        let right_commitments: Vec<_> = (0..dbs_ctx.n).map(|i| {
            dbs_ctx.optimizations.g2p.mul(evaluations[i].into_repr())
        }).collect();

        for i in 0..n {
            assert_eq!(left_commitments[i], right_commitments[i]);
        }

        let encryptions: Vec<_> = (0..n).map(|i| {
            dbs_ctx.public_keys[i].mul(evaluations[i].into_repr())
        }).collect();

        type G1 = <E as PairingEngine>::G1Projective;
        type G2 = <E as PairingEngine>::G2Projective;

        let w = <E as PairingEngine>::Fr::rand(&mut rng);
        let a1: G1 = dbs_ctx.public_keys[0].mul(w.into_repr());
        let a2: G2 = dbs_ctx.optimizations.g2p.mul(w.into_repr());

        let mut buf = Vec::new();
        buf.append(&mut to_bytes!(a1).unwrap()); // a1
        buf.append(&mut to_bytes!(a2).unwrap()); // a2
        buf.append(&mut to_bytes!(encryptions[0]).unwrap()); // x
        buf.append(&mut to_bytes!(right_commitments[0].into_affine()).unwrap()); // y
        let left_hash = ser_and_hash(&buf);
        
        buf.clear();
        buf.append(&mut to_bytes!(a1).unwrap()); // a1
        buf.append(&mut to_bytes!(a2).unwrap()); // a2
        buf.append(&mut to_bytes!(encryptions[0]).unwrap()); // x
        buf.append(&mut to_bytes!(right_commitments[0].into_affine().into_projective().into_affine()).unwrap()); // y

        let right_hash = ser_and_hash(&buf);

        assert_eq!(left_hash, right_hash);
    }
}


#[cfg(test)]
mod dleq_tests {
    use crate::{DbsContext, Keypair, Scalar, std_rng};
    use ark_bls12_381::Bls12_381;
    use ark_std::UniformRand;
    use ark_ec::{PairingEngine, AffineCurve};

    type E = Bls12_381;

    #[test]
    fn test_dleq() {
        let mut rng = std_rng();
        let n = 101;
        let t = 50;
        let mut public_keys: Vec<_> = Vec::new();
        let mut secret_keys: Vec<_> = Vec::new();
        let dss_kpair = crypto_lib::Keypair::generate_secp256k1();
        let dss_pk = dss_kpair.public();
        for _i in 0..n {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
        }
        let h2 = <E as PairingEngine>::G2Affine::prime_subgroup_generator()
            .mul(Scalar::<E>::rand(&mut rng));

        let dbs_ctx = DbsContext::<E>::new(&mut rng, h2, n, t, 0, public_keys, secret_keys[0]);
        let pvec = 
            dbs_ctx.generate_shares( &dss_kpair, &mut rng);
        for i in 0..n {
            assert_eq!(None, 
                crate::Dleq::<<E as PairingEngine>::G1Projective, 
                    <E as PairingEngine>::G2Projective, 
                    <E as PairingEngine>::Fr>::verify(
                        &pvec.proofs[i], 
                        &dbs_ctx.public_keys[i], 
                        &pvec.encs[i], 
                        &dbs_ctx.optimizations.g2p, 
                        &pvec.comms[i].into_projective(), 
                        &dss_pk)
                );
        }
    }
}

#[cfg(test)]
mod dbs_tests {
    use crate::{DbsContext, Keypair, PVSSVec, PublicKey, Scalar, SecretKey, std_rng};
    use ark_bls12_381::Bls12_381;
    use ark_std::{UniformRand, Zero};
    use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
    use ark_ff::PrimeField;
    use fnv::FnvHashMap as HashMap;
    use serde::Serialize;

    type E = Bls12_381;
    
    #[test]
    fn gen_test() {
        let mut rng = std_rng();
        let n = 21;
        let t = 10;
        
        let mut public_keys: Vec<PublicKey<E>> = Vec::new();
        let mut secret_keys: Vec<SecretKey<E>> = Vec::new();
        let mut dss_kpair = Vec::new();
        let mut dss_pk = Vec::new();
        for _i in 0..n {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.push(dsskpair.public());
            dss_kpair.push(dsskpair);
        }
        let h2 = <E as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<E>::rand(&mut rng).into_repr());

        let dbs_ctx = DbsContext::<E>::new(&mut rng, h2,n, t, 0, public_keys, secret_keys[0]);
        let idx = 0;
        let pvec = 
            dbs_ctx.generate_shares(&dss_kpair[idx], &mut rng);
        
        type G2P = <E as PairingEngine>::G2Projective;
        let coding_check = (0..n).map(|i| {
                pvec.comms[i].mul(dbs_ctx.optimizations.codewords[i])
            }).fold(G2P::zero(), |acc, c| {
                acc + c
            }) == G2P::zero(); 
        assert_eq!(coding_check, true);
        assert_eq!(None, dbs_ctx.verify_sharing(&pvec, &dss_pk[idx]));

        let into_repr: Vec<_> = (0..dbs_ctx.t+1).map(|i| {
            dbs_ctx.optimizations.fixed_lagranges[i].into()
        }).collect();
        let res = DbsContext::<E>::var_base_scalar_mul(&pvec.comms[0..dbs_ctx.t+1].to_vec(), &into_repr);
        assert_eq!(res, pvec.gs);
    }

    #[test]
    fn test_reduced_pairing() {
        let mut rng = std_rng();
        let g1 = <E as PairingEngine>::G1Affine::prime_subgroup_generator();
        let g2 = <E as PairingEngine>::G2Affine::prime_subgroup_generator();
        let x = Scalar::<E>::rand(&mut rng);

        let g1x: <E as PairingEngine>::G1Prepared = ((g1).mul(x).into_affine()).into();
        let g2x: <E as PairingEngine>::G2Prepared = ((g2).mul(x).into_affine()).into();

        assert_eq!(true, 
        DbsContext::<E>::reduced_pairing_check_part((g1).into(), g2x, g1x, (-g2).into())
        );
    }

    #[test]
    fn codec_test() {
        let mut rng = std_rng();
        let n = 21;
        let t = 10;
        
        let mut public_keys: Vec<PublicKey<E>> = Vec::new();
        let mut secret_keys: Vec<SecretKey<E>> = Vec::new();
        let mut dss_kpair = Vec::new();
        let mut dss_pk = Vec::new();
        for _i in 0..n {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.push(dsskpair.public());
            dss_kpair.push(dsskpair);
        }
        let h2 = <E as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<E>::rand(&mut rng).into_repr());

        let dbs_ctx = DbsContext::<E>::new(&mut rng, h2,n, t, 0, public_keys, secret_keys[0]);
        let idx = 0;
        let pvec = 
            dbs_ctx.generate_shares(&dss_kpair[idx], &mut rng);
        
        assert_eq!(None, dbs_ctx.verify_sharing(&pvec, &dss_pk[idx]));
        assert_eq!(None, dbs_ctx.clone().verify_sharing(&pvec, &dss_pk[idx]));

        let bytes = bincode::serialize(&pvec);
        assert_eq!(true, bytes.is_ok());

        let bytes = bytes.unwrap();
        let pvec2: Result<PVSSVec<E>,_> = bincode::deserialize(&bytes);

        assert_eq!(true, pvec2.is_ok());
        assert_eq!(pvec, pvec2.unwrap());
    }
    
    #[test]
    fn agg_test() {
        let mut rng = std_rng();
        let n:usize = 21;
        let t = 10;
        
        let mut public_keys: Vec<PublicKey<E>> = Vec::new();
        let mut secret_keys: Vec<SecretKey<E>> = Vec::new();
        let mut dss_kpair:HashMap<_,_> = HashMap::default();
        let mut dss_pk:HashMap<_,_> = HashMap::default();
        let mut pvecs = Vec::new();
        for i in 0..n {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.insert(i,dsskpair.public() );
            dss_kpair.insert(i, dsskpair);
        }
        let h2 = <E as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<E>::rand(&mut rng).into_repr());

        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::<E>::new(&mut rng, h2, n as usize, t, i, public_keys.clone(), secret_keys[i as usize].clone())
        }).collect();
        let indices:Vec<_> = (0..t+1).map(|i| i).collect();
        for i in 0..t+1 {
            let pvec = 
            dbs_ctx[i].generate_shares(&dss_kpair[&i], &mut rng);
            assert_eq!(None, dbs_ctx[i].verify_sharing(&pvec, &dss_pk[&i]));
            pvecs.push(pvec);
        }
        let (agg_pvss, agg_pi) = dbs_ctx[0].aggregate(&indices, pvecs);
        assert_eq!(None, dbs_ctx[0].pverify(&agg_pvss));
        for i in 0..n {
            assert_eq!(None, 
                dbs_ctx[i as usize].decomp_verify(&agg_pvss, &agg_pi, &dss_pk)
            );
        }
    }

    #[test]
    fn decryption_test() {
        let mut rng = std_rng();
        let n = 21;
        let t = 10;
        
        let mut public_keys: Vec<PublicKey<E>> = Vec::new();
        let mut secret_keys: Vec<SecretKey<E>> = Vec::new();
        let mut dss_kpair = Vec::new();
        let mut dss_pk = Vec::new();
        for _i in 0..n {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.push(dsskpair.public());
            dss_kpair.push(dsskpair);
        }
        let h2 = <E as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<E>::rand(&mut rng).into_repr());

        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::<E>::new(&mut rng, h2, n, t, i, public_keys.clone(), secret_keys[i])
        }).collect();
        let pvec = 
            dbs_ctx[0].generate_shares(&dss_kpair[0], &mut rng);
        
        for j in 0..n {
            let dec = 
            dbs_ctx[j].decrypt_share(&pvec.encs[j], &dss_kpair[j], &mut rng);
            assert_eq!(None, 
                dbs_ctx[0].verify_share(j, &pvec.encs[j], &dec, &dss_pk[j])
            );
        }
    }

    #[test]
    fn test_reconstruction() {
        let mut rng = std_rng();
        let n = 3;
        let t = 1;
        
        let mut public_keys = Vec::new();
        let mut secret_keys = Vec::new();
        let mut dss_kpair = Vec::new();
        let mut dss_pk = Vec::new();
        for _i in 0..n {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.push(dsskpair.public());
            dss_kpair.push(dsskpair);
        }
        let h2 = <E as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<E>::rand(&mut rng).into_repr());

        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::<E>::new(&mut rng, h2, n, t, i, public_keys.clone(), secret_keys[i])
        }).collect();
        let s = Scalar::<E>::rand(&mut rng);
        let pvec = 
            dbs_ctx[0].generate_share_for_point(&dss_kpair[0], &mut rng, s);
        assert_eq!(None, 
            dbs_ctx[1].verify_sharing(&pvec, &dss_pk[0]));
        let mut decs:Vec<_> = (0..n).map(|j| {
            let dec = 
            dbs_ctx[j].decrypt_share(&pvec.encs[j], &dss_kpair[j], &mut rng);
            assert_eq!(None, dbs_ctx[0].verify_share(j, &pvec.encs[j], &dec, &dss_pk[j]));
            Some(dec.dec)
        }).collect();
        for i in 0..n-(t+1) {
            decs[i] = None;
        }
        
        let beacon = dbs_ctx[0].reconstruct(&decs);

        let gs_orig = dbs_ctx[0].optimizations.g1p.mul(s.into_repr());
        assert_eq!(beacon.value, gs_orig);
        assert_eq!(beacon.beacon, E::pairing(beacon.value, dbs_ctx[0].h2p));
    }
}
