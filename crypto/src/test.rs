#[cfg(test)]
mod keypair_tests {
    use crate::{std_rng, Keypair};

    #[test]
    fn test_gen() {
        let mut rng = std_rng();
        let _ = Keypair::generate_keypair(&mut rng);
    }
}


#[cfg(test)]
mod ctx_tests {
    use crate::{DbsContext, Keypair, std_rng, G2, Scalar};
    use ark_std::UniformRand;
    use ark_ec::AffineCurve;

    #[test]
    fn test_gen() {
        let mut rng = std_rng();
        let h2 = G2::prime_subgroup_generator().mul(Scalar::rand(&mut rng));
        let n = 21;
        let t = 10;
        let keypairs:Vec<_> = (0..n).map(|_i| {
            let kpair = Keypair::generate_keypair(&mut rng);
            kpair
        }).collect();
        let public_keys = (0..n).map(|i| {
            keypairs[i].1
        }).collect();
        let _ = DbsContext::new(&mut rng, h2, n, t, 0, public_keys, keypairs[0].0);
    }
}


#[cfg(test)]
mod dleq_tests {
    use crate::{DbsContext, Keypair, std_rng, G2, Scalar};
    use ark_std::UniformRand;
    use ark_ec::AffineCurve;

    #[test]
    fn test_dleq() {
        let mut rng = std_rng();
        let n = 101;
        let t = 50;
        let mut public_keys = Vec::new();
        let mut secret_keys = Vec::new();
        let dss_kpair = crypto_lib::Keypair::generate_secp256k1();
        let dss_pk = dss_kpair.public();
        for _i in 0..n {
            let kpair = Keypair::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
        }
        let h2 = G2::prime_subgroup_generator().mul(Scalar::rand(&mut rng));

        let dbs_ctx = DbsContext::new(&mut rng, h2, n, t, 0, public_keys, secret_keys[0]);
        let pvec = 
            dbs_ctx.generate_shares( &dss_kpair, &mut rng);
        for i in 0..n {
            assert_eq!(None, 
                crate::Dleq::verify(&pvec.proofs[i], &dbs_ctx.public_keys[i], &pvec.encs[i], &dbs_ctx.h1, &pvec.comms[i], &dss_pk));
        }
    }
}

#[cfg(test)]
mod dbs_tests {
    use crate::{DbsContext, Keypair, std_rng, G2, Scalar};
    use ark_bls12_381::Bls12_381;
    use ark_std::UniformRand;
    use ark_ec::{AffineCurve, ProjectiveCurve, PairingEngine};
    use fnv::FnvHashMap as HashMap;
    
    #[test]
    fn gen_test() {
        let mut rng = std_rng();
        let n = 21;
        let t = 10;
        
        let mut public_keys = Vec::new();
        let mut secret_keys = Vec::new();
        let mut dss_kpair = Vec::new();
        let mut dss_pk = Vec::new();
        for _i in 0..n {
            let kpair = Keypair::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.push(dsskpair.public());
            dss_kpair.push(dsskpair);
        }
        let h2 = G2::prime_subgroup_generator().mul(Scalar::rand(&mut rng));

        let dbs_ctx = DbsContext::new(&mut rng, h2,n, t, 0, public_keys, secret_keys[0]);
        let idx = 0;
        let pvec = 
            dbs_ctx.generate_shares(&dss_kpair[idx], &mut rng);
        assert_eq!(None, dbs_ctx.verify_sharing(&pvec, &dss_pk[idx]));
    }
    
    #[test]
    fn agg_test() {
        let mut rng = std_rng();
        let n:usize = 21;
        let t = 10;
        
        let mut public_keys = Vec::new();
        let mut secret_keys = Vec::new();
        let mut dss_kpair:HashMap<_,_> = HashMap::default();
        let mut dss_pk:HashMap<_,_> = HashMap::default();
        let mut pvecs = Vec::new();
        for i in 0..n {
            let kpair = Keypair::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.insert(i,dsskpair.public() );
            dss_kpair.insert(i, dsskpair);
        }
        let h2 = G2::prime_subgroup_generator().mul(Scalar::rand(&mut rng));

        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::new(&mut rng, h2, n as usize, t, i, public_keys.clone(), secret_keys[i as usize].clone())
        }).collect();
        let indices:Vec<_> = (0..t+1).map(|i| i).collect();
        for i in 0..t+1 {
            let pvec = 
            dbs_ctx[i].generate_shares(&dss_kpair[&i], &mut rng);
            assert_eq!(None, dbs_ctx[i].verify_sharing(&pvec, &dss_pk[&i]));
            pvecs.push(pvec);
        }
        let (agg_pvss, agg_pi) = dbs_ctx[0].aggregate(&indices, &pvecs);
        assert_eq!(None, dbs_ctx[0].pverify(&agg_pvss));
        for i in 0..n {
            assert_eq!(None, 
                dbs_ctx[i as usize].decomp_verify(&agg_pvss, &agg_pi[i], &dss_pk)
            );
        }
    }

    #[test]
    fn decryption_test() {
        let mut rng = std_rng();
        let n = 21;
        let t = 10;
        
        let mut public_keys = Vec::new();
        let mut secret_keys = Vec::new();
        let mut dss_kpair = Vec::new();
        let mut dss_pk = Vec::new();
        for _i in 0..n {
            let kpair = Keypair::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.push(dsskpair.public());
            dss_kpair.push(dsskpair);
        }
        let h2 = G2::prime_subgroup_generator().mul(Scalar::rand(&mut rng));

        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::new(&mut rng, h2, n, t, i, public_keys.clone(), secret_keys[i])
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
            let kpair = Keypair::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.push(dsskpair.public());
            dss_kpair.push(dsskpair);
        }
        let h2 = G2::prime_subgroup_generator().mul(Scalar::rand(&mut rng));

        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::new(&mut rng, h2, n, t, i, public_keys.clone(), secret_keys[i])
        }).collect();
        let s = Scalar::rand(&mut rng);
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

        let gs_orig = dbs_ctx[0].g.mul(s).into_affine();
        assert_eq!(beacon.1, gs_orig);
        assert_eq!(beacon.0, Bls12_381::pairing(beacon.1, dbs_ctx[0].h2));
    }
}
