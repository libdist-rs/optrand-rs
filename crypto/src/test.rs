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
    use ark_ec::{PairingEngine, AffineCurve};
    use ark_std::UniformRand;
    use ark_ff::PrimeField;

    #[test]
    fn test_gen() {
        let mut rng = std_rng();
        let h2 = <Bls12_381 as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<Bls12_381>::rand(&mut rng).into_repr());
        let n = 21;
        let t = 10;
        let keypairs:Vec<_> = (0..n).map(|_i| {
            let kpair = Keypair::<Bls12_381>::generate_keypair(&mut rng);
            kpair
        }).collect();
        let public_keys = (0..n).map(|i| {
            keypairs[i].1
        }).collect();
        let _ = DbsContext::<Bls12_381>::new(&mut rng, h2, n, t, 0, public_keys, keypairs[0].0);
    }
}


#[cfg(test)]
mod dleq_tests {
    use crate::{DbsContext, Keypair, PublicKey, Scalar, SecretKey, std_rng};
    use ark_bls12_381::Bls12_381;
    use ark_std::UniformRand;
    use ark_ec::{PairingEngine, AffineCurve};
    use ark_ff::PrimeField;

    type E = Bls12_381;

    #[test]
    fn test_dleq() {
        let mut rng = std_rng();
        let n = 101;
        let t = 50;
        let mut public_keys: Vec<PublicKey<E>> = Vec::new();
        let mut secret_keys: Vec<SecretKey<E>> = Vec::new();
        let dss_kpair = crypto_lib::Keypair::generate_secp256k1();
        let dss_pk = dss_kpair.public();
        for _i in 0..n {
            let kpair = Keypair::<E>::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
        }
        let h2 = <E as PairingEngine>::G2Affine::prime_subgroup_generator().mul(Scalar::<E>::rand(&mut rng).into_repr());

        let dbs_ctx = DbsContext::<E>::new(&mut rng, h2, n, t, 0, public_keys, secret_keys[0]);
        let pvec = 
            dbs_ctx.generate_shares( &dss_kpair, &mut rng);
        for i in 0..n {
            assert_eq!(None, 
                crate::Dleq::verify(&pvec.proofs[i], &dbs_ctx.public_keys[i], &pvec.encs[i], &dbs_ctx.optimizations.g2p, &pvec.comms[i].into_projective(), &dss_pk));
        }
    }
}

#[cfg(test)]
mod dbs_tests {
    use crate::{DbsContext, Keypair, PublicKey, Scalar, SecretKey, std_rng};
    use ark_bls12_381::Bls12_381;
    use ark_std::UniformRand;
    use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
    use ark_ff::PrimeField;
    use fnv::FnvHashMap as HashMap;

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
        assert_eq!(None, dbs_ctx.verify_sharing(&pvec, &dss_pk[idx]));
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
