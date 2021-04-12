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
    use crate::{DbsContext, Keypair, std_rng};

    #[test]
    fn test_gen() {
        let mut rng = std_rng();
        let n = 21;
        let t = 10;
        let keypairs:Vec<_> = (0..n).map(|_i| {
            let kpair = Keypair::generate_keypair(&mut rng);
            kpair
        }).collect();
        let public_keys = (0..n).map(|i| {
            keypairs[i].1
        }).collect();
        let _ = DbsContext::new(&mut rng, n, t, 0, public_keys, keypairs[0].0);
    }
}


#[cfg(test)]
mod dleq_tests {
    use crate::{DbsContext, Keypair, std_rng};

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
        let dbs_ctx = DbsContext::new(&mut rng, n, t, 0, public_keys, secret_keys[0]);
        let (_s,_, comms,encs,pi) = 
            dbs_ctx.generate_shares( &dss_kpair, &mut rng);
        for i in 0..n {
            assert_eq!(None, 
                crate::Dleq::verify(&pi[i], &dbs_ctx.public_keys[i], &encs[i], &dbs_ctx.h1, &comms[i], &dss_pk));
        }
        
    }
}

#[cfg(test)]
mod dbs_tests {
    // use ark_bls12_381::Bls12_381;

    use crate::{DbsContext, Keypair, std_rng};
    use std::collections::HashMap;
    
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
        let dbs_ctx = DbsContext::new(&mut rng, n, t, 0, public_keys, secret_keys[0]);
        let idx = 0;
        let (_s,_, v,c,pi) = 
            dbs_ctx.generate_shares(&dss_kpair[idx], &mut rng);
        assert_eq!(None, dbs_ctx.verify_sharing(&v, &c, &pi, &dss_pk[idx]));
    }
    
    #[test]
    fn agg_test() {
        let mut rng = std_rng();
        let n = 21;
        let t = 10;
        
        let mut public_keys = Vec::new();
        let mut secret_keys = Vec::new();
        let mut dss_kpair:HashMap<u16,_> = HashMap::new();
        let mut dss_pk:HashMap<u16,_> = HashMap::new();
        let mut comms = Vec::new();
        let mut encs = Vec::new();
        let mut proofs = Vec::new();
        for i in 0..n {
            let kpair = Keypair::generate_keypair(&mut rng);
            secret_keys.push(kpair.0);
            public_keys.push(kpair.1);
            let dsskpair = crypto_lib::Keypair::generate_secp256k1();
            dss_pk.insert(i,dsskpair.public() );
            dss_kpair.insert(i, dsskpair);
        }
        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::new(&mut rng, n as usize, t, i, public_keys.clone(), secret_keys[i as usize].clone())
        }).collect();
        let indices = (0..t+1).map(|i| i as u16).collect();
        for i in 0..t+1 {
            let (_s,_, v,c,pi) = 
            dbs_ctx[i].generate_shares(&dss_kpair[&(i as u16)], &mut rng);
            assert_eq!(None, dbs_ctx[i].verify_sharing(&v, &c, &pi, &dss_pk[&(i as u16)]));
            comms.push(v);
            encs.push(c);
            proofs.push(pi);
        }
        let (agg_pvss, agg_pi) = dbs_ctx[0].aggregate(indices, encs, comms, proofs);
        assert_eq!(None, dbs_ctx[0].pverify(&agg_pvss));
        for i in 0..n {
            assert_eq!(None, 
                dbs_ctx[i as usize].decomp_verify(&agg_pvss, &agg_pi[i as usize], &dss_pk)
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
        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::new(&mut rng, n, t, i as u16, public_keys.clone(), secret_keys[i])
        }).collect();
        let (_s,_, _v,c,_pi) = 
            dbs_ctx[0].generate_shares(&dss_kpair[0], &mut rng);
        
        for j in 0..n {
            let (d,pi) = 
            dbs_ctx[j].decrypt_share(c[j], &dss_kpair[j], &mut rng);
            assert_eq!(None, 
                dbs_ctx[0].verify_share(j, &d, &c[j], &pi, &dss_pk[j])
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
        let dbs_ctx:Vec<_> = (0..n).map(|i| {
            DbsContext::new(&mut rng, n, t, i as u16, public_keys.clone(), secret_keys[i])
        }).collect();
        let (s,gs_orig, v,c,pi_sharing) = 
            dbs_ctx[0].generate_shares(&dss_kpair[0], &mut rng);
        assert_eq!(None, 
            dbs_ctx[1].verify_sharing(&v, &c, &pi_sharing, &dss_pk[0]));
        let mut decs:Vec<_> = (0..n).map(|j| {
            let (d,pi) = 
            dbs_ctx[j].decrypt_share(c[j], &dss_kpair[j], &mut rng);
            assert_eq!(None, dbs_ctx[0].verify_share(j, &d, &c[j], &pi, &dss_pk[j]));
            Some(d)
        }).collect();
        for i in 0..n-(t+1) {
            decs[i] = None;
        }
        
        let (secret,gs) = dbs_ctx[0].reconstruct(&decs);

        assert_eq!(gs, gs_orig);
        assert_eq!(secret, s);
    }
}
