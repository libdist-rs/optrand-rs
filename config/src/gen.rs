use std::collections::VecDeque;

use crypto_lib::{Algorithm, ed25519};
use types::{DbsContext, Keypair, Replica, Result};
use crate::{INITIAL_PVSS_BUFFER, Node, cert};
use fnv::FnvHashMap as HashMap;

pub fn generate_configs(num_nodes: usize, num_faults: usize, delay: u64, base_port: u16) -> Result<VecDeque<Node>> {
    let mut node: VecDeque<Node> = VecDeque::with_capacity(num_nodes);
    let (cert, privkey) = cert::new_root_cert()?;

    let mut pk = HashMap::default();
    let mut keypairs = HashMap::default();
    let mut ip = HashMap::default();

    // PVSS public keys and secret keys
    let mut pvss_pk_map = Vec::new();
    let mut pvss_sk_map = Vec::new();

    let mut rng = crypto::std_rng();
    let h2 = crypto::rand_h2_generator::<_,types::E>(&mut rng);

    for _i in 0..num_nodes {
        let pvss_keypair = Keypair::generate_keypair(&mut rng);
        pvss_sk_map.push(pvss_keypair.0);
        pvss_pk_map.push(pvss_keypair.1);
    }

    let mut pvss_ctx_map:HashMap<_,_> = HashMap::default();
    for i in 0..num_nodes {
        let ctx = DbsContext::new(&mut rng, 
            h2, 
            num_nodes, 
            num_faults, 
            i, 
            pvss_pk_map.clone(), 
            pvss_sk_map[i].clone(),
        );
        pvss_ctx_map.insert(i, ctx);
    }

    for i in 0..num_nodes {
        let kp = ed25519::Keypair::generate();
        keypairs.insert(i, crypto_lib::Keypair::Ed25519(kp.clone()));
        pk.insert(i as Replica, kp.public().encode().to_vec());
        let new_node = Node::new(kp.encode().to_vec(), pvss_ctx_map.remove(&i).unwrap());
        node.push_back(new_node);

        node[i].crypto_alg = Algorithm::ED25519;

        node[i].delta = delay;
        node[i].id = i as Replica;
        node[i].num_nodes = num_nodes;
        node[i].num_faults = num_faults;
           
        ip.insert(
            i as Replica,
            format!("{}:{}", "127.0.0.1", base_port + (i as u16)),
        );

        let (new_cert, new_pkey) = cert::get_signed_cert(&cert, &privkey)?;

        node[i].root_cert = cert.to_der()?;
        node[i].my_cert = new_cert.to_der()?;
        node[i].my_cert_key = new_pkey.private_key_to_der()?;
    }

    for i in 0..num_nodes {
        node[i].set_pk_map_data(pk.clone());
        node[i].net_map = ip.clone();
    }

    for i in 0..num_nodes {
        for j in 0..num_nodes {
            node[j].rand_beacon_queue.insert(
                i as Replica,
                std::collections::VecDeque::with_capacity(num_nodes + num_faults),
            );
        }
    }

    // Since we are generating all the config files in one place, it is okay to aggregate two random PVSS sharings generated here.
    // In the real world, start with the config as seed or run another protocol to generate the first n sharings
    // I mean, come on! If you trust this file to generate keys for your protocol, you can trust this file to generate the seed properly too :)
    let indices = [1, 2]; // We will throw this away anyways
    for i in 0..num_nodes {
        for _k in 0..INITIAL_PVSS_BUFFER {
            let sh1 = node[i].pvss_ctx.generate_shares(&keypairs[&i], &mut rng);
            let sh2 = node[i].pvss_ctx.generate_shares(&keypairs[&i], &mut rng);
            let pvec = vec![sh1, sh2];
            let (combined_pvss,_) = node[i].pvss_ctx.aggregate(&indices, pvec);
            // Put combined_pvss in everyone's buffers, i.e., in rand_queue for node 1
            for j in 0..num_nodes {
                let mut queue = VecDeque::new();
                queue.push_front(combined_pvss.clone());
                node[j].rand_beacon_queue.insert(i, queue);
            }
        }
        
        let mut queue = VecDeque::new();
        for j in 0..num_faults+1 {
            let sh = node[j].pvss_ctx.generate_shares(&keypairs[&j], &mut rng);
            queue.push_back(sh);
        }
        node[i].beacon_sharing_buffer.insert(i, queue);
    }
    Ok(node)
}