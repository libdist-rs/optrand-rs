// A tool that builds config files for all the nodes and the clients for the
// protocol.

use std::collections::VecDeque;
use clap::{load_yaml, App};
use config::Node;
// use crypto::rand::{rngs::StdRng, SeedableRng};
use crypto_lib::{ed25519, Algorithm};
use types::Replica;
use fnv::FnvHashMap as HashMap;

mod io;

fn main() {
    let yaml = load_yaml!("cli.yml");
    let m = App::from_yaml(yaml).get_matches();
    let num_nodes: usize = m
        .value_of("num_nodes")
        .expect("number of nodes not specified")
        .parse::<usize>()
        .expect("unable to convert number of nodes into a number");
    let num_faults: usize = match m.value_of("num_faults") {
        Some(x) => x
            .parse::<usize>()
            .expect("unable to convert number of faults into a number"),
        None => (num_nodes - 1) / 2,
    };
    let delay: u64 = m
        .value_of("delay")
        .expect("delay value not specified")
        .parse::<u64>()
        .expect("unable to parse delay value into a number");
    let base_port: u16 = m
        .value_of("base_port")
        .expect("base_port value not specified")
        .parse::<u16>()
        .expect("failed to parse base_port into a number");
    let out = match m.value_of("out_type").unwrap_or("binary") {
        "binary" => io::OutputType::Binary,
        "json" => io::OutputType::JSON,
        "toml" => io::OutputType::TOML,
        "yaml" => io::OutputType::Yaml,
        _ => io::OutputType::Binary,
    };
    let target = m
        .value_of("target")
        .expect("target directory for the config not specified");
    
    let mut node: Vec<Node> = Vec::with_capacity(num_nodes);

    let mut pk = HashMap::default();
    let mut keypairs = HashMap::default();
    let mut ip = HashMap::default();

    // PVSS public keys and secret keys
    let mut pvss_pk_map = Vec::new();
    let mut pvss_sk_map = Vec::new();

    let mut rng = crypto::std_rng();
    let h2 = crypto::rand_g2_generator(&mut rng);

    for _i in 0..num_nodes {
        let pvss_keypair = crypto::Keypair::generate_keypair(&mut rng);
        pvss_sk_map.push(pvss_keypair.0);
        pvss_pk_map.push(pvss_keypair.1);
    }

    let mut pvss_ctx_map:HashMap<_,_> = HashMap::default();
    for i in 0..num_nodes {
        let ctx = crypto::DbsContext::new(&mut rng, 
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
        node.push(new_node);

        node[i].crypto_alg = Algorithm::ED25519;

        node[i].delta = delay;
        node[i].id = i as Replica;
        node[i].num_nodes = num_nodes;
        node[i].num_faults = num_faults;
           
        ip.insert(
            i as Replica,
            format!("{}:{}", "127.0.0.1", base_port + (i as u16)),
        );
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
        let sh1 = node[i].pvss_ctx.generate_shares(&keypairs[&i], &mut rng);
        let sh2 = node[i].pvss_ctx.generate_shares(&keypairs[&i], &mut rng);
        let pvec = [sh1, sh2];
        let (combined_pvss,_) = node[i].pvss_ctx.aggregate(&indices, &pvec);
        // Put combined_pvss in everyone's buffers, i.e., in rand_queue for node 1
        for j in 0..num_nodes {
            let mut queue = VecDeque::new();
            queue.push_front(combined_pvss.clone());
            node[j].rand_beacon_queue.insert(i, queue);
        }
    }

    // Write all the files
    for i in 0..num_nodes {
        node[i].validate().expect("failed to validate node config");
        io::write_file_for_node(out, target, i, &node[i]);
    }
}
