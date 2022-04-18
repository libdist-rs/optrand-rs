// A tool that builds config files for all the nodes and the clients for the
// protocol.

use clap::{load_yaml, App};
use config::{OutputType, generate_configs};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
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
        "binary" => OutputType::Binary,
        "json" => OutputType::JSON,
        "toml" => OutputType::TOML,
        "yaml" => OutputType::Yaml,
        _ => OutputType::Binary,
    };
    let target = m
        .value_of("target")
        .expect("target directory for the config not specified");
    let num_clients = m.value_of("num_clients").unwrap_or("1").parse()?;
    let cli_base_port = m.value_of("client_base_port")
        .unwrap_or("5000")
        .parse()?;
    
    let (nodes, clients) = generate_configs(num_nodes, num_faults, delay, base_port, num_clients, cli_base_port)?;

    // Write all the files
    for i in 0..num_nodes {
        nodes[i].validate()?;
        nodes[i].write_file(out, target);
    }
    for i in 0..num_clients {
        clients[i].validate()?;
        clients[i].write_file(out, target);
    }
    Ok(())
}
