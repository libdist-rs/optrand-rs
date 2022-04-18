use clap::{load_yaml, App};
use config::Reconfig as Client;
use net::tokio_manager::TlsClient;
use types::ReconfigurationMsg;
use util::codec::EnCodec;
use std::{error::Error, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let yaml = load_yaml!("cli.yml");
    let m = App::from_yaml(yaml).get_matches();

    let conf_str = m.value_of("config")
        .expect("unable to convert config file into a string");
    let conf_file = std::path::Path::new(conf_str);
    let str = String::from(conf_str);
    let mut config = match conf_file
        .extension()
        .expect("Unable to get file extension")
        .to_str()
        .expect("Failed to convert the extension into ascii string") 
    {
        "json" => Client::from_json(str),
        "dat" => Client::from_bin(str),
        "toml" => Client::from_toml(str),
        "yaml" => Client::from_yaml(str),
        _ => panic!("Invalid config file extension"),
    };
    config
        .validate()
        .expect("The decoded config is not valid");
    if let Some(f) = m.value_of("ip") {
        config.update_config(util::io::file_to_ips(f.to_string()));
    }
    let config = config;

    simple_logger::SimpleLogger::new().init().unwrap();
    let x = m.occurrences_of("debug");
    match x {
        0 => log::set_max_level(log::LevelFilter::Info),
        1 => log::set_max_level(log::LevelFilter::Debug),
        2 | _ => log::set_max_level(log::LevelFilter::Trace),
    }

    log::info!("Successfully decoded the config file");
    
    // Connect to the servers

    let mut client_network = TlsClient::<ReconfigurationMsg, ReconfigurationMsg>::new(config.root_cert.clone());
        let servers = config.net_map.clone();
        // let send_id = config.num_nodes;
        let (net_send, net_recv) = 
            client_network.setup(servers, EnCodec::new(), util::codec::reconfig::Codec::new()).await;
    
    let config = Arc::new(config);
    consensus::reconfig::reactor(config, net_send, net_recv).await;
    Ok(())
}
