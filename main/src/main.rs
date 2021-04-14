use std::error::Error;
use types::{ProtocolMsg};

mod io;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = io::load_config();
    log::info!(target:"app","Successfully decoded the config file");

    // Build protocol networks
    let protocol_network =
        net::tokio_manager::Protocol::<ProtocolMsg, ProtocolMsg>::new(
            config.id, 
            config.num_nodes,
            config.root_cert.clone(), 
            config.my_cert.clone(), 
            config.my_cert_key.clone() 
        );

    // Start the protocol network
    let (net_send, net_recv) = protocol_network.server_setup(
        config.net_map.clone(),
        util::codec::EnCodec::new(),
        util::codec::proto::Codec::new(),
    ).await;

    // Start the optrand reactor on the second thread
    consensus::reactor(
        config,
        net_send,
        net_recv,
    ).await;
    Ok(())
}
