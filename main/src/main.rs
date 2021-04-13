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

    // Start a second thread to react to the consensus messages
    let core_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();

    // Start the optrand reactor on the second thread
    core_rt.block_on(consensus::reactor(
        config,
        net_send,
        net_recv,
    ));
    Ok(())
}
