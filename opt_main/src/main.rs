use std::error::Error;
use types::{ProtocolMsg, ReconfigurationMsg};

mod io;

// pub const NUM_NET_CPU:usize = 2;
pub const NUM_NET_CPU:usize = 1;
pub const NUM_CORE_CPU:usize = 1;

fn main() -> Result<(), Box<dyn Error>> {
    let config = io::load_config();
    log::debug!(target:"app","Successfully decoded the config file");

    let num_cpus = num_cpus::get();

    let net_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(NUM_NET_CPU)
        .build()?;
    
    // Build protocol networks
    let protocol_network =
        net::tokio_manager::Protocol::<ProtocolMsg, ProtocolMsg>::new(
            config.id, 
            config.num_nodes,
            config.root_cert.clone(), 
            config.my_cert.clone(), 
            config.my_cert_key.clone() 
        );

    // Build protocol networks
    let cli_net = net::tokio_manager::Protocol::<ReconfigurationMsg, ReconfigurationMsg>::new(
        config.id, 
        config.num_nodes, 
        config.root_cert.clone(), 
        config.my_cert.clone(), 
        config.my_cert_key.clone()
    );

    let (cli_send, cli_recv) = 
    net_rt.block_on(
        cli_net.client_setup(
            config.client_ip(),
            util::codec::EnCodec::new(),
            util::codec::reconfig::Codec::new(),
        )
    );

    // Start the protocol network
    let (net_send, net_recv) = 
    net_rt.block_on(
    protocol_network.server_setup(
        config.net_map.clone(),
        util::codec::EnCodec::new(),
        util::codec::proto::Codec::new(),
    ));

    let core_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_cpus - NUM_NET_CPU)
        .build()?;

    // Start the optrand reactor on the second thread
    core_rt.block_on(
    consensus::optimistic_sm::reactor(
        config,
        net_send,
        net_recv,
        cli_send,
        cli_recv
    ));
    Ok(())
}
