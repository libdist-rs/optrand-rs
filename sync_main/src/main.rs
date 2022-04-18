use std::error::Error;
use consensus::spawn_leader_thread;
use types::ProtocolMsg;

mod io;

pub const NUM_NET_CPU:usize = 1;
pub const NUM_CORE_CPU:usize = 1;

fn main() -> Result<(), Box<dyn Error>> {
    let config = io::load_config();
    log::debug!("Successfully decoded the config file");

    let num_cpus = num_cpus::get();
    let net_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(NUM_NET_CPU)
        .build()?;
    
    // Build protocol networks
    let protocol_network = net::tokio_manager::Protocol::<ProtocolMsg, ProtocolMsg>::new(
        config.id,
        config.num_nodes,
        config.root_cert.clone(),
        config.my_cert.clone(),
        config.my_cert_key.clone()
    );

    // Start the protocol network
    let (net_send, net_recv) = net_rt.block_on(
        protocol_network.server_setup(
            config.net_map.clone(),
            util::codec::EnCodec::new(),
            util::codec::proto::Codec::new(),
        )
    );

    let opt_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_cpus - NUM_CORE_CPU - NUM_NET_CPU)
        .build()?;
    let ctx = config.pvss_ctx.clone();
    let ch = opt_rt.block_on(async {
        spawn_leader_thread(
            config.num_faults,
            ctx,
            config.get_public_key_map()
        )
    });

    let core_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(1)
        .build()?;

    // Start the Optrand reactor on the second thread
    core_rt.block_on(
        consensus::sync_sm::reactor_opt(config,
            net_send,
            net_recv,
            ch,
        )
    );
    Ok(())
    
}
