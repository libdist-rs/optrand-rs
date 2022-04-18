use config::Node;
use log::{warn, debug, error};
use crate::*;
use super::OptRandStateMachine;
use tokio::sync::{mpsc::{Sender, UnboundedReceiver, UnboundedSender}, oneshot};
use types::{PVSSVec, ProtocolMsg, ReconfigurationMsg, Replica};
use tokio_stream::StreamExt;

pub type VerifyReceiver = Sender<(Replica, PVSSVec, oneshot::Sender<(Replica, PVSSVec)>)>;

pub async fn reactor(
    config: Node,
    net_send: UnboundedSender<OutMsg>,
    mut net_recv: UnboundedReceiver<(Replica, ProtocolMsg)>,
    _cli_send: UnboundedSender<CliOutMsg>,
    mut cli_recv: UnboundedReceiver<ReconfigurationMsg>,
) 
{
    let mut osm = OptRandStateMachine::new(config, net_send);
    osm.start_sync();

    loop {
        tokio::select! {
            pmsg_opt = net_recv.recv() => {
                if let None = pmsg_opt {
                    warn!("Failed to decode message from the network: {:?}", pmsg_opt);
                    break;
                }
                let (sender, msg) = pmsg_opt.unwrap();
                if let Err(e) = osm.on_new_msg(sender, msg) {
                    error!("Consensus error: {}", e);
                }
            }
            phase = osm.ev_queue.next() => {
                let ev = phase.unwrap();
                if let Err(e) = osm.on_new_event(ev) {
                    log::error!("Consensus error: {}", e);
                }
            }
            msg_opt = cli_recv.recv() => {
                println!("Got something from a client: {:?}", msg_opt);
            }
        }
    }
}