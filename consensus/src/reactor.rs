use config::Node;
use crypto::std_rng;
use crate::{EventQueue, OptRandStateMachine, events::{Event, TimeOutEvent}};
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::{mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender, channel}, oneshot};
use types::{PVSSVec, ProtocolMsg, Replica, START_EPOCH};
use tokio_util::time::DelayQueue;
use tokio_stream::StreamExt;

pub type VerifyReceiver = Sender<(Replica, PVSSVec, tokio::sync::oneshot::Sender<(Replica, PVSSVec)>)>;

pub async fn reactor(
    config: Node,
    net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,
    mut net_recv: UnboundedReceiver<(Replica, ProtocolMsg)>,
) 
{
    // let (sh_out, verify_in) = spawn_share_thread(&config);
    let mut not_stop = true;

    let delta = config.delta;
    let mut osm = OptRandStateMachine::new(config);

    // A little time to boot everything up
    let mut ev_queue = EventQueue::with_capacity(100_000);
    // We wait for the first epoch (START_EPOCH) to timeout empty, and from then on start the protocol at epoch START_EPOCH+1 with the next leader and so on.
    ev_queue.add_timeout(
        TimeOutEvent::EpochTimeOut(START_EPOCH), 
        Duration::from_millis(11*delta)
    );

    loop {
        tokio::select! {
            pmsg_opt = net_recv.recv() => {
                if let None = pmsg_opt {
                    log::warn!("Failed to decode message from the network: {:?}", pmsg_opt);
                    break;
                }
                let (sender, msg) = pmsg_opt.unwrap();
                log::debug!("Got a new message from {}", sender);
                // log::debug!("Got {}", msg.hex_display());
                unimplemented!()
            }
            phase = ev_queue.next() => {
                let ev = phase.unwrap();
                if let Err(e) = osm.on_new_event(ev, &mut ev_queue) {
                    log::error!("Consensus error: {}", e);
                }
            }
            // sh = cx.sh_out.recv(), if not_stop => {
                // let share = sh
                //     .expect("failed to get a share from the share thread");
                // cx.storage.round_shares.push_back(share);
                // if cx.storage.round_shares.len() > cx.num_nodes() {
                //     not_stop = false;
                // }
            // }
            // verified_sh = cx.verified_shares.recv() => {
                // let (sender, share) = verified_sh.unwrap();
                // cx.ev_queue.push_back(Event::NewVerifiedShare(sender, share));
            // }
        }
        // while let Some(x) = cx.ev_queue.pop_front() {
        //     cx.handle_event(x, &mut delay_queue).await;
        // }
    }
}

// fn spawn_share_thread(config: &Node) -> 
//     (Receiver<PVSSVec>, VerifyReceiver) 
// {
//     let pvss_ctx = config.pvss_ctx.clone();
//     let my_sk = config.get_secret_key();
//     let (sh_in, sh_out) = channel(config.num_nodes*config.num_nodes);
//     // This thread generates shares
//     std::thread::spawn(move || {
//         let mut rng = std_rng();
//         loop {
//             let new_share = pvss_ctx.generate_shares(&my_sk, &mut rng);
//             // Testing
//             // Delete after testing
//             sh_in
//                 .blocking_send(new_share)
//                 .expect("Failed to send new shares");
//         }
//     });


//     let pvss_ctx = config.pvss_ctx.clone();
//     let pk_map = config.get_public_key_map();
//     let (verified_sh_in, mut verified_sh_out) = channel::<(Replica, PVSSVec, oneshot::Sender<(Replica, PVSSVec)>)>(config.num_nodes*config.num_nodes);
//     let myid = config.id;
//     // This thread verifies shares
//     std::thread::spawn(move || {
//         // let mut rng = std_rng();
//         // let mut pvss_ctx = pvss_ctx;
//         // pvss_ctx.init(&mut rng);
//         loop {
//             let (sender, sh_to_verify, ch) = verified_sh_out.blocking_recv().unwrap();
//             // My shares are always correct
//             if sender == myid {
//                 ch.send((sender, sh_to_verify)).unwrap();
//                 continue;
//             }
//             if let Some(err) = pvss_ctx.verify_sharing(&sh_to_verify, &pk_map[&sender]) {
//                 log::error!("Error when verifying share for {}: {:?}", sender, err);
//                 continue;
//             }
//             ch.send((sender, sh_to_verify)).unwrap();
//         }
//     });
//     (sh_out, verified_sh_in)
// }
