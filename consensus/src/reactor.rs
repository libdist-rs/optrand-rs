use super::{Context, Event};
use config::Node;
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use types::{ProtocolMsg, Replica};
use tokio_util::time::DelayQueue;
use tokio_stream::StreamExt;

pub async fn reactor(
    config: Node,
    net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,
    mut net_recv: UnboundedReceiver<(Replica, ProtocolMsg)>,
) {
    let mut cx = Context::new(config, net_send);
    let delta = cx.delta();
    // A little time to boot everything up
    let mut delay_queue:DelayQueue<_> = DelayQueue::new();
    delay_queue.insert(Event::EpochEnd, Duration::from_millis(11*delta));
    loop {
        tokio::select! {
            pmsg_opt = net_recv.recv() => {
                if let None = pmsg_opt {
                    log::warn!("Failed to decode message from the network: {:?}", pmsg_opt);
                    break;
                }
                let pmsg = pmsg_opt.unwrap();
                cx.handle_message(pmsg.0, pmsg.1, &mut delay_queue).await;
            }
            phase = delay_queue.next() => {
                let phase = phase.unwrap().unwrap().into_inner();
                cx.handle_event(phase, &mut delay_queue).await;
            }
        }
    }
}
