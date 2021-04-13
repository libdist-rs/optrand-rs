use super::context::Context;
use config::Node;
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time;
use types::{ProtocolMsg, Replica};

#[derive(PartialEq, Debug)]
enum Phase {
    Propose,
    DeliverPropose,
    DeliverCommit,
    Vote,
    Commit,
    End,
}

impl Phase {
    pub fn to_string(&self) -> &'static str {
        match self {
            Phase::Propose => "Propose",
            Phase::DeliverPropose => "DeliverPropose",
            Phase::DeliverCommit => "DeliverCommit",
            Phase::Vote => "Vote",
            Phase::Commit => "Commit",
            Phase::End => "End",
        }
    }
}

pub async fn reactor(
    config: Node,
    net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,
    mut net_recv: UnboundedReceiver<(Replica, ProtocolMsg)>,
) {
    let cx = Context::new(config, net_send);
    let delta = cx.delta();
    // A little time to boot everything up
    let begin = time::Instant::now() + Duration::from_millis(delta);
    let phase_end = time::sleep_until(begin);
    tokio::pin!(phase_end);
    loop {
        tokio::select! {
            _x = net_recv.recv() => {
                log::info!("Got {:?}", _x);
            }
        }
    }
}
