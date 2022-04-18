use std::sync::Arc;

use config::Reconfig;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use types::{ReconfigurationMsg, Replica};


pub async fn reactor(
    config: Arc<Reconfig>,
    net_send: UnboundedSender<(Replica, Arc<ReconfigurationMsg>)>,
    net_recv: UnboundedReceiver<(Replica, ReconfigurationMsg)>,
)
{
    log::info!("Starting the client");
    net_send.send((0, Arc::new(ReconfigurationMsg::Inquire))).unwrap();
}