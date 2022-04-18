use super::OptRandStateMachine;
use log::debug;
use types::{Replica, Result, ProtocolMsg};
use std::fmt::Debug;

impl OptRandStateMachine {
    // `on_new_msg` takes incoming protocol messages, validates it and then calls the `on_new_msg_event`
    pub(crate) fn on_new_msg(&mut self, 
        sender: Replica,
        msg: ProtocolMsg, 
    ) -> Result<()> 
    {
        debug!("Got msg: {:?} from {}", msg, sender);
        #[cfg(feature = "profile")]
        {
            let now = std::time::Instant::now();
        }
        match msg {
            ProtocolMsg::Sync => {
                self.on_sync_msg();
            }
            _ => unimplemented!("Handling of {:?}", msg),
        }
        Ok(())
    }
}