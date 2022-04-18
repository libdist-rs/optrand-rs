use std::sync::Arc;
use types::{Result, ProtocolMsg};
use super::OptRandStateMachine;

impl OptRandStateMachine {
    pub(crate) fn on_sync_msg(&self) -> Result<()>
    {
        todo!();
    }

    pub(crate) fn start_sync(&mut self) 
    {
        // id 0 is reponsible for synchronizing all the nodes
        if self.config.id != 0 {
            return;
        }

        self
            .ev_queue
            .send_msg(
                self.config.num_nodes, 
                ProtocolMsg::Sync
            );
    }
}