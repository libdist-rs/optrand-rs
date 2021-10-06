use types::Epoch;

use crate::OptRandStateMachine;

impl OptRandStateMachine {
    /// Update the epoch
    pub fn set_epoch(&mut self, e: Epoch) {
        debug_assert!(e>= self.epoch, "Downgrading epoch");
        self.epoch = e;
    } 

    pub fn is_leader(&self) -> bool {
        self.config.id == self.epoch % self.config.num_nodes
    }
}