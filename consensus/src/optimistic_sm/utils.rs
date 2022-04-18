use std::time::Duration;
use super::OptRandStateMachine;

impl OptRandStateMachine {
    /// Returns x*\Delta 
    /// Useful to compute 11Delta, 3 Delta, etc.
    pub(crate) fn x_delta(&self, times: usize) -> Duration {
        Duration::from_millis(self.config.delta * (times as u64))
    }
}