use std::sync::Arc;
use types::{Block, Certificate, Result, Vote};
use super::OptRandStateMachine;

impl OptRandStateMachine {

    /// Returns x*\Delta 
    /// Useful to compute 11Delta, 3 Delta, etc.
    pub(crate) fn x_delta(&self, times: u64) -> std::time::Duration {
        std::time::Duration::from_millis(self.config.delta * times)
    }

    pub fn highest_certificate(&self) -> &Certificate<Vote> {
        &self.highest_certificate.0
    }

    pub fn highest_certified_block(&self) -> Arc<Block> {
        self.highest_certificate.1.clone()
    }

    pub fn highest_certified_data(&self) -> &Vote {
        &self.highest_certificate.2
    }
    
    pub(crate) fn update_highest_cert(&mut self, v: Vote, c: Certificate<Vote>) -> Result<()> {
        let b = {
            let (p, _) = self.storage.prop_from_hash(v.proposal_hash()).ok_or(format!("Proposal not found when trying to update the highest certificate"))?;
            self.storage.get_delivered_block_by_hash(p.block().hash()).ok_or(format!("Block not found in storage when trying to update the highest certified block"))?
        };
        self.highest_certificate = (c, b, v);
        Ok(())
    }

}