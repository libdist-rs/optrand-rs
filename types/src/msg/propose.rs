use super::Block;
use crate::{Epoch, Certificate};
use types_upstream::WireReady;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proposal {
    /// The block in the proposal
    pub new_block: Block,
    pub highest_certificate: Certificate,
    pub epoch: Epoch,
}

impl Proposal {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let c: Proposal = bincode::deserialize(&bytes)
            .expect("failed to decode the propose");
        c
    }
}

impl WireReady for Proposal {
    /// init will update the hash of the block
    fn init(mut self) -> Self {
        self.new_block = self.new_block.init();
        self
    }

    fn from_bytes(data: &[u8]) -> Self {
        Proposal::from_bytes(data)
    }
}