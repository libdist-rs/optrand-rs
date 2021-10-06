use super::Block;
use crate::{Certificate, Codeword, Epoch, MTAccumulator, Witness};
use types_upstream::WireReady;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(Builder)]
pub struct Proposal {
    /// The block in the proposal
    epoch: Epoch,
    block: Block, 
    highest_cert: Certificate<Proposal>,

    #[serde(skip)]
    codewords: Option<Vec<Codeword<Proposal>>>,
    #[serde(skip)]
    witnesses: Option<Vec<Witness<Proposal>>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Proof {
    /// The accumulator for the proposal
    acc: MTAccumulator<Proposal>,
    /// A signature on the accumulator
    sign: Certificate<MTAccumulator<Proposal>>,
}

impl WireReady for Proposal {
    fn from_bytes(data: &[u8]) -> Self {
        bincode::deserialize(data).expect("failed to deserialize proposal")
    }

    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize proposal")
    }

    fn init(mut self) -> Self {
        self.block = self.block.init();
        self
    }
}

impl WireReady for Proof {
    fn from_bytes(data: &[u8]) -> Self {
        bincode::deserialize(data).expect("failed to deserialize proposal")
    }

    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize proposal")
    }

    fn init(self) -> Self {
        self
    }
}

impl Proposal {
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}