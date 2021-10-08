use crypto::hash::{EMPTY_HASH, Hash};
use serde::{Serialize, Deserialize};
use crate::Epoch;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Type {
    Sync,
    Responsive,
}

impl std::default::Default for Type {
    fn default() -> Self {
        Type::Sync
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder, Default)]
pub struct Vote {
    epoch: Epoch,
    prop_hash: Hash,
    tp: Type,
}

impl Vote {
    pub const GENESIS: Self = Self {
        epoch: 0,
        prop_hash: EMPTY_HASH,
        tp: Type::Sync,
    };

    pub fn higher_than(&self, other: &Self) -> bool {
        self.epoch > other.epoch
    }

    pub const fn num_sigs(&self, num_nodes: usize) -> usize {
        match self.tp {
            Type::Sync => num_nodes/2 + 1,
            Type::Responsive => 3*num_nodes/4 + 1,
        }
    }

    pub fn proposal_hash(&self) -> &Hash {
        &self.prop_hash
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

