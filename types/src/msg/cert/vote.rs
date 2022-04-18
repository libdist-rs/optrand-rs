use crypto::hash::{EMPTY_HASH, Hash};
use serde::{Serialize, Deserialize};
use crate::{Epoch, resp_threshold, sync_threshold};


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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
            Type::Sync => sync_threshold(num_nodes),
            Type::Responsive => resp_threshold(num_nodes),
        }
    }

    pub fn proposal_hash(&self) -> &Hash {
        &self.prop_hash
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn vote_type(&self) -> &Type {
        &self.tp
    }
}

