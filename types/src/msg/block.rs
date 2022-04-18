use crypto::{DSSPublicKey, hash::{Hash, EMPTY_HASH}};
use fnv::FnvHashMap;
use serde::{Deserialize, Serialize};
use crate::{AggregatePVSS, DbsContext, DecompositionProof, Height, Replica, Storage, error::Error};

#[derive(Serialize, Deserialize, Clone, Builder)]
#[builder(build_fn(skip))]
pub struct Block {
    parent_hash: Hash,
    proposer: Replica,
    height: Height,
    
    aggregate_pvss: AggregatePVSS,
    aggregate_proof: DecompositionProof,

    /// The hash of the block, do not serialize, init will update it automatically
    #[serde(skip)]
    hash: Hash,
}

impl Default for Block {
    fn default() -> Self {
        Block::genesis()
    }
}

impl Block {
    pub const GENESIS_BLOCK: Block = Block {
        hash: EMPTY_HASH,
        height: 0,
        proposer:0,
        parent_hash: EMPTY_HASH,
        aggregate_pvss: AggregatePVSS{
            comms: vec![],
            encs: vec![],
        },
        aggregate_proof: DecompositionProof{
            dleq_proof: vec![],
            gs_vec: vec![],
            indices: vec![],
        },
    };

    pub fn genesis() -> Self {
        Self::GENESIS_BLOCK
    }

    /// Compute the hash of the block, it does not set the block hash
    pub fn compute_hash(&self) -> Hash {
        crypto::hash::ser_and_hash(self)
    }

    /// This will check for:
    /// 1. A valid parent in the storage
    /// 2. The height is correct
    /// 3. The aggregate pvss is correct
    /// 4. The decomposition proof is correct
    pub fn is_valid(&self, 
        storage: &Storage, 
        _dbs_ctx: &DbsContext, 
        _pk_map: &FnvHashMap<Replica, DSSPublicKey>
    ) -> Result<(), String> 
    {
        let parent = storage.get_delivered_block_by_hash(&self.parent_hash);
        if parent.is_none() {
            return Err("Unknown parent".to_string());
        }
        let parent = parent.unwrap();
        if parent.height + 1 != self.height {
            return Err("Invalid Height".to_string());
        }
        // We will do this in the optimization
        // if let Some(err) = dbs_ctx.pverify(&self.aggregate_pvss) {
        //     return Err(format!("Pverify failed with {:?}", err));
        // }

        // if let Some(err) = dbs_ctx.decomp_verify(
        //     &self.aggregate_pvss, &self.aggregate_proof, pk_map) {
        //     return Err(format!("Knowledge check failed with {:?}", err));
        // }
        Ok(())
    }

    pub fn pvss(&self) -> &AggregatePVSS {
        &self.aggregate_pvss
    } 

    pub fn proof(&self) -> &DecompositionProof {
        &self.aggregate_proof
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn height(&self) -> Height {
        self.height
    }

    pub fn proposer(&self) -> &Replica {
        &self.proposer
    }
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Block")
         .field("Height", &self.height)
         .field("Parent Hash", &self.parent_hash)
         .field("Knowledge contributions",&self.aggregate_proof.indices)
         .finish()
    }
}


impl types_upstream::WireReady for Block {
    /// After receiving a block from the network update the hash first
    fn init(mut self) -> Self {
        self.hash = self.compute_hash();
        self
    }

    fn from_bytes(data: &[u8]) -> Self {
        let c: Block = bincode::deserialize(data)
            .expect("failed to decode the block");
        return c.init();
    }

    fn to_bytes(self: &Self) -> Vec<u8> {
        bincode::serialize(self).expect(format!("Failed to serialize {:?}", self).as_str())
    }
}

impl BlockBuilder {
    pub fn build(&self) -> Result<Block, Error> {
        let mut block = Block {
            aggregate_proof: Clone::clone(self.aggregate_proof
                .as_ref()
                .ok_or(Error::BuilderUnsetField("aggregate proof"))?),
            parent_hash: Clone::clone(self.parent_hash
                .as_ref()
                .ok_or(Error::BuilderUnsetField("parent_hash"))?),
            aggregate_pvss: Clone::clone(self.aggregate_pvss
                .as_ref()
                .ok_or(Error::BuilderUnsetField("aggregate pvss"))?),
            height: Clone::clone(self.height
                .as_ref()
                .ok_or(Error::BuilderUnsetField("height"))?),
            proposer: Clone::clone(self.proposer
                .as_ref()
                .ok_or(Error::BuilderUnsetField("Proposer"))?),
            hash: EMPTY_HASH,
        };
        block.hash = block.compute_hash();
        Ok(block)
    }
}