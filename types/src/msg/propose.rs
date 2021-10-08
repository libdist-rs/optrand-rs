use super::{Block, accumulator};
use crate::{Certificate, Codeword, DbsContext, DirectProposal, Epoch, MTAccumulator, MTAccumulatorBuilder, ProposalData, Replica, Storage, SyncCertData, SyncCertProposal, Vote, Witness, error::Error};
use crypto::{DSSPublicKey, hash::{Hash, ser_and_hash}};
use fnv::FnvHashMap;
use types_upstream::WireReady;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(Builder)]
pub struct Proposal<T> {
    pub data: T,

    #[serde(skip)]
    codewords: Option<Vec<Codeword<Proposal<T>>>>,
    #[serde(skip)]
    witnesses: Option<Vec<Witness<Proposal<T>>>>,
    #[serde(skip)]
    #[builder(setter(skip))]
    hash: Hash,
}

#[derive(Debug, Serialize, Deserialize, Clone, Builder)]
pub struct Proof<T> {
    /// The accumulator for the proposal
    acc: MTAccumulator<T>,
    /// A signature on the accumulator
    sign: Certificate<(Epoch, MTAccumulator<T>)>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Builder)]
pub struct EquivData<T> {
    /// The accumulator
    acc: [MTAccumulator<T>; 2],
    /// The first signature
    sign: [Certificate<(Epoch, MTAccumulator<T>)>; 2],
    /// The data on which the equivocation was detected
    epoch: Epoch,
}

impl<T> EquivData<T> {
    pub const NUM_EQUIV: usize = 2;
}

impl<T> Proof<T> {
    pub fn acc(&self) -> &MTAccumulator<T> {
        &self.acc
    }

    pub fn sign(&self) -> &Certificate<(Epoch, MTAccumulator<T>)> {
        &self.sign
    }

    pub fn unpack(self) -> (MTAccumulator<T>, Certificate<(Epoch, MTAccumulator<T>)>) {
        (self.acc, self.sign)
    }
}

impl WireReady for DirectProposal {
    fn init(mut self) -> Self {
        self.data.block = self.data.block.init();
        self.hash = ser_and_hash(&self);
        self
    }

    fn from_bytes(data: &[u8]) -> Self {
        bincode::deserialize(data).expect("failed to deserialize proposal")
    }

    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize proposal")
    }
}

impl WireReady for Proposal<SyncCertData> {
    fn init(self) -> Self {
        self
    }

    fn from_bytes(data: &[u8]) -> Self {
        bincode::deserialize(data).expect("failed to deserialize proposal")
    }

    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize proposal")
    }
}

impl<T> WireReady for Proof<T> 
where T:Clone + Send + Sync + DeserializeOwned + Serialize,
{
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

impl DirectProposal {
    pub fn epoch(&self) -> Epoch {
        self.data.epoch
    }

    pub fn block(&self) -> &Block {
        &self.data.block
    }

    pub fn highest_cert(&self) -> &Certificate<Vote> {
        &self.data.highest_cert
    }

    pub fn vote(&self) -> &Vote {
        &self.data.highest_cert_data
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// Check whether 
    /// 1. The block in the proposal is valid
    /// 2. 
    pub fn is_valid(&self, 
        from: Replica,
        e: Epoch,
        proof: &Proof<DirectProposal>,
        storage: &mut Storage,
        pvss_ctx: &DbsContext,
        prop_acc_builder: &MTAccumulatorBuilder<Self>,
        pk_map: &FnvHashMap<Replica, DSSPublicKey>,
    ) -> Result<(), Error> {
        // Is the block valid on its own?
        self.block()
            .is_valid(&storage, 
                pvss_ctx, 
                &pk_map,
            )?; 

        // Is the accumulator valid?
        prop_acc_builder.check(self, &proof.acc)?;
        
        // Is the accumulator signed correctly?
        if !proof.sign.is_vote() {
            return Err(Error::Generic("Invalid # Sigs in the proposal proof".to_string()));
        }
        if !proof.sign.sigs.contains_key(&from) {
            return Err(Error::Generic(format!("Accumulator in the proposal is not signed by the leader")));
        }
        proof.sign.is_valid(&(e,proof.acc.clone()), pk_map)
    }
}

impl SyncCertProposal {
    /// Check whether 
    /// 1. The block in the proposal is valid
    /// 2. 
    pub fn is_valid(&self, 
        from: Replica,
        e: Epoch,
        proof: &Proof<Self>,
        storage: &mut Storage,
        sync_cert_acc_builder: &MTAccumulatorBuilder<Self>,
        pk_map: &FnvHashMap<Replica, DSSPublicKey>,
    ) -> Result<(), Error> {
        // Are all the signatures valid
        self.data.cert.buffered_is_valid(&self.data.vote, pk_map, storage)?;

        // Is the accumulator valid?
        sync_cert_acc_builder.check(self, &proof.acc)?;
        
        // Is the accumulator signed correctly?
        if !proof.sign.is_vote() {
            return Err(Error::Generic("Invalid # Sigs in the proposal proof".to_string()));
        }
        if !proof.sign.sigs.contains_key(&from) {
            return Err(Error::Generic(format!("Accumulator in the proposal is not signed by the leader")));
        }
        proof.sign.is_valid(&(e,proof.acc.clone()), pk_map)
    }
    
    pub fn epoch(&self) -> Epoch {
        self.data.vote.epoch()
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }
}

impl<T> Proposal<T> 
where T:Serialize + Clone
{

    pub fn get_codewords(&mut self, prop_acc_builder: &MTAccumulatorBuilder<Self>) -> Result<Vec<Codeword<Self>>, Error> {
        if let None = self.codewords {
            let bytes = bincode::serialize(self)?;
            let n = prop_acc_builder.n.ok_or(Error::BuilderUnsetField("n"))?;
            let f = prop_acc_builder.f.ok_or(Error::BuilderUnsetField("f"))?;
            self.codewords = Some(accumulator::generate_codewords(&bytes, n, f)?);
        }
        Ok(
            self.codewords
                .as_ref()
                .ok_or(
                    format!("Expected codewords to be cached")
                )?
                .clone()
        )
    }

    pub fn get_witnesses(&mut self, prop_acc_builder: &MTAccumulatorBuilder<Self>) -> Result<Vec<Witness<Self>>, Error> {
        if let None = self.codewords {
            let bytes = bincode::serialize(self)?;
            let n = prop_acc_builder.n.ok_or(Error::BuilderUnsetField("n"))?;
            let f = prop_acc_builder.f.ok_or(Error::BuilderUnsetField("f"))?;
            self.codewords = Some(accumulator::generate_codewords(&bytes, n, f)?);
        }
        if let None = self.witnesses {
            let tree = MTAccumulatorBuilder::get_tree_from_codewords(
                self.codewords.as_ref()
                .ok_or(
                    "We just cached codewords, so this is unreachable".to_string()
                )?
            )?;
            self.witnesses = Some(prop_acc_builder.get_all_witness(&tree)?);
        }
        Ok(self.witnesses.as_ref().clone().ok_or("Expected witnesses to be cached".to_string())?.clone())
    }
}