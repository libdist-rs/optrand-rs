use crate::{Certificate, Codeword, MTAccumulator, Signature, Witness};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverData<T> {
    pub acc: MTAccumulator<T>,
    pub sign: Certificate<MTAccumulator<T>>,
    pub shard: Codeword<T>,
    pub wit: Witness<T>,
}