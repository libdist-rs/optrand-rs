use serde::{Serialize, Deserialize};
use crate::Replica;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Vote {
    /// The id of the signer of this block
    pub origin: Replica,
    /// The signature
    pub auth: Vec<u8>,
}