use serde::{Serialize, Deserialize};
use types_upstream::WireReady;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ReconfigurationMsg {
    Inquire,
    InquireResponse,
    Join,
    AcceptCert,
}

impl WireReady for ReconfigurationMsg {
    fn init(self) -> Self {
        self
    }

    fn from_bytes(data: &[u8]) -> Self {
        let c: Self =
            bincode::deserialize(&data)
                .expect("failed to decode the protocol message");
        c
    }

    fn to_bytes(self: &Self) -> Vec<u8> {
        bincode::serialize(self).expect(format!("Failed to serialize {:?}", self).as_str())
    }
}