use serde::{Deserialize, Serialize};
use crate::{Beacon, Epoch, Proof, Proposal};
use types_upstream::WireReady;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMsg {
    /// Network level beacon message (Epoch, Beacon)
    /// Sent when someone reconstructs the beacon for that epoch
    BeaconReady(Epoch, Beacon),

    /// Status Message consists of the highest ranked certificate and a PVSS tuple
    // Status(Certificate, PVSSVec),

    /// RawPropose contains the actual proposal with Accumulator information
    RawPropose(Proposal, Proof),
    Propose(Proposal, Proof),


    // Parsing errors
    /// An invalid message
    InvalidMessage,
}

impl WireReady for ProtocolMsg {
    fn init(self) -> Self {
        match self {
            ProtocolMsg::RawPropose(prop, proof) => {
                ProtocolMsg::Propose(prop.init(), proof.init())
            },
            ProtocolMsg::BeaconReady(..) => self,
            _ => todo!("Implement state transition for protocolmsg"),
        }
    }

    fn from_bytes(data: &[u8]) -> Self {
        let c: ProtocolMsg =
            bincode::deserialize(&data)
                .expect("failed to decode the protocol message");
        c
    }

    fn to_bytes(self: &Self) -> Vec<u8> {
        bincode::serialize(self).expect(format!("Failed to serialize {:?}", self).as_str())
    }
}

