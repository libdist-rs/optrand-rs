use serde::{Deserialize, Serialize};
use crate::{Beacon, BeaconShare, Block, Certificate, DeliverData, DirectProposal, Epoch, EquivData, PVSSVec, Proof, Proposal, Replica, SyncCertProposal, Vote};
use types_upstream::WireReady;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalData {
    /// The block in the proposal
    pub epoch: Epoch,
    pub block: Block, 
    pub highest_cert_data: Vote,
    pub highest_cert: Certificate<Vote>,
}

impl std::default::Default for ProposalData {
    fn default() -> Self {
        Self {
            block: Block::genesis(),
            ..Default::default()
        }
    }
}
 
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SyncCertData {
    pub vote: Vote,
    pub cert: Certificate<Vote>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMsg {
    /// Status Message consists of the highest ranked certificate and a PVSS tuple
    Status(Vote, Certificate<Vote>, PVSSVec),

    /// RawPropose contains the actual proposal with Accumulator information
    RawPropose(DirectProposal, Proof<DirectProposal>),
    Propose(DirectProposal, Proof<DirectProposal>),
    DeliverPropose(Replica, DeliverData<DirectProposal>),

    SyncVote(Vote, Certificate<Vote>),

    SyncCert(SyncCertProposal, Proof<SyncCertProposal>),
    DeliverSyncCert(Replica, DeliverData<SyncCertProposal>),

    /// Beacon Share
    BeaconShare(Epoch, BeaconShare),
    /// Sent when a node reconstructs the beacon for that epoch
    BeaconReady(Epoch, Beacon),

    EquivocationProposal(EquivData<DirectProposal>),
    EquivocationSyncCert(EquivData<SyncCertProposal>),

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
            ProtocolMsg::Status(..) | 
            ProtocolMsg::BeaconReady(..) | 
            ProtocolMsg::DeliverPropose(..) => self,
            ProtocolMsg::SyncVote(.., c) if !c.is_vote() => ProtocolMsg::InvalidMessage,
            ProtocolMsg::SyncVote(..) => self,
            ProtocolMsg::SyncCert(..) => self,
            ProtocolMsg::DeliverSyncCert(..) => self,
            _ => todo!("Implement state transition for protocolmsg :{:?}", self),
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

