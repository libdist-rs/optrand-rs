use serde::{Deserialize, Serialize};
use crate::*;
use types_upstream::WireReady;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProposalData {
    /// The block in the proposal
    pub epoch: Epoch,
    pub block: Block, 
    pub highest_cert_data: Vote,
    pub highest_cert: Certificate<Vote>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SyncCertData {
    pub vote: Vote,
    pub cert: Certificate<Vote>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct RespCertData {
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
    /// DeliverXXX contains a Reed-solomon share, and the ID of the replica whose share it is
    DeliverPropose(Replica, DeliverData<DirectProposal>),

    SyncVote(Vote, Certificate<Vote>),
    RespVote(Vote, Certificate<Vote>),

    SyncCert(SyncCertProposal, Proof<SyncCertProposal>),
    DeliverSyncCert(Replica, DeliverData<SyncCertProposal>),

    RespCert(RespCertProposal, Proof<RespCertProposal>),
    DeliverRespCert(Replica, DeliverData<RespCertProposal>),

    /// Beacon Share
    BeaconShare(Epoch, Decryption),
    /// Sent when a node reconstructs the beacon for that epoch
    BeaconReady(Epoch, Beacon),

    EquivocationProposal(EquivData<DirectProposal>),
    EquivocationSyncCert(EquivData<SyncCertProposal>),

    /// An `Ack` contains just the epoch number, hash of the block and the responsive certificate accumulator
    /// It should also contain the certificate with one sig on it
    Ack(AckData, Certificate<AckData>),

    // Parsing errors
    /// An invalid message
    InvalidMessage,

    /// Optimization
    /// Send ahead a PVSS Sharing
    AggregateReady(AggregatePVSS, DecompositionProof),

    /// Initial syncing message sent by the node 0 in lieu of clock synchronization
    Sync,

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
            ProtocolMsg::BeaconShare(..) => self,
            ProtocolMsg::RespVote(..) => self,
            ProtocolMsg::RespCert(..) => self,
            ProtocolMsg::DeliverRespCert(..) => self,
            ProtocolMsg::Ack(..) => self,
            ProtocolMsg::AggregateReady(..) => self,
            ProtocolMsg::Sync => self,
            _ => todo!("Implement state transition for protocolmsg: {:?}", self),
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

