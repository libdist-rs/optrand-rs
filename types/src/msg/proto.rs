use serde::{Deserialize, Serialize};
use crate::{AckMsg, CertType, Certificate, DataWithAcc, Epoch, Height, Proposal, Replica, ResponsiveCertMsg, ResponsiveVote, SignedShard, SyncCertMsg, SyncVote, Beacon, AggregatePVSS, DecompositionProof, Decryption, PVSSVec};
use types_upstream::WireReady;
use crypto::{hash::ser_and_hash};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMsg {
    /// Network level beacon message
    RawBeaconReady(Epoch, Beacon),
    /// Someone has already reconstructed this value
    BeaconReady(Epoch, Beacon),

    /// Used internally for networking
    RawStatus(Epoch, Height, CertType),
    /// Status message contains a certificate > 1 signatures
    Status(Epoch, Height, CertType),

   /// RawEpochPVSSSharing used internally on the wire
    RawEpochPVSSSharing(PVSSVec),
    /// EpochPVSSSharing is sent by nodes to the leader to prepare for the next round
    /// A valid EpochPVSSSharing message guarantees that 
    /// dleq.len() = pvssvec.enc.len() = pvssvec.comms.len() = pvssvec.proofs.len()
    EpochPVSSSharing(PVSSVec),

    RawPVSSSharingReady(Replica, AggregatePVSS, DecompositionProof),
    PVSSSharingReady(Replica, AggregatePVSS, DecompositionProof),

    /// Network-level propose message
    RawPropose(Epoch, Proposal, DataWithAcc, DecompositionProof),
    /// Semantically valid propose message
    /// 1. The block's hash is pre-populated
    /// 2. The hash in the certificate is of the parent block mentioned in the new block
    /// 3. The signature contains only 1 vote on the hash of the block
    Propose(Epoch, Proposal, DataWithAcc, DecompositionProof),
    /// Deliver Propose contains my shard and your shard instead of sending messages twice
    DeliverPropose(Epoch, Vec<u8>, SignedShard, Replica),

    /// Network-level propose message
    RawResponsiveVoteMsg(ResponsiveVote, Certificate),
    /// A Semantically valid responsive vote message
    /// There is only one vote in certificate and it is a hash
    ResponsiveVoteMsg(ResponsiveVote, Certificate),

    /// Network level responsive certificate
    RawResponsiveCert(ResponsiveCertMsg, DataWithAcc),
    /// Semantically valid responsive certificate
    ResponsiveCert(ResponsiveCertMsg, DataWithAcc),
    /// Deliver responsive certificate delivers (my shard, your shard) for the responsive certificate
    DeliverResponsiveCert(Epoch, Vec<u8>, SignedShard, Replica),

    /// Network level sync certificate
    RawSyncCert(SyncCertMsg, DataWithAcc),
    /// Semantically valid sync certificate
    SyncCert(SyncCertMsg, DataWithAcc),
    /// Deliver responsive certificate delivers (my shard, your shard) for the responsive certificate
    DeliverSyncCert(Epoch, Vec<u8>, SignedShard, Replica),

    /// Network level Sync Vote
    /// contains (Epoch, Certificate)
    RawSyncVoteMsg(SyncVote, Certificate),
    /// Semantically valid Sync Vote guarantees that there is only one vote in the certificate
    SyncVoteMsg(SyncVote, Certificate),
    
    /// Network level Ack Vote
    RawAck(AckMsg, Certificate),
    /// Semantically valid ack message guarantees that there is only vote in the certificate
    Ack(AckMsg, Certificate),
    DeliverAckCert(Epoch, Vec<u8>, Vec<u8>),

    /// Network level Beacon Share
    /// Contains the epoch for the share and the decryption itself
    RawBeaconShare(Epoch, Decryption),
    /// Semantically valid beacon share
    BeaconShare(Epoch, Decryption),

    /// Network level equivocation message
    RawEquivocation(Certificate, Certificate),
    /// Semantically valid equivocation message that is guaranteed to have different hashes
    Equivocation(Certificate, Certificate),

    // Parsing errors
    /// An invalid message
    InvalidMessage,
}

impl ProtocolMsg {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let c: ProtocolMsg =
            bincode::deserialize(&bytes).expect("failed to decode the protocol message");
        return c;
    }
}

impl WireReady for ProtocolMsg {
    fn init(self) -> Self {
        // log::info!("Transforming {:?}", self);
        match self {
            ProtocolMsg::RawStatus(ep, x, c) => {
                ProtocolMsg::Status(ep, x,c)
            },
            ProtocolMsg::RawEpochPVSSSharing( y) => {
                if y.encs.len() != y.comms.len() {
                    log::warn!("Invalid encs and comms length");
                    ProtocolMsg::InvalidMessage
                } else if y.encs.len() != y.proofs.len() {
                    log::warn!("Invalid encs and proofs length");
                    ProtocolMsg::InvalidMessage
                } else {
                    ProtocolMsg::EpochPVSSSharing(y)
                }
            }
            ProtocolMsg::RawPVSSSharingReady(e, agg, decomp) => 
            {
                if agg.encs.len() != agg.comms.len() {
                    ProtocolMsg::InvalidMessage
                } else if decomp.indices.len() != decomp.dleq_proof.len() || decomp.indices.len() != decomp.gs_vec.len() {
                    ProtocolMsg::InvalidMessage
                } else {
                    ProtocolMsg::PVSSSharingReady(e, agg, decomp)
                }
            }
            ProtocolMsg::RawBeaconReady(x,y) => 
                ProtocolMsg::BeaconReady(x,y),
            ProtocolMsg::RawPropose(e,p,z_pa, decomp) => {
                let p = p.init();
                log::debug!("Got a propose message");
                if p.new_block.aggregate_pvss.encs.len() != p.new_block.aggregate_pvss.comms.len() {
                    log::warn!("Rejecting propose beacuse pvss encs len != pvss comms len");
                    return ProtocolMsg::InvalidMessage;
                }
                ProtocolMsg::Propose(e, p,z_pa, decomp)
            }
            ProtocolMsg::RawResponsiveVoteMsg(resp_vote, vote) => {
                log::debug!("Got vote message");
                if vote.len() != 1 {
                    log::warn!("Rejecting a vote message invalid vote len");
                    return ProtocolMsg::InvalidMessage;
                }
                if vote.msg.len() != crypto::hash::HASH_SIZE {
                    log::warn!("Rejecting a vote message not hash len");
                    return ProtocolMsg::InvalidMessage;
                }
                if ser_and_hash(&resp_vote) != vote.msg[..] {
                    log::warn!("Rejecting a vote message hash of cert not in vote");
                    return ProtocolMsg::InvalidMessage;
                }
                ProtocolMsg::ResponsiveVoteMsg(resp_vote, vote)
            }
            ProtocolMsg::RawResponsiveCert(cert, ep) =>
                ProtocolMsg::ResponsiveCert(cert, ep),
            ProtocolMsg::RawSyncCert(cert, ep) =>
                ProtocolMsg::SyncCert(cert, ep),
            ProtocolMsg::RawSyncVoteMsg(sv,cert) => {
                if cert.len() != 1 {
                    ProtocolMsg::InvalidMessage
                } else {
                    ProtocolMsg::SyncVoteMsg(sv, cert)
                }
            }
            ProtocolMsg::RawAck(ep, cert) => {
                if cert.len() != 1 {
                    ProtocolMsg::InvalidMessage
                } else {
                    ProtocolMsg::Ack(ep, cert)
                }
            }
            ProtocolMsg::RawBeaconShare(ep, sh) => 
                ProtocolMsg::BeaconShare(ep, sh),
            ProtocolMsg::RawEquivocation(c1,c2) => 
                if c1.msg == c2.msg {
                    ProtocolMsg::InvalidMessage
                } else {
                    ProtocolMsg::Equivocation(c1, c2)
                }
            _ => self,
        }
    }

    fn from_bytes(data: &[u8]) -> Self {
        ProtocolMsg::from_bytes(data)
    }

    fn to_bytes(self: &Self) -> Vec<u8> {
        bincode::serialize(self).expect(format!("Failed to serialize {:?}", self).as_str())
    }
}

