use serde::{Deserialize, Serialize};
use crate::{Proposal, Epoch, Height, Certificate};
use types_upstream::{WireReady};
use crypto::{Beacon, Decryption, PVSSVec};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtocolMsg {
    /// Network level beacon message
    RawBeaconReady(Epoch, Beacon),
    /// Someone has already reconstructed this value
    BeaconReady(Epoch, Beacon),

    /// Used internally for networking
    RawStatus(Epoch, Height, Certificate),
    /// Status message contains a certificate > 1 signatures
    Status(Epoch, Height, Certificate),

    /// RawEpochPVSSSharing used internally on the wire
    RawEpochPVSSSharing(Epoch, PVSSVec),
    /// A valid EpochPVSSSharing message guarantees that 
    /// dleq.len() = pvssvec.enc.len() = pvssvec.comms.len() = pvssvec.proofs.len()
    EpochPVSSSharing(Epoch, PVSSVec),

    /// Network-level propose message
    RawPropose(Proposal, Certificate),
    /// Semantically valid propose message
    /// 1. The block's hash is pre-populated
    /// 2. The hash in the certificate is of the parent block mentioned in the new block
    /// 3. The signature contains only 1 vote on the hash of the block
    Propose(Proposal, Certificate),

    /// Network-level propose message
    RawResponsiveVote(Epoch, Certificate),
    /// A Semantically valid responsive vote message
    /// There is only one vote in certificate and it is a hash
    ResponsiveVote(Epoch, Certificate),

    /// Network level responsive certificate
    RawResponsiveCert(Certificate, Epoch),
    /// Semantically valid responsive certificate
    ResponsiveCert(Certificate, Epoch),

    /// Network level Sync Vote
    /// contains (Epoch, Certificate)
    RawSyncVote(Epoch, Certificate),
    /// Semantically valid Sync Vote guarantees that there is only one vote in the certificate
    SyncVote(Epoch, Certificate),
    
    /// Network level Ack Vote
    RawAck(Epoch, Certificate),
    /// Semantically valid ack message guarantees that there is only vote in the certificate
    Ack(Epoch, Certificate),

    /// Network level Beacon Share
    RawBeaconShare(Epoch, Decryption),
    /// Semantically valid beacon share
    BeaconShare(Epoch, Decryption),

    /// Network level equivocation message
    RawEquivocation(Certificate, Certificate),
    /// Semantically valid equivocation message that is guaranteed to have different hashes
    Equivocation(Certificate, Certificate),

    /// An invalid message
    InvalidMessage,
}

impl ProtocolMsg {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let c: ProtocolMsg =
            bincode::deserialize(&bytes).expect("failed to decode the protocol message");
        return c.init();
    }
}

impl WireReady for ProtocolMsg {
    fn init(self) -> Self {
        match self {
            ProtocolMsg::RawStatus(t, x, c) => {
                if c.len() > 1 {
                    ProtocolMsg::Status(t,x,c)
                } else {
                    ProtocolMsg::InvalidMessage
                }
            },
            ProtocolMsg::RawEpochPVSSSharing( x, y) => {
                if y.encs.len() != y.comms.len() {
                    ProtocolMsg::InvalidMessage
                } else if y.encs.len() != y.proofs.len() {
                    ProtocolMsg::InvalidMessage
                } else {
                    ProtocolMsg::EpochPVSSSharing(x,y)
                }
            }
            ProtocolMsg::RawBeaconReady(x,y) => 
                ProtocolMsg::BeaconReady(x,y),
            ProtocolMsg::RawPropose(p,c) => {
                let p = p.init();
                if p.highest_certificate.msg != p.new_block.parent_hash {
                    return ProtocolMsg::InvalidMessage;
                }
                if p.new_block.hash != c.msg[..] {
                    return ProtocolMsg::InvalidMessage;
                }
                ProtocolMsg::Propose(p,c)
            }
            ProtocolMsg::RawResponsiveVote(epoch, vote) => {
                if vote.len() != 1 {
                    return ProtocolMsg::InvalidMessage;
                }
                if vote.msg.len() != crypto::hash::HASH_SIZE {
                    return ProtocolMsg::InvalidMessage;
                }
                ProtocolMsg::ResponsiveVote(epoch, vote)
            }
            ProtocolMsg::RawResponsiveCert(cert, ep) =>
                ProtocolMsg::ResponsiveCert(cert, ep),
            ProtocolMsg::RawSyncVote(ep,cert) => {
                if cert.len() != 1 {
                    ProtocolMsg::InvalidMessage
                } else {
                    ProtocolMsg::SyncVote(ep, cert)
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
            _ => ProtocolMsg::InvalidMessage,
        }
    }

    fn from_bytes(data: &[u8]) -> Self {
        ProtocolMsg::from_bytes(data)
    }
}
