mod proto;
pub use proto::*;

mod block;
pub use block::*;

mod cert;
pub use cert::*;

mod vote;
pub use vote::*;

mod generic;
pub use generic::*;

mod storage;
pub use storage::*;

mod propose;
pub use propose::*;

mod ack;
pub use ack::*;

use crate::Epoch;

impl ProtocolMsg {
    /// Get epoch returns the epoch in which the message must be processed
    /// 0 means that the message must be processed immediately
    pub fn get_epoch(&self) -> Epoch {
        match self {
            // ProtocolMsg::RawBeaconReady(ref x,_) => *x,
            ProtocolMsg::BeaconReady(ref x, _) => *x,
            // ProtocolMsg::RawStatus(ref x,_,_) => *x,
            ProtocolMsg::Status(ref x,_,_) => *x,
            // ProtocolMsg::RawEpochPVSSSharing(_) => 0,
            ProtocolMsg::EpochPVSSSharing(_) => 0,
            // ProtocolMsg::RawPVSSSharingReady(_,_,_)=>0,
            ProtocolMsg::PVSSSharingReady(_,_,_)=>0,
            // ProtocolMsg::RawPropose(ref x,_,_,_) => *x,
            ProtocolMsg::Propose(ref x,_,_,_) => *x,
            ProtocolMsg::DeliverPropose(ref x, _,_,_) => *x,
            ProtocolMsg::ResponsiveVoteMsg(ref x,_)=> x.epoch,
            ProtocolMsg::DeliverResponsiveCert(ref x,_,_,_) => *x,
            ProtocolMsg::SyncCert(ref x,_)=> x.sync_vote.epoch,
            ProtocolMsg::Ack(ref x, _)=> x.epoch,
            ProtocolMsg::DeliverAckCert(ref x,_,_)=> *x,
            ProtocolMsg::BeaconShare(ref x,_) => *x,
            _ => 0,
        }
    }
}