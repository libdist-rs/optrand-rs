use serde::{Serialize, Deserialize};
use types_upstream::WireReady;
use crate::{Epoch, Vote};
use crypto::hash::Hash;

/// A certificate contains several signatures on a message
/// A vote is a special case of certificate with one vote
/// A sync certificate is a certificate containing vote from n/2+1 nodes
/// A responsive certificate is a certificate containing votes from 3n/4 nodes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Certificate {
    pub msg: Vec<u8>,
    pub votes: Vec<Vote>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ResponsiveVote {
    pub epoch: Epoch, 
    pub block_hash: Hash,
}

pub type SyncVote = ResponsiveVote;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResponsiveCertMsg {
    pub resp_vote: ResponsiveVote,
    pub cert: Certificate,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SyncCertMsg {
    pub sync_vote: SyncVote, 
    pub cert: Certificate,
}

/// Used in creating proposals and checking
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CertType{
    Resp(ResponsiveCertMsg),
    Sync(SyncCertMsg),
}

impl Certificate {
    pub const fn empty_cert() -> Self {
        Certificate { msg:Vec::new(),votes: Vec::new() }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let c: Certificate = bincode::deserialize(&bytes).expect("failed to decode the propose");
        c
    }

    /// Adds a vote to the certificate
    pub fn add_vote(&mut self, v: Vote) {
        self.votes.push(v);
    }

    /// len() returns the number of votes in this certificate
    pub fn len(&self) -> usize {
        self.votes.len()
    }
}

impl std::default::Default for Certificate {
    fn default() -> Self {
        Certificate::empty_cert()
    }
}

impl WireReady for ResponsiveCertMsg {
    fn init(self) -> Self {
        self
    }

    fn from_bytes(data: &[u8]) -> Self {
        let c:ResponsiveCertMsg = bincode::deserialize(&data).expect("failed to decode the responsive certificate");
        c
    }
}

impl WireReady for SyncCertMsg {
    fn init(self) -> Self {
        self
    }

    fn from_bytes(data: &[u8]) -> Self {
        let c:SyncCertMsg = bincode::deserialize(&data).expect("failed to decode the responsive certificate");
        c
    }
}