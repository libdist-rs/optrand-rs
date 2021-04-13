use serde::{Serialize, Deserialize};
use crate::Vote;
/// A certificate contains several signatures on a message
/// A vote is a special case of certificate with one vote
/// A sync certificate is a certificate containing vote from n/2+1 nodes
/// A responsive certificate is a certificate containing votes from 3n/4 nodes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Certificate {
    pub msg: Vec<u8>,
    votes: Vec<Vote>,
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