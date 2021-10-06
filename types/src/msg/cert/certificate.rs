use crypto::{DSSPublicKey, DSSSecretKey, hash::{EMPTY_HASH, Hash, ser_and_hash}};
use fnv::FnvHashMap;
use serde::{Serialize, Deserialize};
use crate::{Replica, Signature, error::Error};

/// A certificate contains several signatures on a message
/// A vote is a special case of certificate with one vote
/// A sync certificate is a certificate containing vote from n/2+1 nodes
/// A responsive certificate is a certificate containing votes from 3n/4 nodes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Certificate<T> {
    hash: Hash,
    sigs: FnvHashMap<Replica, Signature<T>>,
}

impl<T> std::default::Default for Certificate<T> {
    fn default() -> Self {
        Self {
            hash: EMPTY_HASH, 
            sigs: FnvHashMap::default(),
        }
    }
}

impl<T> Certificate<T> 
where T: Serialize,
{
    /// Converts a signature into a certificate
    pub fn from_signature_and_msg_hash(
        id: Replica, 
        h: Hash, 
        sig: Signature<T>
    ) -> Self {
        let mut cert = Self {
            hash: h,
            sigs: FnvHashMap::default(),
        };
        cert.sigs.insert(id, sig);
        cert
    }

    pub fn new_cert(msg: &T, myid: Replica, sk: &DSSSecretKey) -> Result<Self, Error> {
        let mut cert = Self {
            hash: ser_and_hash(msg),
            sigs: FnvHashMap::default(),
        };
        let sig = Signature::new_signature_from_hash(&cert.hash, sk)?;
        cert.sigs.insert(myid, sig);
        Ok(cert) 
    }

    /// Adds a signature to the certificate
    pub fn add_signature(&mut self, from: Replica, v: Signature<T>) {
        self.sigs.insert(from, v);
    }

    /// The number of votes in the certificate
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    /// Check whether this is a vote, i.e., there is only one signature in this certificate
    pub fn is_vote(&self) -> bool {
        self.sigs.len() == 1
    }

    /// `is_valid` checks if:
    /// 1. The certificate is for this message
    /// 2. Every vote is vaild against this message
    pub fn is_valid(&self, msg: &T, pks: &FnvHashMap<Replica, DSSPublicKey>) -> Result<(), Error> {
        if self.hash != ser_and_hash(msg) {
            return Err(Error::CertificateHashMismatch);
        }
        if pks.len() < self.len() {
            return Err(Error::CertificateTooManySigs);
        }
        for (from, sig) in &self.sigs {
            let pk = pks.get(from)
                .ok_or(Error::CertificateUnknownOrigin(*from))?;
            sig.is_valid_with_hash(&self.hash, pk)?;
        }
        Ok(())
    }
}