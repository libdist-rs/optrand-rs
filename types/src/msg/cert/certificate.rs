use std::borrow::BorrowMut;

use crypto::{DSSPublicKey, DSSSecretKey, hash::{EMPTY_HASH, Hash, ser_and_hash}};
use fnv::FnvHashMap;
use serde::{Serialize, Deserialize};
use crate::{Replica, Signature, Storage, error::Error};

/// A certificate contains several signatures on a message
/// A vote is a special case of certificate with one vote
/// A sync certificate is a certificate containing vote from n/2+1 nodes
/// A responsive certificate is a certificate containing votes from 3n/4 nodes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Certificate<T> {
    hash: Hash,
    pub sigs: FnvHashMap<Replica, Signature<T>>,
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

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

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
    pub fn is_valid(&self, 
        msg: &T, 
        pks: &FnvHashMap<Replica, DSSPublicKey>
    ) -> Result<(), Error> {
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
    
    /// Buffered `is_valid` checks if the signature is on this message, and that every signature is valid while buffering the correct signatures
    pub fn buffered_is_valid(&self, 
        msg: &T, 
        pks: &FnvHashMap<Replica, DSSPublicKey>,
        storage: &mut Storage,
    ) -> Result<(), Error> {
        if self.hash != ser_and_hash(msg) {
            return Err(Error::CertificateHashMismatch);
        }
        if pks.len() < self.len() {
            return Err(Error::CertificateTooManySigs);
        }
        for (from, sig) in &self.sigs {
            if storage.is_already_verified(*from, &self.hash) {
                continue;
            }
            let pk = pks.get(from)
                .ok_or(Error::CertificateUnknownOrigin(*from))?;
            sig.is_valid_with_hash(&self.hash, pk)?;
            storage.add_verified_sig(*from, self.hash, sig.get_sig());
        }
        Ok(())
    }
}