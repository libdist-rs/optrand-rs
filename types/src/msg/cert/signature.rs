use std::marker::PhantomData;
use crypto::{DSSPublicKey, DSSSecretKey, hash::{Hash, ser_and_hash}};
use serde::{Serialize, Deserialize};

use crate::error::Error;


/// A signature on type T is actually a signature on the hash of T along with information about the origin
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signature<T> {
    sig: Vec<u8>,
    _x: PhantomData<T>,
}

impl<T> Signature<T> 
where T:Serialize,
{
    pub fn get_sig(&self) -> Vec<u8> {
        self.sig.clone()
    }

    pub fn is_valid(&self, data: &T, pk: &DSSPublicKey) -> Result<(), String> {
        let hash = ser_and_hash(data);
        self.is_valid_with_hash(&hash, pk)
    }

    pub fn is_valid_with_hash(&self, hash: &Hash, pk: &DSSPublicKey) -> Result<(), String> {
        if !pk.verify(hash, &self.sig) {
            return Err("Signature check failed".to_string());
        }
        Ok(())
    }

    pub fn new_signature_from_hash(hash: &Hash, sk: &DSSSecretKey) -> Result<Self, Error> {
        Ok(Self {
            sig: sk.sign(hash)?,
            _x: PhantomData,
        })
    }

    pub fn new_signature(msg: &T, sk: &DSSSecretKey) -> Result<Self, Error> {
        let h = ser_and_hash(msg);
        Self::new_signature_from_hash(&h, sk)
    }
}

pub struct SignatureBuilder<T> {
    signing_key: DSSSecretKey,
    _x: PhantomData<T>,
}

impl<T> SignatureBuilder<T> 
where T: Serialize,
{
    pub fn new(sk: DSSSecretKey) -> Self {
        Self {
            signing_key: sk,
            _x: PhantomData,
        }
    }

    pub fn new_sig(&self, data: &T) -> Result<Signature<T>, Error> {
        let hash = ser_and_hash(data);
        self.new_sig_with_hash(&hash)
    }

    pub fn new_sig_with_hash(&self, hash: &Hash) -> Result<Signature<T>, Error> {
        let sig = Signature {
            sig: self.signing_key
                .sign(hash)?,
            _x: PhantomData,
        };
        Ok(sig)
    }
}