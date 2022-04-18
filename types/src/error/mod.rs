use crypto_lib::error::SigningError;
use reed_solomon_erasure::Error as RSError;
use openssl::error::ErrorStack;
use crate::{Epoch, Replica};

#[derive(Debug)]
pub enum Error {
    Signing(SigningError),
    ShardLeafError,
    ShardMerkleError,
    ShardAccumulatorTreeMismatch,
    ShardAccumulatorMismatch,
    ReedSolomon(RSError),
    BinaryCodec(bincode::Error),
    BuilderUnsetField(&'static str),
    CertificateHashMismatch,
    CertificateUnknownOrigin(Replica),
    CertificateTooManySigs,
    DERConversionError(ErrorStack),
    ParseInvalidMapLen(usize, usize),
    ParseIncorrectFaults(usize, usize),
    ParseInvalidMapEntry(usize),
    ParseInvalidPkSize(usize),
    ParseInvalidSkSize(usize),
    ParseUnimplemented(&'static str),
    Generic(String),
    EquivocationDetected(Epoch),
}

impl From<SigningError> for Error {
    fn from(serror: SigningError) -> Self {
        Self::Signing(serror)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::Generic(s)
    }
}

impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        Self::BinaryCodec(e)
    }
}

impl From<RSError> for Error {
    fn from(e: RSError) -> Error {
        Self::ReedSolomon(e)
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Self::DERConversionError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signing(serror) => write!(f, "Signing error: {}", serror)?,
            Self::ShardLeafError => write!(f, "The hash of the shard does not match the leaf hash in the witness")?,
            Self::ShardMerkleError => write!(f, "The merkle proof for the witness is invalid")?,
            Self::ShardAccumulatorTreeMismatch => write!(f, "Shard does not belong to the accumulator")?,
            Self::ShardAccumulatorMismatch => write!(f, "Shard Merkle tree does not match the root")?,
            Self::ReedSolomon(e) => write!(f, "Failed to reconstruct the shard with RS error: {}", e)?,
            Self::BinaryCodec(e) => write!(f, "Binary codec error: {}", e)?,
            Self::BuilderUnsetField(s) => write!(f, "Field {} is unset for the builder", s)?,
            Self::CertificateHashMismatch => write!(f, "Hash of the message is not the hash in the certificate")?,
            Self::CertificateUnknownOrigin(from) => write!(f, "Unknown signer {} for the certificate", from)?,
            Self::CertificateTooManySigs => write!(f, "Too many signatures in the certificate")?,
            Self::ParseIncorrectFaults(fault, n) => write!(f, "2*{} >= {}", *fault, *n)?,
            Self::ParseInvalidMapEntry(entry) => write!(f, "Invalid map entry: {}", entry)?,
            Self::ParseInvalidMapLen(exp, got) => write!(f, "Invalid map length - Expected {}, Got {}", exp, got)?,
            Self::ParseInvalidPkSize(s) => write!(f, "Invalid PK size - Got {}", s)?,
            Self::ParseInvalidSkSize(s) => write!(f, "Invalid SK size - Got {}", s)?,
            Self::ParseUnimplemented(unimp) => write!(f, "Unimplemented algorithm: {}", unimp)?,
            Self::DERConversionError(e) => write!(f, "DER Error: {}", e)?,
            Self::EquivocationDetected(e) => write!(f, "Equivocation detected in {}", e)?,
            Self::Generic(s) => write!(f, "Generic Error: {}", s)?,
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Self::Signing(..) => "Signing Error",
            Self::ShardLeafError => "Shard Leaf Error",
            Self::ShardMerkleError => "Shard Merkle Error",
            Self::ShardAccumulatorTreeMismatch => "Shard Accumulator Tree Mismatch",
            Self::ShardAccumulatorMismatch => "Shard Accumulator Mismatch",
            Self::ReedSolomon(..) => "Reed Solomon Error",
            Self::BinaryCodec(..) => "Binary Codec Error",
            Self::BuilderUnsetField(..) => "Builder Field Unset",
            Self::CertificateHashMismatch => "Certificate Hash Mismatch",
            Self::CertificateUnknownOrigin(..) => "Certificate Unknown Origin",
            Self::CertificateTooManySigs => "Certificate Too Many Sigs",
            Self::ParseIncorrectFaults(..) => "Parse Incorrect Faults",
            Self::ParseInvalidMapEntry(..) => "Parse Invalid Map Entry",
            Self::ParseInvalidMapLen(..) => "Parse Invalid Map Length",
            Self::ParseInvalidPkSize(..) => "Parse Invalid PK Size",
            Self::ParseInvalidSkSize(..) => "Parse Invalid SK Size",
            Self::ParseUnimplemented(..) => "Parse Unimplemented Algorithm",
            Self::DERConversionError(..) => "DER Error",
            Self::EquivocationDetected(..) => "Equivocation Error",
            Self::Generic(..) => "Generic Error",
        }
    }
}