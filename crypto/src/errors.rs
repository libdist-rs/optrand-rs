#[derive(Debug,PartialEq)]
pub enum DbsError {
    // Dleq Checks
    InvalidChallenge,
    InvalidSignature,
    LeftCheckFailed,
    RightCheckFailed,
    LengthCheckFailed,

    // Single PVSS verification
    CodingCheckFailed,
    DlogProofCheckFailed(usize),
    InvalidGs,
    SingleDleqProofCheckFailed,

    // Pverify checks
    PairingCheckFailed(usize),
    
    // Decomposition verification checks
    CommitmentNotDecomposing,
    EncryptionNotDecomposing,
}