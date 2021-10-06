use std::sync::Arc;
use config::Node;
use tokio_util::time::DelayQueue;
use types::Result;
use crypto::DSSSecretKey;

use types::{Beacon, Certificate, Epoch, MTAccumulator, Proof, Proposal, ProtocolMsg, Replica, START_EPOCH, SignatureBuilder, error::Error};

use crate::{EventQueue, events::{Event, TimeOutEvent}};

/// Builds all the messages for the protocol
pub struct OptRandStateMachine {
    pub(crate) config: Node,
    pub(crate) epoch: Epoch,
    pub(crate) prop_sig_builder: SignatureBuilder<MTAccumulator<Proposal>>,
    pub(crate) latest_beacon: Option<Beacon>,
    pub(crate) highest_certificate: Certificate<Proposal>,
}

impl OptRandStateMachine {
    pub fn new(config: Node) -> Self {
        let sk = config.get_secret_key();
        Self {
            config,
            epoch: START_EPOCH,
            prop_sig_builder: SignatureBuilder::new(sk),
            latest_beacon: None,
            highest_certificate: Certificate::default(),
        }
    }

}
