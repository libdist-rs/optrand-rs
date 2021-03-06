use crate::{context::Context, events::Event};
use std::sync::Arc;
use crypto::hash::ser_and_hash;
use tokio_util::time::DelayQueue;
use types::{AckMsg, Certificate, ProtocolMsg, Vote};

impl Context {
    /// do ack; Send ack to all the nodes
    pub fn do_ack(&mut self, ack: AckMsg, dq:&mut DelayQueue<Event>) {
        if ack.epoch != self.epoch {
            log::debug!("Stale ack received");
            return;
        }
        let mut cert = Certificate::empty_cert();
        let hash = ser_and_hash(&ack).to_vec();
        cert.add_vote(Vote{ 
            auth: self.my_secret_key.sign(&hash).unwrap(),
            origin: self.id(),
        });
        cert.msg = hash;
        self.net_send.send((self.num_nodes(), 
            Arc::new(ProtocolMsg::Ack(ack.clone(), cert.clone())),
        )).unwrap();
        self.on_recv_ack(ack, cert, dq);
    }

    /// What to do on receiving an ack from outside
    pub fn on_recv_ack(&mut self, ack: AckMsg, vote: Certificate, dq: &mut DelayQueue<Event>) {
        log::debug!("Got an ack message for epoch {}",ack.epoch);
        let hash = ser_and_hash(&ack);
        // Check if this is a valid ack vote
        if self.id() != vote.votes[0].origin && !self.pub_key_map[&vote.votes[0].origin].verify(&hash, &vote.votes[0].auth) {
            log::warn!("Invalid ack message {:?} received from {:?}", ack, vote);
        }
        // Is this the first ack message
        if self.ack_msg.is_none() {
            self.ack_msg = Some(ack.clone());
        }
        // Add this vote to the list of ack votes
        self.ack_votes.add_vote(vote.votes[0].clone());

        // Do we have enough votes to trigger the next step?
        if self.ack_votes.votes.len() < self.optimistic() {
            return;
        }
        // We may received 3/4 acks without doing acks ourselves
        self.do_responsive_commit(ack.block_hash,dq);

    }
}