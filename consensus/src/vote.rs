use crypto::hash::{Hash, ser_and_hash};
use tokio_util::time::DelayQueue;
use types::{Certificate, Proposal, ResponsiveVote, Vote, ProtocolMsg, SyncVote, ResponsiveCertMsg, SyncCertMsg};
use std::sync::Arc;
use tokio::time::Duration;
use crate::{get_acc};

use crate::{Context, Event};

impl Context {
    /// This is triggered on seeing a valid proposal, and on seeing a valid decomposition proof
    pub async fn do_vote(&mut self, p: &Proposal, dq: &mut DelayQueue<Event>)
    {
        // Do not vote if the proposal was received after 4\Delta of starting the epoch
        if self.propose_timeout || self.equivocation_detected {
            return;
        }
        let resp_vote = ResponsiveVote{
            block_hash: p.new_block.hash,
            epoch: self.epoch,
        };
        let msg = ser_and_hash(&resp_vote);
        let sig = self.my_secret_key.sign(&msg).unwrap();
        let vote = Vote{
            origin: self.config.id,
            auth:sig,
        };
        let mut cert = Certificate::empty_cert();
        cert.add_vote(vote);
        cert.msg = msg.to_vec();
        // Send responsive vote to the leader
        if self.config.id == self.last_leader {
            self.receive_resp_vote(resp_vote, cert, dq).await;
            return;
        }
        self.net_send.send((self.last_leader, Arc::new(ProtocolMsg::RawResponsiveVoteMsg(resp_vote, cert)))).unwrap();
        // Set timer for 2\Delta to send synchronous vote
        dq.insert(Event::VoteTimeout(p.new_block.hash), Duration::from_millis(2*self.config.delta));
    }

    /// Do sync vote
    pub async fn do_sync_vote(&mut self,block_hash: Hash, dq: &mut DelayQueue<Event>)
    {
        let sync_vote = SyncVote{
            block_hash,
            epoch: self.epoch,
        };
        let msg = ser_and_hash(&sync_vote);
        let sig = self.my_secret_key.sign(&msg).unwrap();
        let vote = Vote{
            origin: self.config.id,
            auth: sig,
        };
        let mut cert = Certificate::empty_cert();
        cert.msg = msg.to_vec();
        cert.add_vote(vote);
        if self.config.id == self.last_leader {
            self.receive_sync_vote(sync_vote, cert, dq).await;
            return;
        }
        // Send sync vote to the leader
        self.net_send.send((self.last_leader, Arc::new(ProtocolMsg::RawSyncVoteMsg(sync_vote, cert)))).unwrap();
    }

    pub async fn receive_resp_vote(&mut self, resp_vote: ResponsiveVote, mut cert: Certificate, dq: &mut DelayQueue<Event>) {
        log::info!("Got a responsive vote");
        // Check if the vote is valid
        let hash = ser_and_hash(&resp_vote).to_vec();
        if self.id() != cert.votes[0].origin &&
            !self.pub_key_map[&cert.votes[0].origin].verify(&hash, &cert.votes[0].auth) {
                log::warn!("Invalid vote {:?} received: {:?}", resp_vote,cert);
                return;
        }
        if self.resp_votes.votes.len() == 0 {
            self.resp_votes.msg = hash;
        } 
        self.resp_votes.add_vote(cert.votes.remove(0));
        if self.resp_votes.votes.len() < self.optimistic() {
            return;
        } 
        // We have optimistic conditions
        let msg = ResponsiveCertMsg{
            cert: self.resp_votes.clone(),
            resp_vote: resp_vote,
        };
        let (shards, acc) = get_acc(&self, &msg);
        self.net_send.send((self.num_nodes(), 
            Arc::new(ProtocolMsg::RawResponsiveCert(msg.clone(), acc.clone()))
        )).unwrap();
        self.do_deliver_resp_cert(acc.clone(), shards, dq).await;
        self.receive_resp_cert_direct(msg, acc, dq).await;
    }

    pub async fn receive_sync_vote(&mut self, sync_vote: SyncVote, mut cert: Certificate, dq: &mut DelayQueue<Event>) {
        log::info!("Got a sync vote");
        // Check if the vote is valid
        let hash = ser_and_hash(&sync_vote).to_vec();
        if self.id() != cert.votes[0].origin &&
            !self.pub_key_map[&cert.votes[0].origin].verify(&hash, &cert.votes[0].auth) {
                log::warn!("Invalid vote {:?} received: {:?}", sync_vote,cert);
                return;
        }
        if self.sync_votes.votes.len() == 0 {
            self.sync_votes.msg = hash;
        } 
        self.sync_votes.add_vote(cert.votes.remove(0));
        if self.sync_votes.votes.len() < self.num_faults()+1 {
            return;
        } 
        // We have optimistic conditions
        let msg = SyncCertMsg{
            cert: self.sync_votes.clone(),
            sync_vote: sync_vote,
        };
        let (shards, acc) = get_acc(&self, &msg);
        self.net_send.send((self.num_nodes(), 
            Arc::new(ProtocolMsg::RawSyncCert(msg, acc.clone()))
        )).unwrap();
        self.do_deliver_sync_cert(acc, shards, dq).await;
    }
}