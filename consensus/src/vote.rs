use crypto::hash::{Hash, ser_and_hash};
use tokio_util::time::DelayQueue;
use types::{Certificate, Proposal, ResponsiveVote, Vote, ProtocolMsg, SyncVote};
use std::sync::Arc;
use tokio::time::Duration;

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

    pub async fn receive_resp_vote(&mut self, resp_vote: ResponsiveVote, cert: Certificate, dq: &mut DelayQueue<Event>) {
        log::info!("Got a responsive vote");
    }

    pub async fn receive_sync_vote(&mut self, sync_vote: SyncVote, cert: Certificate, dq: &mut DelayQueue<Event>) {
        log::info!("Got a sync vote");
    }
}