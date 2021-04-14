use tokio_util::time::DelayQueue;
use types::{ProtocolMsg, Replica};
use crate::{Context, Event};

impl Context {
    /// React to a protocol message received on the network
    pub async fn handle_message(&mut self, sender: Replica, msg: ProtocolMsg, dq:&mut DelayQueue<Event>) {
        log::debug!("Got {:?} from {}", msg, sender);
        match msg {
            // I got a sharing for a future epoch
            ProtocolMsg::EpochPVSSSharing(pvec) => {
                self.new_epoch_sharing(sender, pvec).await;
            },
            ProtocolMsg::Propose(p,cert, decomp) => {
                self.receive_proposal_direct(sender, p, cert, decomp, dq).await;
            },
            ProtocolMsg::DeliverPropose(shard, auth, origin) => {
                self.do_receive_propose_deliver(shard, auth, origin).await;
            },
            ProtocolMsg::ResponsiveVoteMsg(vote, sig) => {
                self.receive_resp_vote(vote, sig, dq).await;
            },
            ProtocolMsg::SyncVoteMsg(vote, sig) => {
                self.receive_sync_vote(vote, sig, dq).await;
            }
            ProtocolMsg::PVSSSharingReady(epoch, pvec, decomp) => {
                
            }
            _x => log::info!("Unimplemented {:?}", _x),
        }
    }

    /// React to an event (timers or others that occured in the reactor)
    pub async fn handle_event(&mut self, ev: Event, dq: &mut DelayQueue<Event> ) {
        match ev {
            Event::EpochEnd => self.new_epoch(dq).await,
            Event::Propose => self.do_propose(dq).await,
            Event::ProposeTimeout => {
                self.propose_timeout = true;
            }
            Event::VoteTimeout(block_hash) => self.do_sync_vote(block_hash, dq).await,
            // _ => {
            //     log::warn!("Event not supposed to occur");
            // }
        }
    }

    
}