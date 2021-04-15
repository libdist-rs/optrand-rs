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
            // I got a new proposal
            ProtocolMsg::Propose(p,cert, decomp) => {
                self.receive_proposal_direct(sender, p, cert, decomp, dq).await;
            },
            // I got a proposal shard
            ProtocolMsg::DeliverPropose(shard, auth, origin) => {
                self.do_receive_propose_deliver(shard, auth, origin).await;
            },
            // I got a responsive vote message
            ProtocolMsg::ResponsiveVoteMsg(vote, sig) => {
                self.receive_resp_vote(vote, sig, dq).await;
            },
            // I got a sync vote message
            ProtocolMsg::SyncVoteMsg(vote, sig) => {
                self.receive_sync_vote(vote, sig, dq).await;
            }
            // Someone's pvss sharing for a future epoch is ready
            ProtocolMsg::PVSSSharingReady(epoch, pvec, decomp) => {
                self.new_sharing_ready(epoch, pvec, decomp).await;
            }
            // I got a responsive certificate
            ProtocolMsg::ResponsiveCert(msg, acc) => {
                self.receive_resp_cert_direct(msg, acc, dq).await;
            }
            // I got a deliver msg for responsive certificate
            ProtocolMsg::DeliverResponsiveCert(shard, auth,origin) => {
                self.do_receive_resp_cert_deliver(shard, auth, origin, dq).await;
            }
            // I got a synchronous certificate
            ProtocolMsg::SyncCert(msg, acc) => {
                self.receive_sync_cert_direct(msg, acc, dq).await;
            }
            // I got a deliver msg for responsive certificate
            ProtocolMsg::DeliverSyncCert(shard, auth,origin) => {
                self.do_receive_sync_cert_deliver(shard, auth, origin, dq).await;
            }
            // I got an ack message
            ProtocolMsg::Ack(msg, vote) => {
                self.on_recv_ack(msg, vote, dq).await;
            }
            // I got a status message
            ProtocolMsg::Status(ht, cert) => {
                self.do_receive_status(ht, cert).await;
            }
            // I got a beacon share
            ProtocolMsg::BeaconShare(ep, sh) => {
                self.on_recv_share(ep, sender, sh, dq).await;
            }
            // I got a reconstruction
            ProtocolMsg::BeaconReady(ep, b) => {
                self.on_recv_beacon(ep, b, dq).await;
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
            Event::SyncCommit(e) => self.start_sync_commit(e, dq).await,
            Event::ResponsiveCommitTimeout => {
                self.responsive_timeout = true;
            },
            Event::SyncCommitTimeout => {
                self.sync_commit_timeout = true;
            },
            Event::SyncTimer(e) => self.try_sync_commit(dq).await,
            // _ => {
            //     log::warn!("Event not supposed to occur");
            // }
        }
    }

    
}