use tokio_util::time::DelayQueue;
use types::{ProtocolMsg, Replica};
use crate::{Context, Event};

impl Context {
    /// React to a protocol message received on the network
    pub fn handle_message(&mut self, sender: Replica, msg: ProtocolMsg, dq:&mut DelayQueue<Event>) {
        log::debug!("Got {:?} from {}", msg, sender);
        let msg = self.futurify(sender, msg);
        if msg.is_none() {
            return;
        }
        let msg = msg.unwrap();
        match msg {
            // I got a sharing for a future epoch
            ProtocolMsg::EpochPVSSSharing(pvec) => {
                self.new_epoch_sharing(sender, pvec);
            },
            // I got a new proposal
            ProtocolMsg::Propose(e, p,cert, decomp) => {
                self.receive_proposal_direct(e, sender, p, cert, decomp, dq);
            },
            // // I got a proposal shard
            // ProtocolMsg::DeliverPropose(e, shard, auth, origin) => {
            //     // self.do_receive_propose_deliver(e, shard, auth, origin).await;
            // },
            // I got a responsive vote message
            ProtocolMsg::ResponsiveVoteMsg(vote, sig) => {
                self.receive_resp_vote(vote, sig, dq);
            },
            // // I got a sync vote message
            // ProtocolMsg::SyncVoteMsg(vote, sig) => {
            //     self.receive_sync_vote(vote, sig, dq).await;
            // }
            // Someone's pvss sharing for a future epoch is ready
            ProtocolMsg::PVSSSharingReady(epoch, pvec, decomp) => {
                self.new_sharing_ready(epoch, pvec, decomp);
            }
            // I got a responsive certificate
            ProtocolMsg::ResponsiveCert(msg, acc) => {
                self.receive_resp_cert_direct(msg, acc, dq);
            }
            // // I got a deliver msg for responsive certificate
            // ProtocolMsg::DeliverResponsiveCert(e, shard, auth,origin) => {
                // self.do_receive_resp_cert_deliver(e, shard, auth, origin, dq).await;
            // }
            // // I got a synchronous certificate
            // ProtocolMsg::SyncCert(msg, acc) => {
            //     self.receive_sync_cert_direct(msg, acc, dq);
            // }
            // // I got a deliver msg for responsive certificate
            // ProtocolMsg::DeliverSyncCert(e, shard, auth,origin) => {
            //     // self.do_receive_sync_cert_deliver(e,shard, auth, origin, dq).await;
            // }
            // I got an ack message
            ProtocolMsg::Ack(msg, vote) => {
                self.on_recv_ack(msg, vote, dq);
            }
            // I got a status message
            ProtocolMsg::Status(e, ht, cert) => {
                self.do_receive_status(ht, cert);
            }
            // I got a beacon share
            ProtocolMsg::BeaconShare(ep, sh) => {
                self.on_recv_share(ep, sender, sh, dq);
            }
            // I got a reconstruction
            // ProtocolMsg::BeaconReady(ep, b) => {
            //     self.on_recv_beacon(ep, b, dq).await;
            // }
            _x => log::info!("Unimplemented"),
        }
    }

    /// React to an event (timers or others that occured in the reactor)
    pub fn handle_event(&mut self, ev: Event, dq: &mut DelayQueue<Event> ) {
        match ev {
            Event::EpochEnd(e) => self.new_epoch(e, dq),
            Event::Propose => self.do_propose(dq),
            Event::ProposeTimeout => {
                self.propose_timeout = true;
            }
            Event::VoteTimeout(block_hash) => self.do_sync_vote(block_hash, dq),
            Event::SyncCommit(ht) => self.start_sync_commit(ht, dq),
            Event::ResponsiveCommitTimeout => {
                self.responsive_timeout = true;
            },
            Event::SyncCommitTimeout => {
                self.sync_commit_timeout = true;
            },
            Event::SyncTimer(ht) => self.try_sync_commit(ht, dq),
            // _ => {
            //     log::warn!("Event not supposed to occur");
            // }
        }
    }

    /// If this proposal message is for a future epoch, futurify it
    pub fn futurify(&mut self, sender: Replica, m: ProtocolMsg) -> Option<ProtocolMsg> {
        let e = m.get_epoch();
        if self.epoch < e {
            log::warn!("Got a future msg {:?}", m);
            self.add_future_messages((sender, m));
            return None;
        }
        Some(m)
    }
}