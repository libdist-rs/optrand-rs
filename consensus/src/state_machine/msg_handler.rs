use crate::{Event, EventQueue, MsgBuf, NewMessage, OptRandStateMachine};
use types::{ProtocolMsg, Replica, Result};

impl OptRandStateMachine {
    // `on_new_msg` takes incoming protocol messages, validates it and then calls the `on_new_msg_event`
    pub(crate) fn on_new_msg(&mut self, 
        sender: Replica,
        msg: ProtocolMsg, 
        ev_queue: &mut EventQueue, 
        _msg_buf: &mut MsgBuf
    ) -> Result<()> {
        match msg {
            ProtocolMsg::Status(vote, cert, pvec) => {
                self.verify_status(sender, &vote, &cert, &pvec)?;
                ev_queue.add_event(Event::Message(sender, NewMessage::Status(vote, cert, pvec)));
                Ok(())
            }
            ProtocolMsg::Propose(prop, proof) => {
                self.verify_proposal(sender, &prop, &proof)?;
                ev_queue.add_event(Event::Message(sender, NewMessage::Propose(prop, proof)));
                Ok(())
            }
            ProtocolMsg::DeliverPropose(sh_for, d) => {
                self.verify_propose_deliver_share(sender, sh_for, &d)?;
                ev_queue.add_event(
                    Event::Message(
                        sh_for, 
                        NewMessage::DeliverPropose(sh_for, d)
                    )
                );
                Ok(())
            }
            ProtocolMsg::SyncVote(v, c) => {
                self.verify_sync_vote(&v, &c)?;
                ev_queue.add_event(
                    Event::Message(
                        sender, 
                        NewMessage::SyncVote(v, c)
                    )
                );
                Ok(())
            }
            ProtocolMsg::SyncCert(prop, proof) => {
                self.verify_sync_cert(sender, &prop, &proof)?;
                ev_queue.add_event(
                    Event::Message(
                        sender,
                        NewMessage::SyncCert(prop, proof)
                    )
                );
                Ok(())
            }
            ProtocolMsg::DeliverSyncCert(sh_for, d) => {
                self.verify_sync_cert_deliver_share(sender, sh_for, &d)?;
                ev_queue.add_event(
                    Event::Message(
                        sh_for,
                        NewMessage::DeliverSyncCert(sh_for, d)
                    )
                );
                Ok(())
            }
            ProtocolMsg::InvalidMessage => {
                log::warn!("{} sent an invalid message", sender);
                Ok(())
            }
            _ => unimplemented!("Handling of {:?}", msg),
        }
    }
    
    pub(crate) fn on_new_msg_event(&mut self, 
        from: Replica, 
        msg_ev: NewMessage, 
        ev_queue: &mut EventQueue, 
        msg_buf: &mut MsgBuf
    ) -> Result<()> {
        match msg_ev {
            NewMessage::Status(vote, c, pvec) => {
                self.on_verified_status(from, vote, c, pvec)
            },
            NewMessage::Propose(prop, proof) => {
                self.on_verified_propose(prop, proof, ev_queue, msg_buf)
            }
            NewMessage::DeliverPropose(from, sh) => {
                self.on_verified_propose_deliver(from, sh)
            }
            NewMessage::SyncVote(v, c) => {
                self.on_verified_sync_vote(from, v, c, ev_queue, msg_buf)
            }
            NewMessage::SyncCert(prop, proof) => {
                self.on_verified_sync_cert(prop, proof, ev_queue, msg_buf)
            }
            NewMessage::DeliverSyncCert(from, sh) => {
                self.on_verified_sync_cert_deliver(from, sh)
            }
            _ => unimplemented!("Handling of {:?}", msg_ev),
        }
    }
}