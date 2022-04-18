use std::sync::Arc;

use crypto::hash::Hash;
use types::{Certificate, Epoch, ProtocolMsg, Replica, Result, Type, Vote, VoteBuilder, resp_threshold};
use crate::{OutMsg, ev_queue::EventQueue, events::{Event, NewMessage}};

use super::OptRandStateMachine;

impl OptRandStateMachine {
    fn resp_vote_msg(&self, 
        vote: Vote, 
        cert: Certificate<Vote>
    ) -> OutMsg {
        (
            self.leader_ctx.current_leader(),
            Arc::new(ProtocolMsg::RespVote(vote, cert)),
        )
    }

    pub(crate) fn do_resp_vote(&mut self, 
        e: Epoch, 
        prop_hash: Hash, 
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        let vote = {
            let mut builder = VoteBuilder::default();
            builder.epoch(e)
                .prop_hash(prop_hash)
                .tp(types::Type::Responsive)
                .build()
                .map_err(|e| format!("Builder Error: {}", e))?
        };
        let cert = Certificate::new_cert(&vote, self.config.id, &self.sk)?;
        if !self.leader_ctx.is_leader(self.config.id) {
            let msg = self.resp_vote_msg(vote.clone(), cert.clone());
            ev_queue.send_msg(msg);
        } else {
            ev_queue.add_event(
                Event::Message(
                    self.config.id,
                    NewMessage::RespVote(vote, cert),
                )
            );
        }
        Ok(())
    }

    pub(crate) fn verify_resp_vote(&mut self, 
        v: &Vote, 
        cert: &Certificate<Vote>
    ) -> Result<()> {
        log::debug!("Checking resp vote");
        // Skip checking if we already have a responsive certificate
        if self.storage.num_resp_votes(&v.epoch()) > v.num_sigs(self.config.num_nodes) 
        {
            return Ok(());
        }

        if v.vote_type() != &Type::Responsive {
            return Err(
                format!("Got a responsive vote that is not responsive").into()
            );
        }

        // Check if the signature is valid
        cert.buffered_is_valid(v, &self.pk_map, &mut self.storage)
    }


    pub(crate) fn on_verified_resp_vote(&mut self, 
        from: Replica, 
        v: Vote, 
        c: Certificate<Vote>, 
        ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        log::info!("Got a valid resp vote");
        // Check if we have a lready collected enough responsive votes
        if self.storage.num_resp_votes(&v.epoch()) > v.num_sigs(self.config.num_nodes) 
        {
            return Ok(());
        }
        
        // Add vote
        if self.storage.add_resp_vote(from, v, c).is_some() {
            log::warn!("Got a resp vote from the same node on two messages");
        }

        // Try cleaving
        if let Some((v, c)) = self.storage.cleave_resp_cert(self.epoch,resp_threshold(self.config.num_nodes)) {
            log::info!("Successfully created a resp certificate for {}", v.epoch());
            // If successful update highest certificate
            log::info!("Updating highest cert to a responsive cert");
            // Always upgrade to the responsive certificate
            self.update_highest_cert(v.clone(), c.clone())?;
            // Propose resp cert
            // log::warn!("Unimplemented proposing responsive cert");
            self.propose_resp_cert(v, c,ev_queue)?;
        }
        Ok(())

        // todo!();
    }
}