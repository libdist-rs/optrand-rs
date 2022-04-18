use std::sync::Arc;
use types::{Certificate, Epoch, ProtocolMsg, Replica, Result, Type, Vote, VoteBuilder, error::Error, sync_threshold};
use crate::{Event, EventQueue, NewMessage, OutMsg};
use super::OptRandStateMachine;
use crypto::hash::Hash;

impl OptRandStateMachine {
    /// Called by all the nodes after waiting 2\Delta to try and send a sync vote
    pub(crate) fn try_sync_vote(&self, 
        e:Epoch, 
        prop_hash: Hash, 
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        // Check for equivocation in epoch e
        if self.storage.is_equivocation(&e) {
            log::warn!("Proposal equivocation detected. Not voting.");
            return Err(Error::EquivocationDetected(e));
        }
        let vote = {
            let mut builder = VoteBuilder::default();
            builder.epoch(e)
                .prop_hash(prop_hash)
                .tp(types::Type::Sync)
                .build()
                .map_err(|e| format!("Builder Error: {}", e))?
        };
        let cert = Certificate::new_cert(&vote, self.config.id, &self.sk)?;
        if !self.leader_ctx.is_leader(self.config.id) {
            let msg = self.sync_vote_msg(vote.clone(), cert.clone())?;
            ev_queue.send_msg(msg);
        } else {
            ev_queue.add_event(Event::Message(self.config.id,
                NewMessage::SyncVote(vote, cert)
            ));
        }
        Ok(())
    }

    fn sync_vote_msg(&self, vote: Vote, cert: Certificate<Vote>) -> Result<OutMsg> {
        let msg = ProtocolMsg::SyncVote(vote, cert);
        Ok((
            self.leader_ctx.current_leader(),
            Arc::new(msg)
        ))
    }

    /// Called by the leader of the epoch to add this vote to the sync cert
    pub(crate) fn verify_sync_vote(&mut self, 
        v: &Vote, 
        cert: &Certificate<Vote>
    ) -> Result<()> {
        log::debug!("Checking sync vote");
        // Skip check if we already have a certificate for the epoch
        if self.storage.num_sync_votes(&v.epoch()) > self.config.num_faults {
            return Ok(());
        }

        if v.vote_type() != &Type::Sync {
            return Err(
                format!("Got a sync vote that is not of type sync").into()
            );
        }

        // Check if the signature is valid
        cert.buffered_is_valid(v, &self.pk_map, &mut self.storage)
    }

    pub(crate) fn on_verified_sync_vote(&mut self, 
        from: Replica,
        v: Vote, 
        c: Certificate<Vote>,
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        // Skip if already have a certificate
        if self.storage.num_sync_votes(&v.epoch()) > self.config.num_faults {
            return Ok(());
        }
        log::info!("Got a valid sync vote");
        // Add vote
        if self.storage.add_sync_vote(from, v, c).is_some() {
            log::warn!("Got a sync vote from the same node on two messages");
        }

        // Try cleaving
        if let Some((v, c)) = self.storage.cleave_sync_cert(self.epoch, sync_threshold(self.config.num_nodes)) 
        {
            log::info!("Successfully created a sync certificate for {}", v.epoch());
            if self.highest_certified_data().epoch() < self.epoch {
                // If successful update highest certificate
                self.update_highest_cert(v.clone(), c.clone())?;
            }
            // Propose sync cert
            self.propose_sync_cert(v, c,ev_queue)?;
        }
        Ok(())
    }
}