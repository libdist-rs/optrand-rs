use std::sync::Arc;

use crate::{ThreadRecvMsg, ThreadSendMsg, ev_queue::EventQueue, optimistic_sm::OptRandStateMachine};
use crypto::{hash::ser_and_hash};
use types::{AggregatePVSS, DecompositionProof, ProtocolMsg, Replica, Result};

impl OptRandStateMachine {
    pub(crate) fn on_optimizer_event(&mut self, 
        ev: ThreadRecvMsg,
        ev_queue: &mut EventQueue,
    ) -> Result<()>
    {
        match ev {
            // I have aggregated some messages, and am ready to send them to all the nodes
            ThreadRecvMsg::AggregateReady(vec, proof) => {
                // New protocol msg
                let msg = (self.config.num_nodes,
                    Arc::new(ProtocolMsg::AggregateReady(vec.clone(), proof.clone()))
                );
                ev_queue.send_msg(msg);
                self.config.leader_beacon_queue.push_back((vec, proof));
            }
            // Some other node's share is ready for use
            ThreadRecvMsg::VerifiedAggregateSharing(_from, agg) => {
                // Store it in a buffer
                let hash = ser_and_hash(&agg);
                self.config.pool_of_verified_shares.insert(hash, agg);
            }
        }
        Ok(())
    }

    pub(crate) fn on_optimizer_agg_ready(&mut self,
        from: Replica,
        agg: AggregatePVSS,
        decomp: DecompositionProof,
    ) -> Result<()>
    {
        self.leader_thread_sender.send(
            ThreadSendMsg::NewAggregateSharing(from, agg, decomp)
        ).map_err(|e| 
            format!("Failed to send to leader thread: {}", e)
        )?;
        Ok(())
    }
}