use std::sync::Arc;
use types::{Decryption, Epoch, ProtocolMsg, Replica, Result};
use crate::{Event, NewMessage, OutMsg, ev_queue::EventQueue};
use super::OptRandStateMachine;

impl OptRandStateMachine {
    fn new_beacon_share_msg(&self, 
        e: Epoch,
        dec: Decryption,
    ) -> OutMsg
    {
        (
            self.config.num_nodes, // SendAll
            Arc::new(ProtocolMsg::BeaconShare(e, dec))
        )
    }

    // Do the beacon sharing for epoch e
    pub(crate) fn on_beacon_share(&mut self, 
        e: Epoch,
        ev_queue: &mut EventQueue,
    ) -> Result<()> 
    {
        // Get pvss from random beacon queue and add it to Q
        log::debug!("Getting PVSS vec for {}", self.leader_ctx.current_leader());
        let pvss = self.storage.cleave_beacon_share(self.leader_ctx.current_leader())?;

        let my_share = self.config.pvss_ctx.decrypt_share(&pvss.encs[self.config.id], &self.sk, &mut self.rng);
        self.beacon_ctx.add_epoch_pvss(e, pvss, self.config.num_nodes);
        // Send my shares to all the nodes
        let msg = self.new_beacon_share_msg(e, my_share.clone());
        ev_queue.send_msg(msg);
        // Add my own share to the ev_queue
        ev_queue.add_event(
            Event::Message(
                self.config.id,
                NewMessage::BeaconShare(
                    e,
                    my_share,
                )
            )
        );
        Ok(())
    }

    pub(crate) fn on_new_beacon_share(&mut self,
        from: Replica,
        e: Epoch,
        dec: Decryption,
        ev_queue: &mut EventQueue,
    ) -> Result<()> {
        let beacon_opt = self.beacon_ctx.add_beacon_share(&self.config.pvss_ctx, 
            self.config.id,
            &self.pk_map, 
            e, 
            from, 
            dec,
            self.config.num_faults,
        )?;
        if let None = beacon_opt {
            return Ok(());
        }
        let beacon = beacon_opt.unwrap();
        println!("Got a beacon");
        self.on_beacon_ready(e, beacon, ev_queue)
    }
}