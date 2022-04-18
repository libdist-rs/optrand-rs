use crate::{Event, EventQueue, NewMessage, events::TimeOutEvent};
use super::OptRandStateMachine;
use types::{ProtocolMsg, Replica, Result, START_EPOCH};

impl OptRandStateMachine {
    // `on_new_msg` takes incoming protocol messages, validates it and then calls the `on_new_msg_event`
    pub(crate) fn on_new_msg(&mut self, 
        sender: Replica,
        msg: ProtocolMsg, 
        ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        #[cfg(feature = "profile")]
        let now = std::time::Instant::now();
        match msg {
            ProtocolMsg::Status(vote, cert, pvec) => {
                self.verify_status(sender, &vote, &cert, pvec)?;
                ev_queue.add_event(
                    Event::Message(
                        sender, 
                        NewMessage::Status(vote, cert)
                    )
                );
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Message handling profile for {}: {}", 
                        "status", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            ProtocolMsg::Propose(prop, proof) => {
                self.verify_proposal(sender, &prop, &proof)?;
                ev_queue.add_event(
                    Event::Message(
                        sender, 
                        NewMessage::Propose(prop, proof)
                ));
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Message handling profile for {}: {}", 
                        "Propose", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            ProtocolMsg::DeliverPropose(sh_for, d) => {
                self.verify_propose_deliver_share(sender, sh_for, &d)?;
                ev_queue.add_event(
                    Event::Message(
                        sh_for, 
                        NewMessage::DeliverPropose(sh_for, d)
                    )
                );
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Message handling profile for {}: {}", 
                        "deliver propose", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            ProtocolMsg::SyncVote(v, c) => {
                self.verify_sync_vote(&v, &c)?;
                ev_queue.add_event(
                    Event::Message(
                        sender, 
                        NewMessage::SyncVote(v, c)
                    )
                );
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Message handling profile for {}: {}", 
                        "sync vote", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            ProtocolMsg::SyncCert(prop, proof) => {
                self.verify_sync_cert(sender, &prop, &proof)?;
                ev_queue.add_event(
                    Event::Message(
                        sender,
                        NewMessage::SyncCert(prop, proof)
                    )
                );
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Message handling profile for {}: {}", 
                        "sync cert", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            ProtocolMsg::DeliverSyncCert(sh_for, d) => {
                self.verify_sync_cert_deliver_share(sender, sh_for, &d)?;
                ev_queue.add_event(
                    Event::Message(
                        sh_for,
                        NewMessage::DeliverSyncCert(sh_for, d)
                    )
                );
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Message handling profile for {}: {}", 
                        "deliver sync cert", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            ProtocolMsg::BeaconShare(e, dec) => {
                // Directly forward it to the beacon context
                ev_queue.add_event(
                    Event::Message(
                        sender,
                        NewMessage::BeaconShare(e, dec)
                    )
                );
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Message handling profile for {}: {}", 
                        "beacon share", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            ProtocolMsg::AggregateReady(agg, decomp) => {
                self.on_optimizer_agg_ready(sender, agg, decomp)?;
            }
            ProtocolMsg::InvalidMessage => {
                log::warn!("{} sent an invalid message", sender);
            }
            ProtocolMsg::Sync => {
                ev_queue.add_event(
                    Event::TimeOut(
                        TimeOutEvent::EpochTimeOut(START_EPOCH),
                    )
                );

            }
            _ => unimplemented!("Handling of {:?}", msg),
        }
        Ok(())
    }
    
    pub(crate) fn on_new_msg_event(&mut self, 
        from: Replica, 
        msg_ev: NewMessage, 
        ev_queue: &mut EventQueue, 
    ) -> Result<()> {
        #[cfg(feature = "profile")]
        let now = std::time::Instant::now();
        match msg_ev {
            NewMessage::Status(vote, c) => {
                self.on_verified_status(from, vote, c)?;
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Verified message handling profile for {}: {}", 
                        "Status", 
                        now2.duration_since(now).as_micros()
                    );
                }
            },
            NewMessage::Propose(prop, proof) => {
                self.on_verified_propose(prop, proof, ev_queue)?;
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Verified message handling profile for {}: {}", 
                        "Propose", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            NewMessage::DeliverPropose(from, sh) => {
                self.on_verified_propose_deliver(from, sh)?;
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Verified message handling profile for {}: {}", 
                        "Deliver Propose", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            NewMessage::SyncVote(v, c) => {
                self.on_verified_sync_vote(from, v, c, ev_queue)?;
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Verified message handling profile for {}: {}", 
                        "Sync Vote", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            NewMessage::SyncCert(prop, proof) => {
                self.on_verified_sync_cert(prop, proof, ev_queue)?;
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Verified message handling profile for {}: {}", 
                        "Sync Cert", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            NewMessage::DeliverSyncCert(from, sh) => {
                self.on_verified_sync_cert_deliver(from, sh)?;
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Verified message handling profile for {}: {}", 
                        "Deliver sync cert", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            NewMessage::BeaconShare(e, dec) => {
                self.on_new_beacon_share(from, e, dec)?;
                #[cfg(feature = "profile")]
                {
                    let now2 = std::time::Instant::now();
                    println!("Verified message handling profile for {}: {}", 
                        "Beacon share", 
                        now2.duration_since(now).as_micros()
                    );
                }
            }
            _ => unimplemented!("Handling of {:?}", msg_ev),
        }
        Ok(())
    }
}