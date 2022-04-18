// use std::collections::VecDeque;
// use config::{Node, generate_configs};
// use futures::StreamExt;
// use log::LevelFilter;
// use simple_logger::SimpleLogger;
// use types::{ProtocolMsg, Result, START_EPOCH, error::Error};
// use types_upstream::WireReady;

// pub const N: usize = 4;

// use crate::{EventQueue, MsgBuf, NewMessage, events::{Event, TimeOutEvent}};
// use crate::sync_sm::OptRandStateMachine as OSM;

// // A test config generator
// fn test_configs() -> Result<VecDeque<Node>> {
//     let mut to_generate = true;
//     for i in 0..N {
//         to_generate = std::path::Path::new(&format!("/tmp/nodes-{}.json", i)).exists();
//         if !to_generate {
//             break;
//         }
//     }
//     if !to_generate {
//         let confs = generate_configs(N, 1, 50, 4000)?;
//         for i in 0..N {
//             confs[i].write_file(config::OutputType::JSON, "/tmp");
//         }
//         return Ok(confs)
//     }
//     let configs = (0..N).map(|i| {
//         Node::from_json(format!("/tmp/nodes-{}.json", i))
//     }).collect();
//     Ok(configs)
// }
// // A test OSM generator
// fn test_osms() -> Result<VecDeque<OSM>> {
//     let mut configs = test_configs()?;
//     (0..N).map(|_i| {
//         let conf = configs.pop_front()
//             .ok_or("Did not return n configs".to_string())?;
//         Ok(OSM::new(conf))
//     }).collect::<Result<VecDeque<OSM>>>()

// }

// #[tokio::test]
// async fn test_epoch() -> Result<()> {
//     let _logger = SimpleLogger::new()
//         .with_level(LevelFilter::Debug)
//         .init()
//         .map_err(|e| format!("Log error: {}", e))?;
//     let mut osms = test_osms()?;
//     log::info!("Generated the OSMs");
//     let mut leader_osm = osms.pop_front()
//         .ok_or("Unable to pop an OSM".to_string())?;
//     // let mut ev_queue = EventQueue::with_capacity(100_000);
//     // let mut msg_buf = MsgBuf::new();
//     // log::info!("Starting the test");
//     // leader_osm.on_new_event(Event::TimeOut(TimeOutEvent::EpochTimeOut(START_EPOCH)), &mut ev_queue, &mut msg_buf)?;
//     // assert_eq!(leader_osm.current_epoch(), START_EPOCH+1, "Epoch number did not change after epoch timeout");
//     // assert_eq!(msg_buf.len(), 0, "No messages are expected from the leader after the first epoch");
//     // assert_eq!(leader_osm.leader_ctx.is_leader(1), false, "The first leader is node 1 not node 0");
//     Ok(())
// }

// #[tokio::test]
// async fn test_proposal() -> Result<()> {
//     let _logger = SimpleLogger::new()
//         .with_level(LevelFilter::Debug)
//         .init()
//         .map_err(|e| format!("Log error: {}", e))?;
//     let mut osms = test_osms()?;
//     log::info!("Generated the OSMs");
//     let mut leader_osm = osms.pop_front()
//         .ok_or("Unable to pop an OSM".to_string())?;
//     // let mut ev_queue: Vec<_> = (0..N).map(|_i| {
//     //     EventQueue::with_capacity(100_000)
//     // }).collect(); 
//     // let mut msg_buf:Vec<_> = (0..N).map(|_i| {
//     //     MsgBuf::new()
//     // }).collect();
//     // log::info!("Starting the test");
//     // let tout_ev = Event::TimeOut(TimeOutEvent::EpochTimeOut(START_EPOCH));
//     // leader_osm.on_new_event(tout_ev.clone(), &mut ev_queue[0], &mut msg_buf[0])?;
//     // let mut new_leader_osm = osms.pop_front().ok_or("Unable to pop an OSM".to_string())?;
//     // new_leader_osm.on_new_event(tout_ev, &mut ev_queue[1], &mut msg_buf[1])?;
//     // assert_eq!(new_leader_osm.leader_ctx.is_leader(1), true, "The first node should be the leader in epoch 1");
//     // let (from, status_msg) = msg_buf[0].pop_front()
//     //     .ok_or(
//     //         format!("Expected a status  msg from a non-leader node after epoch timeout")
//     //     )?;
//     // assert_eq!(from, 1, "The status message was not sent to the leader");
//     // if let ProtocolMsg::Status(vote, cert, pvec) = status_msg.as_ref() {
//     //     // Verify the new status message from 0
//     //     new_leader_osm.verify_status(0, vote, cert, pvec)?;
//     //     new_leader_osm.on_verified_status(0, vote.clone(), cert.clone(), pvec.clone())?;
//     //     // assert_eq!(new_leader_osm.rnd_ctx.num_beacon_shares() > 0, true, "We must have added this share");
//     // } else {
//     //     return Err(Error::Generic("Expected a status message".to_string()));
//     // }
//     // while let Some(Event::Message(from, NewMessage::Status(vote, cert, pvec))) = ev_queue[1].next().await {
//     //     new_leader_osm.on_verified_status(from, vote, cert, pvec)?;
//     //     // assert_eq!(new_leader_osm.rnd_ctx.num_beacon_shares() > 1, true, "We must have added this share");
//     // }
//     // // Now we must be ready to propose
//     // let msg_buf_len_before = msg_buf[1].len();
//     // new_leader_osm.on_new_timeout_event(
//     //     TimeOutEvent::ProposeWaitTimeOut(1), 
//     //     &mut ev_queue[1], 
//     //     &mut msg_buf[1],
//     // )?;
//     // assert_eq!(
//     //     msg_buf[1].len(), 
//     //     msg_buf_len_before + 1, 
//     //     "We must have added a new message to send to the others"
//     // );
//     // let (from, msg) = msg_buf[1].pop_back()
//     //     .ok_or("Expect at least the propose message".to_string())?;
//     // assert_eq!(from, N, "The proposal must be sent to all the nodes");
//     // let msg = msg.as_ref().clone().init();
//     // if let ProtocolMsg::Propose(x, y) = &msg {
//     //     // The other nodes must accept it
//     //     leader_osm.on_new_msg(1, msg.clone(), &mut ev_queue[0], &mut msg_buf[0])?;
//     //     let ev = ev_queue[0]._events_queue().pop_back().ok_or("Non leader node did not add the proposal to the event queue".to_string())?;
//     //     if let Event::Message(from, NewMessage::Propose(x, y)) = &ev {
//     //         assert_eq!(*from, 1, "Invalid source when adding propose to event queue");
//     //         leader_osm.on_new_msg_event(1, NewMessage::Propose(x.clone(), y.clone()), &mut ev_queue[0], &mut msg_buf[0])?;
//     //     } else {
//     //         return Err(Error::Generic(format!("Expected to add a propose new message event. Added {:?}", ev)));
//     //     }
//     //     // The leader must also accept its own proposal
//     //     let x = x.clone();
//     //     let y = y.clone();
//     //     new_leader_osm.on_new_msg_event(1, NewMessage::Propose(x, y), &mut ev_queue[1], &mut msg_buf[1])?;
//     // } else {
//     //     return Err(Error::Generic(
//     //         format!("Expected a proposal message but {:x?} was added to the message buffer", msg)
//     //     ));
//     // }
//     // new_leader_osm.verify_status()
//     Ok(())
// }