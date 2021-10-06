use std::collections::VecDeque;
use config::{Node, generate_configs};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use tokio_util::time::DelayQueue;
use types::{Result, START_EPOCH, error::Error};

pub const N: usize = 4;

use crate::{EventQueue, OptRandStateMachine as OSM, events::{Event, TimeOutEvent}};

// A test config generator
fn test_configs() -> Result<VecDeque<Node>> {
    let mut to_generate = true;
    for i in 0..N {
        to_generate = std::path::Path::new(&format!("/tmp/nodes-{}.json", i)).exists();
        if !to_generate {
            break;
        }
    }
    if !to_generate {
        let confs = generate_configs(N, 1, 50, 4000)?;
        for i in 0..N {
            confs[i].write_file(config::OutputType::JSON, "/tmp");
        }
        return Ok(confs)
    }
    let configs = (0..N).map(|i| {
        Node::from_json(format!("/tmp/nodes-{}.json", i))
    }).collect();
    Ok(configs)
}
// A test OSM generator
fn test_osms() -> Result<VecDeque<OSM>> {
    let mut configs = test_configs()?;
    (0..N).map(|_i| {
        let conf = configs.pop_front()
            .ok_or("Did not return n configs".to_string())?;
        Ok(OSM::new(conf))
    }).collect::<Result<VecDeque<OSM>>>()

}

#[test]
fn test_epoch() -> Result<()> {
    let _logger = SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init()
        .map_err(|e| format!("Log error: {}", e))?;
    let mut osms = test_osms()?;
    log::info!("Generated the OSMs");
    let mut leader_osm = osms.pop_front()
        .ok_or("Unable to pop an OSM".to_string())?;
    let mut ev_queue = EventQueue::with_capacity(100_000);
    log::info!("Starting the test");
    let msgs = leader_osm.on_new_event(Event::TimeOut(TimeOutEvent::EpochTimeOut(START_EPOCH)), &mut ev_queue)?;
    assert_eq!(msgs.len(), 0, "No messages are expected from the leader after the first epoch");
    assert_eq!(leader_osm.is_leader(), false, "The first leader is node 1 not node 0");
    Ok(())
}