use linked_hash_map::LinkedHashMap;
use types::{Epoch, Replica, START_EPOCH};
use fnv::FnvHashMap as HashMap;

#[derive(Debug, Default)]
pub(crate) struct LeaderContext {
    // A rotating list of leaders
    leaders: LinkedHashMap<Replica, ()>,
    past_leaders: HashMap<Epoch, Replica>,
}

impl LeaderContext {
    /// Takes the leader from the current epoch, and adds it to the list of past leaders
    /// Then inserts this leader to the back of the linked hash map
    pub(crate) fn update_leader(&mut self, old_epoch: Epoch) {
        let (old_leader, _) = self.leaders.pop_front().unwrap();
        // Insert old leader at the back
        self.leaders.insert(old_leader, ());
        // Add old leader to the past leaders
        self.past_leaders.insert(old_epoch, old_leader);
    }

    /// Returns the current leader
    pub(crate) fn current_leader(&self) -> Replica {
        let (ldr, _) = self.leaders.front().unwrap();
        *ldr
    }

    pub(crate) fn remove_leader(&mut self, e:Epoch) {
        // We did not get any proposal from this epoch
        self.leaders.remove(&self.get_past_leader(&e));
    }

    pub(crate) fn get_past_leader(&self, _e: &Epoch) -> Replica {
        todo!()
    }

    /// Is this node the leader for the current epoch
    pub fn is_leader(&self, id: Replica) -> bool {
        id == self.current_leader()
    }

    pub(crate) fn new(num_nodes: usize) -> LeaderContext {
        let mut leaders = LinkedHashMap::default();
        let past_leaders = HashMap::default();
        for i in START_EPOCH..START_EPOCH+num_nodes {
            leaders.insert(i, ());
        }
        Self {
            leaders,
            past_leaders,
        }
    }

}