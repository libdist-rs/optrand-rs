use linked_hash_map::LinkedHashMap;
use types::{Epoch, Replica, START_EPOCH};
use fnv::FnvHashMap as HashMap;

#[derive(Debug, Default)]
pub(crate) struct LeaderContext {
    // A rotating list of qualified leaders
    qualified_leaders: LinkedHashMap<Replica, ()>,
    /// HashMap <Epoch, Replica>
    past_leaders: HashMap<Epoch, Replica>,
}

impl LeaderContext {
    /// Takes the leader from the current epoch, and adds it to the list of past leaders
    /// Then inserts this leader to the back of the linked hash map
    pub(crate) fn update_leader(&mut self, old_epoch: Epoch) {
        let old_leader = self
            .qualified_leaders
            .pop_front()
            .unwrap()
            .0;
        // Insert old leader to the list of leaders
        self
            .qualified_leaders
            .insert(old_leader, ());
        // Add old leader to the map of epoch <-> leader
        self
            .past_leaders
            .insert(old_epoch, old_leader);
    }

    /// Returns the current leader
    pub(crate) fn current_leader(&self) -> Replica {
        self
            .qualified_leaders
            .front()
            .unwrap()
            .0
            .clone()
    }

    pub(crate) fn remove_leader(&mut self, e:Epoch) {
        // We did not get any proposal from this epoch
        self
            .qualified_leaders
            .remove(&self.get_past_leader(&e));
    }

    pub(crate) fn get_past_leader(&self, e: &Epoch) -> Replica {
        self
            .past_leaders
            .get(e)
            .expect("Queried a future leader")
            .clone()
    }

    /// Is this node the leader for the current epoch
    pub fn is_leader(&self, id: Replica) -> bool {
        id == self.current_leader()
    }

    pub(crate) fn new(num_nodes: usize) -> Self {
        let mut ctx = Self::default();
        // Populate the qualified nodes from `START_EPOCH` to `START_EPOCH`+n
        for i in START_EPOCH..START_EPOCH+num_nodes {
            ctx.qualified_leaders.insert(i%num_nodes, ());
        }
        for i in 0..START_EPOCH {
            ctx.past_leaders.insert(i, i%num_nodes);
        }
        ctx
    }

}