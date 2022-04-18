use crate::{EventQueue, events::{Event}};
use super::OptRandStateMachine;
use types::Result;

impl OptRandStateMachine {
    pub(crate) fn on_new_event(&mut self, 
        ev: Event, 
    ) -> Result<()> 
    {
        match ev {
            Event::LoopBack(x) => {
                self.on_new_msg(self.config.id, x)
            }
            _ => unimplemented!(),
        }
    }

    pub(crate) fn _on_equivocation(&mut self) -> Result<()> 
    {
        unimplemented!()
    }
}