use crate::{EventQueue, MsgBuf, OptRandStateMachine};
use types::{Epoch, Result, error::Error};
use crypto::hash::Hash;

impl OptRandStateMachine {
    pub(crate) fn on_commit(&mut self, 
        e: Epoch,
        prop_hash: Hash,
        ev_queue: &mut EventQueue, 
        msg_buf: &mut MsgBuf,
    ) -> Result<()> {
        // Get the proposal
        let block = if let Some((x, _)) = self.storage.prop_from_hash(&prop_hash) {
            self.storage.get_delivered_block_by_hash(x.block().hash())
        } else {
            return Err(
                Error::Generic(
                    format!("Trying to commit a block for which we don't have the proposal")
                )
            );
        };

        // Get the block
        let block = if let Some(x) = block {
            x
        } else {
            return Err(
                Error::Generic(
                    format!("Trying to commit a block without having the block")
                )
            );
        };

        // Commit B and its parents
        self.storage.commit_block(block)
    }

    pub(crate) fn try_commit(&mut self,
        e: Epoch,
        prop_hash: Hash,
        ev_queue: &mut EventQueue,
        msg_buf: &mut MsgBuf,
    ) -> Result<()> {
        // Have we detected any equivocation?
        if self.storage.is_equivocation(&e) {
            return Err(
                Error::Generic(
                    format!("Equivocation detected. Not committing")
                )
            );
        }

        self.on_commit(e, prop_hash, ev_queue, msg_buf)
    }
}