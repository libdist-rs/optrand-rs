use types::{Epoch, ProtocolMsg, Replica};

use crate::context::Context;

impl Context {
    pub fn get_future_messages(&mut self, e: Epoch) -> Option<(Replica, ProtocolMsg)> {
        if self.future_messages1.contains_key(&e) {
            return self.future_messages1.remove(&e);
        }
        if self.future_messages2.contains_key(&e) {
            return self.future_messages2.remove(&e);
        }
        if self.future_messages3.contains_key(&e) {
            let vec = self.future_messages3.remove(&e);
            if let Some(mut x) = vec {
                if x.len() > 0 {
                    let val = x.pop().unwrap();
                    self.future_messages3.insert(e, x);
                    return Some(val);
                };
            }
        }
        None
    }

    pub fn add_future_messages(&mut self, m: (Replica, ProtocolMsg)) {
        let e = m.1.get_epoch();
        match &m {
            (_, ProtocolMsg::Propose(..)) => {
                self.future_messages1.insert(e, m);
            }
            (_,ProtocolMsg::ResponsiveCert(..)) => {
                self.future_messages2.insert(e, m);
            }
            (_,ProtocolMsg::Ack(..)) => {
                if let None = self.future_messages3.remove(&e) {
                    let mut new_vec = Vec::new();
                    new_vec.push(m);
                    self.future_messages3.insert(e, new_vec);
                } else {
                    let mut old_vec = self.future_messages3.remove(&e).unwrap();
                    old_vec.push(m);
                    self.future_messages3.insert(e, old_vec);
                }
            }
            _ => (),
        }
    }
}