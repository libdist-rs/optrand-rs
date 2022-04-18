use std::{collections::VecDeque, task::{Poll, Context}, time::Duration, pin::Pin, sync::Arc};

use config::Node;
use futures::{Stream, StreamExt};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::time::DelayQueue;
use types::{Replica, ProtocolMsg};
use crate::{OutMsg, events::Event};

pub(crate) struct EventQueue {
    time_queue: DelayQueue<Event>,
    ev_queue: VecDeque<Event>,
    net_send: UnboundedSender<OutMsg>,
    loopback_tx: VecDeque<ProtocolMsg>,
    myid: Replica,
    num_nodes: Replica,
}

impl Stream for EventQueue {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) 
                                                -> Poll<Option<Self::Item>> 
    {
        if let Some(x) = self.loopback_tx.pop_front() {
            return Poll::Ready(Some(Event::LoopBack(x)));
        }
        if let Some(x) = self
            .ev_queue
            .pop_front() 
        {
            return Poll::Ready(Some(x));
        }
        if !self
            .time_queue
            .is_empty() 
        {
            if let Poll::Ready(Some(x)) = 
                self
                    .time_queue
                    .poll_next_unpin(cx) 
            {
                return Poll::Ready(Some(x.into_inner()));
            }
        }
        Poll::Pending
    }
}

impl EventQueue {
    /// The size parameter defines the initial sizes for the event queue and the timer queue
    pub fn with_capacity(size: usize, 
        net_send: UnboundedSender<OutMsg>,
        config: &Node,
    ) 
    -> Self 
    {
        Self {
            time_queue: DelayQueue::with_capacity(size),
            ev_queue: VecDeque::with_capacity(size),
            net_send,
            loopback_tx: VecDeque::default(),
            myid: config.id,
            num_nodes: config.num_nodes,
        }
    }

    // pub fn add_event(&mut self, ev: Event) {
    //     self.ev_queue.push_back(ev);
    // }

    // pub fn add_timeout(&mut self, 
    //     ev: Event,
    //     timeout: Duration,
    // ) {
    //     self.time_queue.insert(ev, 
    //          timeout
    //     );
    // }

    pub(crate) fn send_msg(&mut self, dest: Replica, msg: ProtocolMsg) 
    {
        if dest == self.myid || dest == self.num_nodes {
            self
                .loopback_tx
                .push_back(msg.clone());
        }
        let err = self
            .net_send
            .send((dest,Arc::new(msg)));
        if let Err(e) = err {
            log::error!("Error sending message: {}", e);
        }
    }
}