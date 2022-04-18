use std::{collections::VecDeque, task::{Poll, Context}, time::Duration, pin::Pin};

use futures::{Stream, StreamExt};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::time::DelayQueue;
use types::Epoch;
use crate::{OutMsg, events::{Event, TimeOutEvent}};

pub(crate) struct EventQueue {
    time_queue: DelayQueue<TimeOutEvent>,
    ev_queue: VecDeque<Event>,
    net_send: UnboundedSender<OutMsg>,
    _delta: u64,
    root_time: tokio::time::Instant,
}

impl Stream for EventQueue {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) 
                                                -> Poll<Option<Self::Item>> 
    {
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
            if let Poll::Ready(Some(Ok(x))) = 
                self
                    .time_queue
                    .poll_next_unpin(cx) 
            {
                return Poll::Ready(Some(Event::TimeOut(x.into_inner())));
            }
        }
        Poll::Pending
    }
}

impl EventQueue {
    /// The size parameter defines the initial sizes for the event queue and the timer queue
    pub fn with_capacity(size: usize, 
        net_send: UnboundedSender<OutMsg>,
        delta: u64,
    ) 
    -> Self 
    {
        Self {
            time_queue: DelayQueue::with_capacity(size),
            ev_queue: VecDeque::with_capacity(size),
            net_send,
            root_time: tokio::time::Instant::now(),
            _delta: delta,
        }
    }

    pub fn reset_root_time(&mut self) {
        self.root_time = tokio::time::Instant::now();
    }

    pub fn add_event(&mut self, ev: Event) {
        self.ev_queue.push_back(ev);
    }

    pub fn add_timeout(&mut self, 
        tev: TimeOutEvent, 
        timeout: Duration, 
        _e: Epoch,
    ) {
        self.time_queue.insert(tev, 
            // self.root_time 
            // + std::time::Duration::from_millis(11*(e as u64 - 1)*self.delta) +
             timeout
        );
    }

    pub(crate) fn _events_queue(&mut self) -> &mut VecDeque<Event> {
        &mut self.ev_queue
    }

    pub(crate) fn send_msg(&self, msg: OutMsg) 
    {
        if let Err(e) = self.net_send.send(msg) {
            log::error!("Error sending message: {}", e);
        }
    }
}