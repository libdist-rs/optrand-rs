use std::{collections::VecDeque, task::Poll, time::Duration};

use futures::{Stream, StreamExt};
use tokio_util::time::DelayQueue;
use crate::events::{Event, TimeOutEvent};

pub(crate) struct EventQueue {
    time_queue: DelayQueue<TimeOutEvent>,
    ev_queue: VecDeque<Event>,
}

impl Stream for EventQueue {
    type Item = Event;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.time_queue.is_empty() {
            if let Poll::Ready(Some(Ok(x))) = self.time_queue.poll_next_unpin(cx) {
                return Poll::Ready(Some(Event::TimeOut(x.into_inner())));
            }
        }
        if let Some(x) = self.ev_queue.pop_front() {
            return Poll::Ready(Some(x));
        }
        Poll::Pending
    }
}

impl EventQueue {
    /// The size parameter defines the initial sizes for the event queue and the timer queue
    pub fn with_capacity(size: usize) -> Self {
        Self {
            time_queue: DelayQueue::with_capacity(size),
            ev_queue: VecDeque::with_capacity(size),
        }
    }

    pub fn add_event(&mut self, ev: Event) {
        self.ev_queue.push_back(ev);
    }

    pub fn add_timeout(&mut self, tev: TimeOutEvent, timeout: Duration) {
        self.time_queue.insert(tev, timeout);
    }

    pub fn events_queue(&mut self) -> &mut VecDeque<Event> {
        &mut self.ev_queue
    }
}