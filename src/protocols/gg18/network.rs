#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{
  Mutex,
  Notify,
};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct UnicastId {
  kind: u8,
  from: usize,
  to: usize,
}

impl UnicastId {
  pub fn new(kind: u8, from: usize, to: usize) -> Self {
    Self {
      kind,
      from,
      to,
    }
  }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct BroadcastId(pub u8);


type ValueType = Vec<u8>;
type BroadcastValues = Vec<ValueType>;
type UnicastValue = ValueType;

pub struct Network {
  num_parties: usize,
  broadcasts: Arc<Mutex<HashMap<BroadcastId,BroadcastValues>>>,
  unicasts: Arc<Mutex<HashMap<UnicastId,UnicastValue>>>,
  data_added: Arc<Notify>,
}

impl Network {
  pub fn new(num_parties: usize) -> Self {
    Self {
      num_parties,
      broadcasts: Arc::new(Mutex::new(HashMap::new())),
      unicasts: Arc::new(Mutex::new(HashMap::new())),
      data_added: Arc::new(Notify::new()),
    }
  }

  pub async fn broadcast(
    &self,
    id: &BroadcastId,
    value: ValueType,
  ) {
    let mut broadcasts = self.broadcasts.lock().await;
    if broadcasts.contains_key(id) {
      if broadcasts.get(id).unwrap().len() <= self.num_parties {
        broadcasts.get_mut(id).unwrap().push(value);
      } else {
        panic!("Unexpected number of Broadcasts for {:?}", id);
      }

    } else {
      broadcasts.insert(id.clone(), vec![value]);
    }
    self.data_added.notify_waiters();
  }

  pub async fn receive_broadcasts(
    &self,
    id: BroadcastId,
  ) -> BroadcastValues {
    // wait until the number of received broadcasts reaches to num_parties
    loop {
      let broadcasts = self.broadcasts.lock().await;
      if broadcasts.get(&id).unwrap().len() == self.num_parties {
        return broadcasts.get(&id).unwrap().clone()
      }
      drop(broadcasts);
      self.data_added.notified().await;
    }
  }

  pub async fn unicast(&mut self, id: &UnicastId, data: UnicastValue) {
    let mut unicasts = self.unicasts.lock().await;
    if !unicasts.contains_key(&id) {
      unicasts.insert(id.clone(), data);
    } else {
      panic!("Multiple Unicasts found for {:?}", id);
    }
    self.data_added.notify_waiters();
  }

  pub async fn receive_unicast(&self, id: &UnicastId) -> UnicastValue {
    // wait until unicast is received
    loop {
      let unicasts = self.unicasts.lock().await;
      if unicasts.contains_key(&id) { 
        return unicasts.get(&id).unwrap().clone();
      }
      drop(unicasts);
      self.data_added.notified().await;
    }
  }
}

