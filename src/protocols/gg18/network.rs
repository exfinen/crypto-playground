#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{
  Mutex,
  Notify,
};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct UnicastId(pub u8);

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct UnicastDest {
  id: UnicastId,
  from: u32,
  to: u32,
}

impl UnicastDest {
  pub fn new(id: UnicastId, from: u32, to: u32) -> Self {
    Self {
      id,
      from,
      to,
    }
  }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct BroadcastId(pub u8);

type ValueType = Vec<u8>;
type BroadcastValues = Vec<ValueType>;

pub struct Network {
  num_parties: usize,
  broadcasts: Arc<Mutex<HashMap<BroadcastId,BroadcastValues>>>,
  unicasts: Arc<Mutex<HashMap<UnicastDest,ValueType>>>,
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
    value: &ValueType,
  ) {
    let mut broadcasts = self.broadcasts.lock().await;
    if broadcasts.contains_key(id) {
      if broadcasts.get(id).unwrap().len() <= self.num_parties {
        broadcasts.get_mut(id).unwrap().push(value.clone());
      } else {
        panic!("Unexpected number of Broadcasts for {:?}", id);
      }

    } else {
      broadcasts.insert(id.clone(), vec![value.clone()]);
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

  pub async fn unicast(
    &self,
    dest: &UnicastDest,
    value: &ValueType,
  ) {
    let mut unicasts = self.unicasts.lock().await;
    if !unicasts.contains_key(&dest) {
      unicasts.insert(dest.clone(), value.clone());
    } else {
      panic!("Multiple Unicasts found for destination {:?}", dest);
    }
    self.data_added.notify_waiters();
  }

  pub async fn receive_unicast(&self, dest: &UnicastDest) -> ValueType {
    // wait until unicast is received
    loop {
      let unicasts = self.unicasts.lock().await;
      if unicasts.contains_key(&dest) { 
        return unicasts.get(&dest).unwrap().clone();
      }
      drop(unicasts);
      self.data_added.notified().await;
    }
  }
}

