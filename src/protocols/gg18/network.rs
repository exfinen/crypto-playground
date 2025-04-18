#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{
  Mutex,
  Notify,
};
use serde::{
  de::DeserializeOwned,
  Serialize,
};

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct UnicastId(pub u8);

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct UnicastDest {
  id: UnicastId,
  from: u32,
  to: u32,
  value_id: ValueId,
}

impl UnicastDest {
  pub fn new(
    id: UnicastId,
    from: u32,
    to: u32,
    value_id: ValueId,
  ) -> Self {
    Self {
      id,
      from,
      to,
      value_id,
    }
  }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct BroadcastId(pub u8);

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct ValueId(pub u8);

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

  pub async fn broadcast<V>(
    &self,
    id: &BroadcastId,
    value: &V,
  ) where 
    V: Serialize, 
  {
    let mut broadcasts = self.broadcasts.lock().await;
    let ser_value = bincode::serialize(value).unwrap();

    if broadcasts.contains_key(id) {
      if broadcasts.get(id).unwrap().len() <= self.num_parties {
        broadcasts.get_mut(id).unwrap().push(ser_value);
      } else {
        panic!("Unexpected number of Broadcasts for {:?}", id);
      }

    } else {
      broadcasts.insert(id.clone(), vec![ser_value]);
    }
    self.data_added.notify_waiters();
  }

  pub async fn broadcast_with_index<I, V>(
    &self,
    id: &BroadcastId,
    index: I,
    value: &V,
  ) where 
    I: Into<u32>,
    V: Serialize, 
  {
    let indexed_value = (index.into(), value);
    self.broadcast(
      id,
      &indexed_value,
    ).await;
  }

  pub async fn receive_broadcasts<V>(
    &self,
    id: &BroadcastId,
  ) -> Vec<V>
  where
      V: DeserializeOwned,
  {
    // wait until the number of received broadcasts reaches to num_parties
    let broadcasts = loop {
      let broadcasts = self.broadcasts.lock().await;
      if broadcasts.get(id).unwrap().len() == self.num_parties {
        break broadcasts.get(&id).unwrap().clone();
      }
      drop(broadcasts);
      self.data_added.notified().await;
    };
    broadcasts
      .iter()
      .map(|x| bincode::deserialize(x).unwrap())
      .collect()
  }

  pub async fn receive_idx_broadcasts<V>(
    &self,
    id: &BroadcastId,
  ) -> Vec<V>
  where
      (u32, V): DeserializeOwned,
  {
    let mut idx_ser_vec: Vec<(u32, V)> = self.receive_broadcasts(id).await;

    // sort by index and return only values
    idx_ser_vec.sort_by_key(|(i, _)| *i);
    idx_ser_vec.into_iter().map(|(_, v)| v).collect()
  }

  pub async fn unicast<V>(
    &self,
    dest: &UnicastDest,
    value: &V,
  ) where 
    V: Serialize, 
  {
    let mut unicasts = self.unicasts.lock().await;
    if !unicasts.contains_key(&dest) {
      let ser_value = bincode::serialize(value).unwrap();
      unicasts.insert(dest.clone(), ser_value);
    } else {
      panic!("Multiple Unicasts found for destination {:?}", dest);
    }
    self.data_added.notify_waiters();
  }

  pub async fn receive_unicast<V>(
    &self,
    dest: &UnicastDest,
  ) -> V
  where
      V: DeserializeOwned,
  {
    // wait until unicast is received
    loop {
      let mut unicasts = self.unicasts.lock().await;
      if unicasts.contains_key(&dest) { 
        let ser_value = unicasts.get(&dest).unwrap().clone();
        unicasts.remove(&dest).unwrap();
        let value = bincode::deserialize(&ser_value).unwrap();
        return value;
      }
      drop(unicasts);
      self.data_added.notified().await;
    }
  }
}

