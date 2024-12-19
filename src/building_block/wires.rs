#![allow(non_snake_case)]

use crate::building_block::wire::Wire;
use std::collections::HashSet;

pub struct Wires {
  pub K: usize,
  pub wires: Vec<Wire>,
  input_wires: HashSet<usize>,
}

impl Wires {
  pub fn new(K: usize) -> Self {
    Wires { 
      K,
      wires: Vec::new(),
      input_wires: HashSet::new(),
    }
  }

  pub fn create(&mut self, is_input: bool) -> usize {
    let index = self.wires.len();
    let wire = Wire::new(self.K, index);
    self.wires.push(wire);

    if is_input {
      self.input_wires.insert(index);
    }
    index
  }

  pub fn get(&self, index: usize) -> &Wire {
    &self.wires[index]
  }
}
