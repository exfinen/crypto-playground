#![allow(dead_code)]

use crate::building_block::{
  gate_type::GateType,
  garbled_table::GarbledTable,
};

#[derive(Debug)]
pub struct Gate {
  pub index: usize,
  pub gate_type: GateType,
  pub out: usize,
  pub left: usize,
  pub right: usize,
  pub garbled_table: GarbledTable,
}

impl Gate {
  pub fn new(
    index: usize,
    gate_type: &GateType,
    out: usize,
    left: usize,
    right: usize,
    garbled_table: GarbledTable,
  ) -> Self {
    let gate = Gate {
      index,
      gate_type: gate_type.clone(),
      left,
      right,
      out,
      garbled_table,
    };
    gate
  }
}

