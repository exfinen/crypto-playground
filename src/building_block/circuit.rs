#![allow(non_snake_case)]

use crate::building_block::{
  garbled_table::GarbledTable,
  gates::Gates,
  gate_type::GateType,
  gate_model::GateModel,
  output_decoding_table::OutputDecodingTable,
  wires::Wires,
};

#[derive(Debug)]
pub struct Circuit {
  pub root: usize,
}

impl Circuit {
  fn build_leaf_gate(
    gate_model: &GateModel,
    out_index: usize,
    gates: &mut Gates,
    wires: &mut Wires,
  ) -> usize {
    let left_index = wires.create(true);
    let right_index = wires.create(true);

    let garbled_table = GarbledTable::new(
      gates.next_index(),
      out_index,
      left_index,
      right_index,
      GateType::func(&gate_model.gate_type),
      wires,
    );
    let output_decoding_table = OutputDecodingTable::new(
      gates.next_index(),
      out_index,
      wires,
    );

    gates.create(
      &gate_model.gate_type,
      out_index,
      left_index,
      right_index,
      garbled_table,
      output_decoding_table,
    )
  }

  fn build_internal_gate(
    K: usize,
    gate_model: &GateModel,
    out_index: usize,
    gates: &mut Gates,
    wires: &mut Wires,
  ) -> usize {
    let left_index = wires.create(false);
    let right_index = wires.create(false);

    // recursively build left and right sub-circuits
    let left_gate = Self::build(
      K,
      gate_model.left.as_ref().unwrap(),
      left_index,
      gates,
      wires,
    );
    
    let right_gate = Self::build(
      K,
      gate_model.right.as_ref().unwrap(),
      right_index,
      gates,
      wires,
    );

    let garbled_table = GarbledTable::new(
      gates.next_index(),
      out_index,
      left_gate,
      right_gate,
      GateType::func(&gate_model.gate_type),
      wires,
    );
    let output_decoding_table = OutputDecodingTable::new(
      gates.next_index(),
      out_index,
      wires,
    );

    gates.create(
      &gate_model.gate_type,
      out_index,
      left_gate,
      right_gate,
      garbled_table,
      output_decoding_table,
    )
  }

  fn build(
    K: usize,
    gate_model: &GateModel,
    out_index: usize,
    gates: &mut Gates,
    wires: &mut Wires,
  ) -> usize {
    // if the gate is internal gate
    if gate_model.left.is_some() && gate_model.right.is_some() {
      Self::build_internal_gate(
        K,
        gate_model,
        out_index,
        gates,
        wires,
      )
    // if the gate is leaf gate
    } else if gate_model.left.is_none() && gate_model.right.is_none() {
      Self::build_leaf_gate(
        gate_model,
        out_index,
        gates,
        wires,
      )
    } else {
      panic!("Malformed gate model. Either both children should exist or missing.");
    }
  }

  pub fn new(
    root_gate_model: &GateModel,
    K: usize,
    gates: &mut Gates,
    wires: &mut Wires,
  ) -> Self {
    let root_out_index = wires.create(false);
    let root = Self::build(
      K,
      root_gate_model,
      root_out_index,
      gates,
      wires,
    );

    Circuit {
      root,
    }
  }
}

