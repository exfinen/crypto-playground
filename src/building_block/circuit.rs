#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::{
  garbled_table::GarbledTable,
  gate::Gate,
  gates::Gates,
  gate_type::GateType,
  gate_model::{GateModel, GateModelBody},
  output_decoding_table::OutputDecodingTable,
  wire::Wire,
  wire_label::WireLabel,
  wires::Wires,
};

#[derive(Debug)]
pub struct Circuit {
  pub root_gate_index: usize,
  pub output_decoding_table: OutputDecodingTable,
  input_wires: Vec<usize>,
  wires: Wires,
  gates: Gates,
}

impl Circuit {
  fn gen_leaf_gate(
    gate_type: &GateType,
    out_wire: usize,
    left_wire: usize,
    right_wire: usize,
    gates: &mut Gates,
    wires: &mut Wires,
    input_wires: &mut Vec<usize>,
  ) -> usize {
    let garbled_table = GarbledTable::new(
      gates.next_index(),
      out_wire,
      left_wire,
      right_wire,
      GateType::func(gate_type),
      wires,
    );
    input_wires.push(left_wire);
    input_wires.push(right_wire);

    gates.create(
      gate_type,
      out_wire,
      left_wire,
      right_wire,
      garbled_table,
    )
  }

  fn gen_internal_gate(
    gate_type: &GateType,
    K: usize,
    left_model: &GateModel,
    right_model: &GateModel,
    out_wire: usize,
    left_wire: usize,
    right_wire: usize,
    gates: &mut Gates,
    wires: &mut Wires,
    input_wires: &mut Vec<usize>,
  ) -> usize {
    Self::build(
      K,
      left_model,
      left_wire,
      gates,
      wires,
      input_wires,
    );
    Self::build(
      K,
      right_model,
      right_wire,
      gates,
      wires,
      input_wires,
    );
    let garbled_table = GarbledTable::new(
      gates.next_index(),
      out_wire,
      left_wire,
      right_wire,
      GateType::func(&gate_type),
      wires,
    );
    gates.create(
      gate_type,
      out_wire,
      left_wire,
      right_wire,
      garbled_table,
    )
  }

  fn build(
    K: usize,
    gate_model: &GateModel,
    out_wire: usize,
    gates: &mut Gates,
    wires: &mut Wires,
    input_wires: &mut Vec<usize>,
  ) -> usize {
    let left_wire = wires.create(false);
    let right_wire = wires.create(false);

    match gate_model {
      // Internal And
      GateModel::And(GateModelBody::Models(left_model, right_model)) => {
        Self::gen_internal_gate(
          &GateType::And,
          K,
          left_model,
          right_model,
          out_wire,
          left_wire,
          right_wire,
          gates,
          wires,
          input_wires,
        )
      },
      // Leaf And
      GateModel::And(GateModelBody::Values) => {
        Self::gen_leaf_gate(
          &GateType::And,
          out_wire,
          left_wire,
          right_wire,
          gates,
          wires,
          input_wires,
        )
      },
      // Internal Or
      GateModel::Or(GateModelBody::Models(left_model, right_model)) => {
        Self::gen_internal_gate(
          &GateType::Or,
          K,
          left_model,
          right_model,
          out_wire,
          left_wire,
          right_wire,
          gates,
          wires,
          input_wires,
        )
      },
      // Leaf Or
      GateModel::Or(GateModelBody::Values) => {
        Self::gen_leaf_gate(
          &GateType::Or,
          out_wire,
          left_wire,
          right_wire,
          gates,
          wires,
          input_wires,
        )
      },
    }
  }

  pub fn get_input_wire(&self, index: usize) -> &Wire {
    let wire_index = self.input_wires[index];
    self.wires.get(wire_index)
  } 

  fn get_gate_with_wires(&self, left: usize, right: usize) -> &Gate {
    for gate in &self.gates {
      if gate.left == left && gate.right == right {
        return gate;
      }
    }
    panic!("Gate with left={} and right={} not found. Check code.", left, right);
  }

  pub fn evaluate(&self, inputs: Vec<&WireLabel>) -> WireLabel {
    let mut eval_wire_labels = Vec::<WireLabel>::new();
    for input in inputs {
      eval_wire_labels.push(input.clone());
    }

    while eval_wire_labels.len() >= 2 {
      // get gate
      let left = eval_wire_labels.remove(0);
      let right = eval_wire_labels.remove(0);
      let gate = self.get_gate_with_wires(left.wire_index, right.wire_index);

      // evaluate gate
      let out_wire_label = gate.garbled_table.evaluate(
        &gate.index,
        &left,
        &right,
      );

      let root_out_wire = self.gates.get(self.root_gate_index).out;

      if out_wire_label.wire_index == root_out_wire {
        // if the output wire is the root wire,
        // return the WireLabel corresponding to the evaluation result
        return out_wire_label;

      } else {
        // otherwise, add the output wire_label to input wire label list
        eval_wire_labels.push(out_wire_label);
      }
    }
    panic!("Malformed circuit found. Check code.");
  }

  pub fn new(
    root_gate_model: &GateModel,
    K: usize,
  ) -> Self {
    let mut gates = Gates::new();
    let mut wires = Wires::new(K);
    let mut input_wires = Vec::<usize>::new();
    let root_out_wire = wires.create(false);

    let root_gate_index = Self::build(
      K,
      root_gate_model,
      root_out_wire,
      &mut gates,
      &mut wires,
      &mut input_wires,
    );

    let output_decoding_table = OutputDecodingTable::new(
      root_out_wire,
      &mut wires,
    );

    Circuit {
      root_gate_index,
      output_decoding_table,
      input_wires,
      gates,
      wires,
    }
  }
}

