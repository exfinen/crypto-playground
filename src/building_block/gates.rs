use crate::building_block::{
  garbled_table::GarbledTable,
  gate::Gate,
  gate_type::GateType,
  output_decoding_table::OutputDecodingTable,
};

pub struct Gates {
  pub gates: Vec<Gate>,
}

impl Gates {
  pub fn new() -> Self {
    Gates {
      gates: Vec::new(),
    }
  }

  pub fn create(
    &mut self,
    gate_type: &GateType,
    out: usize,
    left: usize,
    right: usize,
    garbled_table: GarbledTable,
    output_decoding_table: OutputDecodingTable,
  ) -> usize {
    let index = self.gates.len();

    let gate = Gate::new(
      index,
      gate_type,
      out,
      left,
      right,
      garbled_table,
      output_decoding_table,
    );
    self.gates.push(gate);

    index
  }

  pub fn get(&self, index: usize) -> &Gate {
    &self.gates[index]
  }

  pub fn next_index(&self) -> usize {
    self.gates.len()
  }
}

