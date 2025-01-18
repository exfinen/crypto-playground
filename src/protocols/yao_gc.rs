#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::{
  gate_model::GateModel,
  circuit::Circuit,
  ot::{
    EncryptedWireLabels,
    OT,
    OTKeys,
  },
  wire_label::WireLabel,
};
use rsa::RsaPublicKey as PubKey;

#[derive(Clone)]
struct Input {
  index: usize,
  value: bool,
}

impl Input {
  pub fn new(index: usize, value: bool) -> Input {
    Input { index, value }
  }
}

struct P1 {
  circuit: Circuit,
  inputs: Vec<Input>,
}

impl P1 {
  pub fn new(
    inputs: Vec<Input>,
    gate_model: Box<GateModel>,
  ) -> P1 {
    P1 {
      circuit: P1::construct_circuit(gate_model),
      inputs,
    }
  }

  fn construct_circuit(gate_model: Box<GateModel>) -> Circuit {
    let K = 64;
    Circuit::new(&gate_model, K)
  }

  fn send_encrypted_wire_labels(
    &self,
    input_index: usize,
    ot_true_key: &PubKey,
    ot_false_key: &PubKey,
  ) -> EncryptedWireLabels {
    // encrypt true and false wire labels of the selected input wire
    let wire = self.circuit.get_input_wire(input_index);

    OT::encrypt_wire_labels(
      ot_true_key,
      ot_false_key,
      wire,
    )
  }
}

struct P2<'a> {
  circuit: &'a Circuit,
  inputs: Vec<Input>,
  ot_keys: OTKeys,
  circuit_inputs: Vec<WireLabel>,
}

impl<'a> P2<'a> {
  pub fn new(
    circuit: &'a Circuit,
    inputs: Vec<Input>,
    p1_input_len: usize,
  ) -> P2 {
    let ot_keys = P2::gen_ot_keys();
    let circuit_inputs: Vec<WireLabel> = vec![
      WireLabel::default(); 
      p1_input_len + inputs.len()
    ];

    P2 {
      circuit,
      inputs,
      ot_keys,
      circuit_inputs,
    }
  }

  pub fn gen_ot_keys() -> OTKeys {
    let rsa_bits = 1024;
    OT::gen_keys(rsa_bits)
  }

  pub fn set_input(&mut self, index: usize, wire_label: WireLabel) {
    self.circuit_inputs[index] = wire_label;
  }
}

pub fn run() -> () {
  // P1 and P2 both know the circuit structure
  /*
   Circuit:
             0|
            (2:Or)
          1/      2\
       (0:And)    (1:Or)
       3/   4\   5/    6\
Input: 0      1  2       3
  */
  let gate_model = 
    GateModel::int_or(
      GateModel::leaf_and(),
      GateModel::leaf_or(),
    );

  // P1 and P2 are in charge of inputs [0, 2] and [1, 3] respectively
  let p1_inputs = vec![
    Input::new(0, true),
    Input::new(2, false),
  ];
  let p2_inputs = vec![
    Input::new(1, false),
    Input::new(3, true),
  ];

  let p1 = P1::new(p1_inputs.clone(), gate_model);

  // P1 constructs the circuit with garbled tables and output decoding table
  // and passes it to P2
  let mut p2 = P2::new(&p1.circuit, p2_inputs.clone(), p1_inputs.len());

  // P1 sends active wire labels for its inputs to P2
  for p1_input in p1_inputs {
    let wire_label: &WireLabel = &p1.circuit
      .get_input_wire(p1_input.index)
      .get_label(p1_input.value);
    p2.circuit_inputs[p1_input.index] = wire_label.clone();
  }

  // P2 obtaines encrypted active wire labels for its inputs from P1 using OT
  for p2_input in p2_inputs {
    // use public key with secret key for the active wire P2 wants to obtain
    let (true_key, false_key) = {
      if p2_input.value {
        (&p2.ot_keys.pk_with_sk, &p2.ot_keys.pk_without_sk)
      } else {
        (&p2.ot_keys.pk_without_sk, &p2.ot_keys.pk_with_sk)
      }
    };

    // get both of the encrypted wire labels of the wire from P1
    let enc_wire_labels = p1.send_encrypted_wire_labels(
      p2_input.index,
      true_key,
      false_key,
    );

    // P2 decrypts the wire label of its interest
    let wire_label = OT::decrypt(
      if p2_input.value {
        &enc_wire_labels.true_label
      } else {
        &enc_wire_labels.false_label
      },
      &p2.ot_keys.sk,
    ).unwrap();

    // P2 sets the wire label as its input for the circuit
    p2.set_input(p2_input.index, wire_label);
  }

  // now P2 has all the inputs to the circuit and evaluates it
  let root_wire_label = p2.circuit.evaluate(p2.circuit_inputs.iter().collect());

  // P2 decode the root active wire label to obtain the evaluation result
  let circuit_eval_result =
    p2.circuit.output_decoding_table.decode(&root_wire_label);

  assert_eq!(circuit_eval_result, true);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_simple_circuit() {
    run();
  }
}
