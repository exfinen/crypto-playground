#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::{
  gate_model::GateModel,
  circuit::Circuit,
  ot::OT,
  wire_label::WireLabel,
};

pub fn run() -> () {
  /*
   Circuit:
             0|
            (2:Or)
          1/      2\
       (0:And)    (1:Or)
       3/   4\   5/    6\
       T      F  F       T
Input: 0      1  2       3
   */

  // P1 constructs circuit
  let gate_model = 
    GateModel::int_or(
      GateModel::leaf_and(),
      GateModel::leaf_or(),
    );

  let K = 64;
  let circuit = Circuit::new(&gate_model, K);

  // P1 has inputs for wire 0 (true) and 1 (false)
  // P2 has inputs for wire 2 (false) and 3 (true)
 
  // P2 gets keys for wire 1 and 3 via OT from P1
  let rsa_bits = 1024;
  let ot_keys = OT::gen_keys(rsa_bits);

  // P2 gets active input wire for wire 1 and 3 via OT

  // P2 sends two public keys to P1 to let P1 encrypt the wire labels
  // for input wire 1, P2 wants wire label for false

  let wire1_active_label: WireLabel = {
    // P1 encrypts wire labels of wire 1 and sends them to P2
    let wire = circuit.get_input_wire(1);
    let (_, enc_false_wire_label) =
      OT::encrypt_wire_labels(
        &ot_keys.pk_without_sk, // true
        &ot_keys.pk_with_sk,    // false; (P2 needs this)
        wire,
      );

    // P2 decrypts false wire label
    OT::decrypt(&enc_false_wire_label, &ot_keys.sk).unwrap()
  };

  let wire3_active_label: WireLabel = {
    // OT of true wire label of wire 3

    // P1 encrypts wire labels of wire 3 and sends them to P2
    let wire = circuit.get_input_wire(3);
    let (enc_true_wire_label, _) =
      OT::encrypt_wire_labels(
        &ot_keys.pk_with_sk,    // true; (P2 needs this)
        &ot_keys.pk_without_sk, // false
        wire,
      );

    // P2 decrypts true wire label
    OT::decrypt(&enc_true_wire_label, &ot_keys.sk).unwrap()
  };

  // P1 sends active label for wire 0 and 2 to P2
  let wire0_active_label = circuit.get_input_wire(0).get_label(true);
  let wire2_active_label = circuit.get_input_wire(2).get_label(false);

  // P2 evaluates the circuit with the leaf active labels
  let root_wire_label = circuit.evaluate(vec![
    wire0_active_label,
    &wire1_active_label,
    wire2_active_label,
    &wire3_active_label,
  ]); 

  // P2 gets the active value associated with the root active label
  // using output_decoding_table
  let circuit_eval_result =
    circuit.output_decoding_table.decode(&root_wire_label);

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
