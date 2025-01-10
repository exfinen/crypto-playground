#![allow(non_snake_case)]

use crate::building_block::{
  gate_model::GateModel,
  circuit::Circuit,
  ot::OT,
  wire::Wire,
};

pub fn run() -> () {
  /*
   Circuit:
          6|
        (2:Or)
       4/     5\
    (0:And)  (1:Or)
    0/   1\  2/  3\
   T       F F     T
   */

  // P1 constructs circuit
  let gate_model = 
    GateModel::int_or(
      GateModel::leaf_and(),
      GateModel::leaf_or(),
    );

  let K = 64;
  let circuit = Circuit::new(&gate_model, K);

  // P1 has inputs for wire 0 (true) and 2 (false)
  // P2 has inputs for wire 1 (false) and 3 (true)
 
  // P2 gets keys for wire 1 and 3 via OT
  let rsa_bits = 1024;
  let ot_keys = OT::gen_keys(rsa_bits);

  // P2 gets active input wire for wire 1 and 3 via OT

  // P2 sends two public keys to P1 to let P1 encrypt the wire labels
  // for wire 1, P2 wants wire label for false

  let wire1_active_label: Wire = {
    // OT of false wire label of wire 1

    let false_pubkey = &ot_keys.pk;
    let true_pubkey = &ot_keys.pk_prime;

    // P1 encrypts wire labels of wire 1 and sends them to P2
    let wire = circuit.get_input_wire(1);
    let (enc_false_wire_label, enc_true_wire_label) =
      OT::encrypt_wire_labels(
        false_pubkey,
        true_pubkey,
        wire,
      );

    // P2 wants false wire label and decrypts false one only
    OT::decrypt(&enc_false_wire_label, &ot_keys.sk)
  };

  let wire3_active_label: Wire = {
    // OT of true wire label of wire 3

    let false_pubkey = &ot_keys.pk_prime;
    let true_pubkey = &ot_keys.pk;

    // P1 encrypts wire labels of wire 3 and sends them to P2
    let wire = circuit.get_input_wire(3);
    let (enc_false_wire_label, enc_true_wire_label) =
      OT::encrypt_wire_labels(
        false_pubkey,
        true_pubkey,
        wire,
      );

    // P2 wants false wire label and decrypts false one only
    OT::decrypt(&enc_false_wire_label, &ot_keys.sk)
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
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test1() {
    run();
  }
}
