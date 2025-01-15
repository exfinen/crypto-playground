#![allow(dead_code)]

use crate::building_block::{
  util::xor_vecs,
  wire_label::WireLabel,
  wires::Wires,
};
use sha3::{Sha3_256, Digest};
use bincode;

#[derive(Debug)]
pub struct GarbledTable {
  table: [Vec<u8>; 4],
}

impl GarbledTable {
  pub fn compute_hash_lhs(
    k_a: &Vec<u8>,
    k_b: &Vec<u8>,
    gate_id: &usize,
  ) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(k_a);
    hasher.update(k_b);
    hasher.update(gate_id.to_be_bytes());
    hasher.finalize().to_vec()
  }

  pub fn compute_hash(
    k_a: &Vec<u8>,
    k_b: &Vec<u8>,
    gate_id: &usize,
    out_label: &WireLabel,
  ) -> Vec<u8> {
    let lhs = Self::compute_hash_lhs(k_a, k_b, gate_id);
    let rhs = bincode::serialize(out_label).unwrap();
    xor_vecs(&lhs, &rhs)
  }

  pub fn new<F>(
    gate_id: usize,
    out: usize,
    left: usize,
    right: usize,
    func: F,
    wires: &Wires,
  ) -> Self
  where
    F: Fn(bool, bool) -> bool,
  {
    let mut table: [Vec<u8>; 4] = [
      Vec::new(),
      Vec::new(),
      Vec::new(),
      Vec::new(),
    ];

    let out = wires.get(out);
    let left = wires.get(left);
    let right = wires.get(right);

    // for all combination of v_a and v_b
    for v_a in [false, true] {
      for v_b in [false, true] {
        // get labels
        let a_label = &left.get_label(v_a);
        let b_label = &right.get_label(v_b);

        // compute the gate function and get the out label
        let v_c = func(v_a, v_b);
        let c_label = &out.get_label(v_c);

        // compute e
        let e = Self::compute_hash(
          &a_label.k,
          &b_label.k,
          &gate_id,
          &c_label,
        );

        // store e in the table so that es are sorted based on p_a and p_b
        let p_a = a_label.p as usize;
        let p_b = b_label.p as usize;
        let index: usize = (p_a << 1) | p_b;
        table[index] = e;
      }
    }
    GarbledTable { table }
  }

  // returns the seralized output label
  pub fn evaluate(
    &self,
    gate_id: &usize,
    left: &WireLabel,
    right: &WireLabel,
  ) -> WireLabel {
    // look up the table to get the encoded output wire label
    let i = (left.p as usize) << 1 | (right.p as usize);
    let enc_out_wire_label = &self.table[i];

    // decode the output wire label
    let hash_lhs: Vec<u8> = Self::compute_hash_lhs(
      &left.k,
      &right.k,
      gate_id,
    );
    let ser_out_wire_label = xor_vecs(&hash_lhs, enc_out_wire_label);

    let out_wire_label: WireLabel =
      bincode::deserialize(&ser_out_wire_label).unwrap();

    out_wire_label
  }
}

