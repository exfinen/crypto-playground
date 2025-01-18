#![allow(dead_code)]

use crate::building_block::{
  wires::Wires,
  wire_label::WireLabel,
};
use sha3::{Sha3_256, Digest};

#[derive(Debug)]
pub struct OutputDecodingTable {
  pub table: [bool; 2],
}

impl OutputDecodingTable {
  fn compute_e_lhs(k: &Vec<u8>, j: &usize) -> bool {
    let mut hasher = Sha3_256::new();

    hasher.update(k);
    hasher.update("out");
    hasher.update(&j.to_be_bytes());

    let hash = hasher.finalize().to_vec();
    let lsb = hash[hash.len() - 1]; 
    lsb % 2 == 1
  }

  fn compute_e(k: &Vec<u8>, j: &usize, v: bool) -> bool {
    let lhs = Self::compute_e_lhs(k, j);
    lhs ^ v
  }

  pub fn decode(&self, wire_label: &WireLabel) -> bool {
    let lhs = Self::compute_e_lhs(
      &wire_label.k,
      &wire_label.wire_index,
    );
    let e = self.table[wire_label.p as usize];
    e ^ lhs
  }

  pub fn new(
    out: usize,
    wires: &Wires,
  ) -> Self {
    let mut table: [bool; 2] = [
      false,
      false,
    ];

    let out = wires.get(out);

    // for all possible v_c
    for v_c in [false, true] {
      // get corresnponding label
      let c_label = out.get_label(v_c);

      // compute e
      let e = Self::compute_e(
        &c_label.k,
        &out.index,
        v_c,
      );

      let index = out.get_label(v_c).p as usize;
      table[index] = e;
    }

    OutputDecodingTable { table }
  }
}

