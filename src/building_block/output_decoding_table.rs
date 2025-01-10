#![allow(dead_code)]

use crate::building_block::wires::Wires;
use sha3::{Sha3_256, Digest};

#[derive(Debug)]
pub struct OutputDecodingTable {
  pub table: [bool; 2],
}

impl OutputDecodingTable {
  fn compute_e(k: &Vec<u8>, j: &usize, v: bool) -> bool {
    let mut hasher = Sha3_256::new();

    hasher.update(k);
    hasher.update("out");
    hasher.update(&j.to_be_bytes());

    let hash: Vec<u8> = hasher.finalize().to_vec();
    let lsb = hash[hash.len() - 1]; 
    let lhs = if lsb % 2 == 1 { true } else { false };

    lhs ^ v
  }

  pub fn new(
    gate_id: usize,
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
        &gate_id,
        v_c,
      );

      let index = if e { 1 } else { 0 };
      table[index] = e;
    }

    OutputDecodingTable { table }
  }
}

