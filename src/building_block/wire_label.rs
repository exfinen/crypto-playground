use crate::building_block::util::gen_random_binary_val;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireLabel {
  pub wire_index: usize,
  pub b: bool,
  pub k: Vec<u8>,  // key of length K
  pub p: bool,     // parity bit
}

impl WireLabel {
  pub fn new(wire_index: usize, b: bool, p: bool, key_size: usize) -> Self {
    let k: Vec<u8> = std::iter::repeat_with(|| gen_random_binary_val() as u8)
      .take(key_size)
      .collect();
    WireLabel { wire_index, b, k, p }
  }
}
