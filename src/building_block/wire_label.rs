use crate::building_block::util::gen_random_binary_val;

#[derive(Debug)]
pub struct WireLabel {
  pub b: bool,
  pub k: Vec<u8>,  // key of length K
  pub p: bool,     // parity bit
}

impl WireLabel {
  pub fn new(b: bool, p: bool, k: usize) -> Self {
    let k: Vec<u8> = std::iter::repeat_with(|| gen_random_binary_val() as u8)
      .take(k)
      .collect();
    WireLabel { b, k, p }
  }

  pub fn serialize(&self) -> &Vec<u8> {
    &self.k
  }
}
