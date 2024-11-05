use crate::util::gen_random_binary_val;

#[derive(Debug)]
// K is the security parameter and determines the length of the key 
// For each wire i, there exist 2 wires w_i^0 and w_i^1
pub struct WireLabel<const K: usize> {
  pub id: usize,     // wire id
  pub k: [bool; K],  // key of length K
  pub p: bool,       // parity bit
}

impl<const K: usize> WireLabel<K> {
  pub fn new(id: usize, p: bool) -> Self {
    let k: [bool; K] =
      std::array::from_fn(|_| gen_random_binary_val());
    WireLabel { id, k, p }
  }

  pub fn serialize(self) -> [bool; K] {
    self.k
  }
}

