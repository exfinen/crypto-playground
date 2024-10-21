use rand::rngs::OsRng;
use crate::util::gen_random_binary_val;

#[derive(Debug)]
pub struct WireLabel<const K: usize> {
  pub k: [bool; K],
  pub p: bool,
}

impl<const K: usize> WireLabel<K> {
  pub fn new(p: bool) -> Self {
    let k: [bool; K] =
      std::array::from_fn(|_| gen_random_binary_val(OsRng));
    WireLabel { k, p }
  }
}

