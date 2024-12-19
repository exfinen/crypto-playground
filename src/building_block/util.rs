use rand::{
  rngs::OsRng,
  RngCore,
};

pub fn gen_random_binary_val() -> bool {
  if OsRng.next_u32() as u8 % 2 == 0 { false } else { true }
}

pub fn get_num_wires(depth: usize) -> usize {
  (1 << (depth + 1)) - 1
}

pub fn get_num_nodes(depth: usize) -> usize {
  get_num_wires(depth - 1)
}

pub fn xor_vecs(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
  let v1_len = v1.len();
  let v2_len = v2.len();
  let mut v1 = v1.clone();
  let mut v2 = v2.clone();

  // Pad the shorter vector with zeros at the front
  if v1_len < v2_len {
    let padding = vec![0; v2_len - v1_len];
    v1.splice(0..0, padding);
  } else if v1_len > v2_len {
    let padding = vec![0; v1_len - v2_len];
    v2.splice(0..0, padding);
  }
  v1.iter()
    .zip(v2.iter())
    .map(|(a, b)| a ^ b)
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_get_num_wires() {
    assert!(get_num_wires(0) == 1);  // 2^0 = 1
    assert!(get_num_wires(1) == 3);  // 2^1 = 2
    assert!(get_num_wires(2) == 7);  // 2^3 = 8
    assert!(get_num_wires(3) == 15); // 2^4 = 16
    assert!(get_num_wires(4) == 31); // 2^5 = 32
  }
}
