use rand::{
  rngs::OsRng,
  RngCore,
};
use rug::{
  integer::IsPrime, rand::{MutRandState, RandState}, Complete, Integer
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

  // Pad the shorter vector with zeros at the end
  if v1_len < v2_len {
    let padding = vec![0; v2_len - v1_len];
    v1.extend(padding);
  } else if v1_len > v2_len {
    let padding = vec![0; v1_len - v2_len];
    v2.extend(padding);
  }
  v1.iter()
    .zip(v2.iter())
    .map(|(a, b)| a ^ b)
    .collect()
}

pub fn get_32_byte_rng<'a>() -> RandState<'a> {
  let mut rng = RandState::new();
  let seed = {
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    Integer::from_digits(&random_bytes, rug::integer::Order::Msf)
  };
  rng.seed(&seed);
  rng
}

pub fn gen_random_number(
  num_bits: u32,
  rng: &mut dyn MutRandState,
) -> Integer {
  Integer::random_bits(num_bits, rng).complete()
}

pub fn gen_random_prime(
  num_bits: u32,
  rng: &mut dyn MutRandState,
) -> Integer {
  let mut n = gen_random_number(num_bits, rng);
  if n.is_even() {
    n += 1;
  }
  n.next_prime()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::building_block::wire_label::WireLabel;
  use crate::building_block::garbled_table::GarbledTable;

  fn are_vecs_equal(v1: &Vec<u8>, v2: &Vec<u8>) -> bool {
    let v1_len = v1.len();
    let v2_len = v2.len();
    let mut v1 = v1.clone();
    let mut v2 = v2.clone();

    // Pad the shorter vector with zeros at the end
    if v1_len < v2_len {
      let padding = vec![0; v2_len - v1_len];
      v1.extend(padding);
    } else if v1_len > v2_len {
      let padding = vec![0; v1_len - v2_len];
      v2.extend(padding);
    }
    v1 == v2
  }
 
  #[test]
  fn test_get_num_wires() {
    assert!(get_num_wires(0) == 1);  // 2^0 = 1
    assert!(get_num_wires(1) == 3);  // 2^1 = 2
    assert!(get_num_wires(2) == 7);  // 2^3 = 8
    assert!(get_num_wires(3) == 15); // 2^4 = 16
    assert!(get_num_wires(4) == 31); // 2^5 = 32
  }

  #[test]
  fn test_xor_vecs_same_inputs() {
    let k = 64;
    let left = WireLabel::new(1, false, true, k);
    let right = WireLabel::new(2, false, false, k);
    let out = WireLabel::new(3, true, false, k);

    let gate_id = 9;
    let lhs = GarbledTable::compute_hash(
      &left.k,
      &right.k,
      &gate_id,
      &out,
    );
    let zero_vec = xor_vecs(&lhs, &lhs);
    assert_eq!(zero_vec, vec![0; zero_vec.len()]);
  }

  #[test]
  fn test_xor_vecs_enc_wire() {
    let k = 64;
    let left = WireLabel::new(1, false, true, k);
    let right = WireLabel::new(2, false, false, k);
    let out = WireLabel::new(3, true, false, k);

    let gate_id = 9;
    let lhs = GarbledTable::compute_hash_lhs(
      &left.k,
      &right.k,
      &gate_id,
    );
    let ser_out = bincode::serialize(&out).unwrap();
    let enc = xor_vecs(&lhs, &ser_out);
    let dec = xor_vecs(&lhs, &enc);
    assert!(are_vecs_equal(&dec, &ser_out));
  }
}
