use rand::{
  rngs::OsRng,
  RngCore,
};

pub fn gen_random_binary_val() -> bool {
  if OsRng.next_u32() as u8 % 2 == 0 { false } else { true }
}

