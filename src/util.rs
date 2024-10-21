use rand::{RngCore, CryptoRng};

pub fn gen_random_binary_val<R: RngCore + CryptoRng>(mut rng: R) -> bool {
    if rng.next_u32() as u8 % 2 == 0 { false } else { true }
}

