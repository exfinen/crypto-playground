#![allow(dead_code)]

use crate::building_block::secp256k1::scalar::Scalar;

pub struct Signature {
  pub r: Scalar,
  pub s: Scalar,
}

