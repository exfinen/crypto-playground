#![allow(dead_code)]
#![allow(non_snake_case)]

use std::fmt;
use crate::building_block::secp256k1::{
  affine_point::AffinePoint,
  jacobian_point::JacobianPoint,
  scalar::Scalar,
};

#[derive(Clone)]
pub struct Signature {
  pub r: Scalar,
  pub s: Scalar,
}

impl Signature {
  pub fn new(r: &Scalar, s: &Scalar) -> Self {
    Self {
      r: r.clone(),
      s: s.clone(),
    }
  }

  pub fn verify(
    &self,
    pk: &JacobianPoint,
    M: &Scalar,
    hasher: impl Fn(&Scalar) -> Scalar,
  ) -> bool {
    let m = hasher(M);
    let u1 = &self.s.inv() * m;
    let u2 = &self.s.inv() * &self.r;

    let g = JacobianPoint::get_base_point();
    let R_pt = g * u1 + pk * u2;
    let R_pt: AffinePoint = R_pt.into();
    let r_prime: Scalar = R_pt.x().into();

    self.r == r_prime
  }

  pub fn to_der(&self) -> Vec<u8> {
    fn to_der(ser_scalar: &Vec<u8>) -> Vec<u8> {
      let mut vec = ser_scalar.to_vec();

      // drop leading zeroes
      while vec.len() > 1 && vec[0] == 0 {
        vec.remove(0);
      }

      // handle negative case
      if vec[0] & 0x80 != 0 {
        vec.insert(0, 0x00);
      }

      let mut res = Vec::new();
      res.push(0x2); // 0x2 = integer
      res.push(vec.len() as u8);
      res.extend(vec);
      res
    }

    let ser_r = self.r.secp256k1_serialize();
    let ser_s = self.s.secp256k1_serialize();

    let der_r = to_der(&ser_r);
    let der_s = to_der(&ser_s);

    let mut der = Vec::new();
    der.push(0x30); // 0x30 = Sequence
    der.push((der_r.len() + der_s.len()) as u8);
    der.extend(der_r);
    der.extend(der_s);
    der
  }
}

impl fmt::Debug for Signature {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Signature")
      .field("r", &self.r.to_hex())
      .field("s", &self.s.to_hex())
      .finish()
  }
}
