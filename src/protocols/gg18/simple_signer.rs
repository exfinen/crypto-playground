#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::{
  building_block::secp256k1::{
    affine_point::AffinePoint,
    jacobian_point::JacobianPoint,
    scalar::Scalar,
  },
  protocols::gg18::signature::Signature,
};

struct SimpleSigner();

impl SimpleSigner {
  pub fn sign(
    hasher: impl Fn(&Scalar) -> Scalar,
    M: &Scalar,
    sk: &Scalar,
  ) -> Signature {
    let m = hasher(M);

    let k = Scalar::rand();
    let k_inv = k.inv();
    let R = JacobianPoint::get_base_point() * &k_inv;
    let r_pt: AffinePoint = R.into();
    let r: Scalar = r_pt.x().into();
    let s = m * k + r * k * sk;

    Signature::new(&r, &s)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::building_block::util::bitcoin_hasher;

  #[test]
  pub fn test_sign_verify() {
    let m = Scalar::rand();
    let sk = Scalar::rand();
    let pk = JacobianPoint::get_base_point() * &sk;

    let sig = SimpleSigner::sign(
      bitcoin_hasher,
      &m,
      &sk,
    );

    assert!(sig.verify(
      &pk,
      &m,
      bitcoin_hasher,
    ));
  }
}
