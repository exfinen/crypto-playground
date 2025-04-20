#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::{
  building_block::secp256k1::{
    jacobian_point::JacobianPoint,
    scalar::Scalar,
  },
  protocols::gg18::signature::Signature,
};

struct SimpleSigner();

impl SimpleSigner {
  pub fn sign(
    k: &Scalar, // k in GG18
    hasher: impl Fn(&Scalar) -> Scalar,
    M: &Scalar,
    x: &Scalar, // x in GG18
  ) -> Signature {
    let m = hasher(M);

    let gamma = Scalar::from(15u32);
    let delta = k * &gamma;
    //println!("====> delta: {:?}", &delta);
    let Gamma = JacobianPoint::get_base_point() * &gamma;
    //println!("====> Gamma: {:?}", &Gamma);

    let R = (&Gamma * delta.inv()).to_affine();
    let r: Scalar = R.x().into();
    println!("====> r: {:?}", &r);
    println!("====> R: {:?}", &R);
    println!("====> m: {:?}", &m);
    println!("====> k: {:?}", &k);
    println!("====> r: {:?}", &r);

    let kx = k * x; // = sigma
    //println!("====> kx: {:?}", &kx);

    let s = m * k + r * kx;
    println!("====> s: {:?}", &s);

    Signature::new(&r, &s)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::building_block::util::bitcoin_hasher;

  #[test]
  pub fn test_sign_verify() {
    let M = Scalar::from(123u32);
    let x = Scalar::from(10u32);
    let pk = JacobianPoint::get_base_point() * &x;

    // k = delta in GG18
    let k = Scalar::from(3u32); // k = k_1 + k_2

    let sig = SimpleSigner::sign(
      &k,
      bitcoin_hasher,
      &M,
      &x,
    );
    println!("sig: {:?}", sig);

    assert!(sig.verify(
      &pk,
      &M,
      bitcoin_hasher,
    ));
  }
}
