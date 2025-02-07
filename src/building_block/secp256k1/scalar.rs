#![allow(non_snake_case)]
#![allow(dead_code)]

use std::{
  ffi::c_int,
  ops::{Add, Sub, Mul},
  cmp::PartialEq,
};

extern "C" {
  fn secp256k1_export_scalar_set_int(r: *mut Scalar, n: u32);
  fn secp256k1_export_scalar_inverse(r: *mut Scalar, a: *const Scalar);
  fn secp256k1_export_scalar_negate(r: *mut Scalar, a: *const Scalar);
  fn secp256k1_export_scalar_eq(a: *const Scalar, b: *const Scalar) -> c_int;

  fn secp256k1_export_scalar_add(r: *mut Scalar, a: *const Scalar, b: *const Scalar);
  fn secp256k1_export_scalar_sub(r: *mut Scalar, a: *const Scalar, b: *const Scalar);

  fn secp256k1_export_scalar_mul(r: *mut Scalar, a: *const Scalar, b: *const Scalar);
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Scalar { // using 4x64 expecting 64-bit arch
  d: [u64; 4],
}

impl Scalar {
  fn new() -> Self {
    Scalar {
      d: [0; 4],
    }
  }

  pub fn inv(&self) -> Self {
    let mut r = Scalar::new();
    unsafe {
      secp256k1_export_scalar_inverse(&mut r, self);
    }
    r
  }

  pub fn neg(&self) -> Self {
    let mut r = Scalar::new();
    unsafe {
      secp256k1_export_scalar_negate(&mut r, self);
    }
    r
  }
}

impl From<u32> for Scalar {
  fn from(n: u32) -> Self {
    let mut s = Scalar::new();
    unsafe {
      secp256k1_export_scalar_set_int(&mut s, n);
    }
    s
  }
}

impl Add<Scalar> for Scalar {
  type Output = Scalar;

  fn add(self, rhs: Scalar) -> Scalar {
    let mut r = Scalar::new();
    unsafe {
      secp256k1_export_scalar_add(&mut r, &self, &rhs);
    }
    r
  }
}

impl Sub<Scalar> for Scalar {
  type Output = Scalar;

  fn sub(self, rhs: Scalar) -> Scalar {
    let mut r = Scalar::new();
    unsafe {
      secp256k1_export_scalar_sub(&mut r, &self, &rhs);
    }
    r
  }
}

impl Mul<Scalar> for Scalar {
  type Output = Scalar;

  fn mul(self, rhs: Scalar) -> Scalar {
    let mut r = Scalar::new();
    unsafe {
      secp256k1_export_scalar_mul(&mut r, &self, &rhs);
    }
    r
  }
}

impl PartialEq for Scalar {
  fn eq(&self, rhs: &Self) -> bool {
    let r;
    unsafe {
      r = secp256k1_export_scalar_eq(self, rhs);
    }
    r != 0
  }
}
impl Eq for Scalar {} // Scalar has total equality
 
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_eq() {
    let a = Scalar::from(5);
    let b = Scalar::from(7);
    assert_eq!(a, a);
    assert_eq!(b, b);
    assert_ne!(a, b);
  }

  #[test]
  fn test_add() {
    let a = Scalar::from(5);
    let b = Scalar::from(7);
    let act = a + b;
    let exp = Scalar::from(12);
    assert_eq!(act, exp);
  }

  #[test]
  fn test_sub() {
    let a = Scalar::from(5);
    let b = Scalar::from(7);
    let act = b - a;
    let exp = Scalar::from(2);
    assert_eq!(act, exp);
  }

  #[test]
  fn test_mul() {
    let a = Scalar::from(5);
    let b = Scalar::from(7);
    let act = b * a;
    let exp = Scalar::from(35);
    assert_eq!(act, exp);
  }

  #[test]
  fn test_neg() {
    let a = Scalar::from(5);
    let a_neg = a.neg();
    let act = a + a_neg;
    let exp = Scalar::from(0);
    assert_eq!(act, exp);

    assert_eq!(a_neg, a_neg);
    assert_eq!(a, a_neg.neg());
  }

  #[test]
  fn test_inv() {
    let a = Scalar::from(5);
    let a_inv = a.inv();
    let act = a * a_inv;
    let exp = Scalar::from(1);
    assert_eq!(act, exp);

    assert_eq!(a_inv, a_inv);
    assert_eq!(a, a_inv.inv());
  }
}


