#![allow(non_snake_case)]
#![allow(dead_code)]

use std::{
  fmt,
  ffi::c_int,
  ops::{Add, AddAssign, Sub, Mul, MulAssign},
  cmp::PartialEq,
};
use rand::{
  rngs::OsRng,
  RngCore,
};

extern "C" {
  fn secp256k1_export_scalar_set_int(r: *mut Scalar, n: u32);
  fn secp256k1_export_scalar_inverse(r: *mut Scalar, a: *const Scalar);
  fn secp256k1_export_scalar_negate(r: *mut Scalar, a: *const Scalar);
  fn secp256k1_export_scalar_eq(a: *const Scalar, b: *const Scalar) -> c_int;

  fn secp256k1_export_scalar_add(r: *mut Scalar, a: *const Scalar, b: *const Scalar);
  fn secp256k1_export_scalar_sub(r: *mut Scalar, a: *const Scalar, b: *const Scalar);

  fn secp256k1_export_scalar_mul(r: *mut Scalar, a: *const Scalar, b: *const Scalar);
  fn secp256k1_export_scalar_set_b32(r: *mut Scalar, buf: *const u8);
  fn secp256k1_export_scalar_get_b32(buf: *mut u8, a: *const Scalar);
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

  pub fn zero() -> Self {
    Scalar::from(0u32)
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

  // 32-byte random scalar
  pub fn rand() -> Self {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    Scalar::from(buf)
  }
}

impl fmt::Display for Scalar {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", u64::from(*self))
  }
}

impl From<Scalar> for u64 {
  fn from(s: Scalar) -> Self {
    let mut buf = [0u8; 32];

    unsafe {
      secp256k1_export_scalar_get_b32(buf.as_mut_ptr(), &s);
    }
    let mut ret: u64 = 0;

    for i in 0..8 {
      ret |= (buf[32 - 1 - i] as u64) << (i * 8);
    }
    ret
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

impl From<usize> for Scalar {
  fn from(n: usize) -> Self {
    let mut s = Scalar::new();
    unsafe {
      secp256k1_export_scalar_set_int(&mut s, n as u32);
    }
    s
  }
}

impl From<[u8; 32]> for Scalar {
  fn from(buf: [u8; 32]) -> Self {
    let mut s = Scalar::new();
    unsafe {
      secp256k1_export_scalar_set_b32(&mut s, buf.as_ptr());
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

impl Add<Scalar> for &Scalar {
  type Output = Scalar;

  fn add(self, rhs: Scalar) -> Scalar {
    let mut r = Scalar::new();
    unsafe {
      secp256k1_export_scalar_add(&mut r, self, &rhs);
    }
    r
  }
}

impl AddAssign<Scalar> for Scalar {
  fn add_assign(&mut self, rhs: Self) {
    let res = self.clone() + rhs;
    self.d = res.d;
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

impl Mul<Scalar> for &Scalar {
  type Output = Scalar;

  fn mul(self, rhs: Scalar) -> Scalar {
    let mut r = Scalar::new();
    unsafe {
      secp256k1_export_scalar_mul(&mut r, self, &rhs);
    }
    r
  }
}

impl MulAssign<Scalar> for Scalar {
  fn mul_assign(&mut self, rhs: Self) {
    let res = self.clone() * rhs;
    self.d = res.d;
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
  fn test_int_conv() {
    let a = Scalar::from(5u32);
    let a_u64: u64 = a.into();
    assert_eq!(a_u64, 5u64);

    let a = Scalar::from(1000u32);
    let a_u64: u64 = a.into();
    assert_eq!(a_u64, 1000u64);
  }

  #[test]
  fn test_eq() {
    let a = Scalar::from(5u32);
    let b = Scalar::from(7u32);
    assert_eq!(a, a);
    assert_eq!(b, b);
    assert_ne!(a, b);
  }

  #[test]
  fn test_add() {
    let a = Scalar::from(5u32);
    let b = Scalar::from(7u32);
    let act = a + b;
    let exp = Scalar::from(12u32);
    assert_eq!(act, exp);
  }

  #[test]
  fn test_sub() {
    let a = Scalar::from(5u32);
    let b = Scalar::from(7u32);
    let act = b - a;
    let exp = Scalar::from(2u32);
    assert_eq!(act, exp);
  }

  #[test]
  fn test_mul() {
    let a = Scalar::from(5u32);
    let b = Scalar::from(7u32);
    let act = b * a;
    let exp = Scalar::from(35u32);
    assert_eq!(act, exp);
  }

  #[test]
  fn test_neg() {
    let a = Scalar::from(5u32);
    let a_neg = a.neg();
    let act = a + a_neg;
    let exp = Scalar::zero();
    assert_eq!(act, exp);

    assert_eq!(a_neg, a_neg);
    assert_eq!(a, a_neg.neg());
  }

  #[test]
  fn test_inv() {
    let a = Scalar::from(5u32);
    let a_inv = a.inv();
    let act = a * a_inv;
    let exp = Scalar::from(1u32);
    assert_eq!(act, exp);

    assert_eq!(a_inv, a_inv);
    assert_eq!(a, a_inv.inv());
  }

  #[test]
  fn test_rand() {
    let a = Scalar::rand();
    let b = Scalar::rand();
    assert_ne!(a, b);
  }
}


