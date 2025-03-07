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
use rug::{
  integer::Order,
  Integer,
};

extern "C" {
  #[link_name = "secp256k1_export_scalar_set_int"]
  fn scalar_set_int(r: *mut Scalar, n: u32);

  #[link_name = "secp256k1_export_scalar_inverse"]
  fn scalar_inverse(r: *mut Scalar, a: *const Scalar);

  #[link_name = "secp256k1_export_scalar_negate"]
  fn scalar_negate(r: *mut Scalar, a: *const Scalar);

  #[link_name = "secp256k1_export_scalar_eq"]
  fn scalar_eq(a: *const Scalar, b: *const Scalar) -> c_int;

  #[link_name = "secp256k1_export_scalar_set_b32"]
  fn scalar_set_b32(r: *mut Scalar, buf: *const u8);

  #[link_name = "secp256k1_export_scalar_get_b32"]
  fn scalar_get_b32(buf: *mut u8, a: *const Scalar);

  #[link_name = "secp256k1_export_scalar_add"]
  fn scalar_add(r: *mut Scalar, a: *const Scalar, b: *const Scalar);

  #[link_name = "secp256k1_export_scalar_sub"]
  fn scalar_sub(r: *mut Scalar, a: *const Scalar, b: *const Scalar);

  #[link_name = "secp256k1_export_scalar_mul"]
  fn scalar_mul(r: *mut Scalar, a: *const Scalar, b: *const Scalar);
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Scalar { // using 4x64 assuming 64-bit arch
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
      scalar_inverse(&mut r, self);
    }
    r
  }

  pub fn neg(&self) -> Self {
    let mut r = Scalar::new();
    unsafe {
      scalar_negate(&mut r, self);
    }
    r
  }

  // 32-byte random scalar
  pub fn rand() -> Self {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    Scalar::from(buf)
  }

  pub fn to_hex(&self) -> String {
    // TODO implement this
    "ab".to_string()
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = [0u8; 32];
    unsafe {
      scalar_get_b32(buf.as_mut_ptr(), self);
    }
    buf.to_vec()
  }
}

impl fmt::Display for Scalar {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", u64::from(*self))
  }
}

macro_rules! impl_from_rhs {
  ($lhs:ty, $num_bytes:expr) => {
    impl From<Scalar> for $lhs {
      fn from(s: Scalar) -> Self {
        let mut buf = [0u8; 32];

        unsafe {
          scalar_get_b32(buf.as_mut_ptr(), &s);
        }
        let mut ret: $lhs = 0;

        for i in 0..$num_bytes {
          ret |= (buf[32 - 1 - i] as $lhs) << (i * 8);
        }
        ret
      }
    }
  }
}
impl_from_rhs!(u128, 16);
impl_from_rhs!(usize, 8);
impl_from_rhs!(u64, 8);
impl_from_rhs!(u32, 4);
impl_from_rhs!(u16, 2);
impl_from_rhs!(u8, 1);

macro_rules! impl_from_lhs {
  ($lhs:ty) => {
    impl From<$lhs> for Scalar {
      fn from(n: $lhs) -> Self {
        let mut s = Scalar::new();
        unsafe {
          scalar_set_int(&mut s, n as u32);
        }
        s
      }
    }
  }
}
impl_from_lhs!(usize);
impl_from_lhs!(u64);
impl_from_lhs!(u32);
impl_from_lhs!(u16);
impl_from_lhs!(u8);

impl From<[u8; 32]> for Scalar {
  fn from(buf: [u8; 32]) -> Self {
    let mut s = Scalar::new();
    unsafe {
      scalar_set_b32(&mut s, buf.as_ptr());
    }
    s
  }
}

impl From<&Integer> for Scalar {
  fn from(i: &Integer) -> Self {
    let mut s = Scalar::new();
    let mut buf = i.to_digits::<u8>(Order::MsfBe);
    
    // make buf 32 bytes
    if buf.len() > 32 {
      buf.drain(0..(buf.len() - 32));
    } else if buf.len() < 32 {
      let mut padded_buf = vec![0u8; 32 - buf.len()];
      padded_buf.extend_from_slice(&buf);
      buf = padded_buf;
    }
    
    let mut buf_array = [0u8; 32];
    buf_array.copy_from_slice(&buf);
    unsafe {
      scalar_set_b32(&mut s, buf_array.as_ptr());
    }
    s
  }
}

impl From<Scalar> for Integer {
  fn from(s: Scalar) -> Self {
    let buf = s.serialize();
    Integer::from_digits(&buf, Order::MsfBe)
  }
}

macro_rules! impl_op {
  ("nn", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = Scalar;

      fn $op_fn(self, rhs: $rhs) -> Scalar {
        let mut r = Scalar::new();
        unsafe {
          $ffi_fn(&mut r, &self, &rhs);
        }
        r
      }
    }
  };
  ("rn", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = Scalar;

      fn $op_fn(self, rhs: $rhs) -> Scalar {
        let mut r = Scalar::new();
        unsafe {
          $ffi_fn(&mut r, self, &rhs);
        }
        r
      }
    }
  };
  ("nr", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = Scalar;

      fn $op_fn(self, rhs: $rhs) -> Scalar {
        let mut r = Scalar::new();
        unsafe {
          $ffi_fn(&mut r, &self, rhs);
        }
        r
      }
    }
  };
  ("rr", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = Scalar;

      fn $op_fn(self, rhs: $rhs) -> Scalar {
        let mut r = Scalar::new();
        unsafe {
          $ffi_fn(&mut r, self, rhs);
        }
        r
      }
    }
  };
}

// Add
impl_op!("nn", Add, add, scalar_add, Scalar, Scalar);
impl_op!("rn", Add, add, scalar_add, &Scalar, Scalar);
impl_op!("nr", Add, add, scalar_add, Scalar, &Scalar);
impl_op!("rr", Add, add, scalar_add, &Scalar, &Scalar);

// Sub
impl_op!("nn", Sub, sub, scalar_sub, Scalar, Scalar);
impl_op!("rn", Sub, sub, scalar_sub, &Scalar, Scalar);
impl_op!("nr", Sub, sub, scalar_sub, Scalar, &Scalar);
impl_op!("rr", Sub, sub, scalar_sub, &Scalar, &Scalar);

// Mul
impl_op!("nn", Mul, mul, scalar_mul, Scalar, Scalar);
impl_op!("rn", Mul, mul, scalar_mul, &Scalar, Scalar);
impl_op!("nr", Mul, mul, scalar_mul, Scalar, &Scalar);
impl_op!("rr", Mul, mul, scalar_mul, &Scalar, &Scalar);

impl AddAssign<Scalar> for Scalar {
  fn add_assign(&mut self, rhs: Self) {
    let res = self.clone() + rhs;
    self.d = res.d;
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
      r = scalar_eq(self, rhs);
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


