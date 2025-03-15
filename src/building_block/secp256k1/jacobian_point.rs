#![allow(non_snake_case)]
#![allow(dead_code)]

use std::{
  ffi::c_int,
  ops::{Add, AddAssign, Mul},
  cmp::PartialEq,
};
use crate::building_block::secp256k1::{
  field::{Field, Fe5x52},
  scalar::Scalar,
};
use serde::{
  Serialize,
  Deserialize,
};

extern "C" {
  #[link_name = "secp256k1_export_group_add"]
  fn group_add(r: *mut JacobianPoint, a: *const JacobianPoint, b: *const JacobianPoint);

  #[link_name = "secp256k1_export_group_ecmult"]
  fn group_mul(r: *mut JacobianPoint, a: *const JacobianPoint, q: Scalar);

  #[link_name = "secp256k1_export_group_eq"]
  fn group_eq(a: *const JacobianPoint, b: *const JacobianPoint) -> c_int;

  #[link_name = "secp256k1_export_group_get_base_point"]
  fn group_get_base_point(r: *mut JacobianPoint);
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct JacobianPoint { // using 5x52 assuming 64-bit arch
  pub x: Fe5x52,
  pub y: Fe5x52,
  pub z: Fe5x52,
  infinity: c_int,
}

impl JacobianPoint {
  fn new() -> Self { // returns point at infinity
    JacobianPoint {
      x: [0; 5],
      y: [0; 5],
      z: [0; 5],
      infinity: 1,
    }
  }

  pub fn z(&self) -> Field {
    self.z.into()
  }

  pub fn point_at_infinity() -> Self {
    Self::new()
  }

  pub fn get_base_point() -> Self {
    let mut p = Self::new();
    unsafe {
      group_get_base_point(&mut p);
    }
    p
  }

  pub fn get_point_at_infinity() -> Self {
    Self::new()
  }

  pub fn serialize(&self) -> Vec<u8> {
    bincode::serialize(self).unwrap()
  }

  pub fn deserialize(bytes: &[u8]) -> Self {
    bincode::deserialize(bytes).unwrap()
  }
}

impl From<Scalar> for JacobianPoint {
  fn from(n: Scalar) -> Self {
    let g = JacobianPoint::get_base_point();
    g * n
  }
}

impl From<&Scalar> for JacobianPoint {
  fn from(n: &Scalar) -> Self {
    let g = JacobianPoint::get_base_point();
    g * n
  }
}

macro_rules! impl_op {
  ("nn", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = JacobianPoint;

      fn $op_fn(self, rhs: $rhs) -> JacobianPoint {
        let mut r = JacobianPoint::new();
        unsafe {
          $ffi_fn(&mut r, &self, &rhs);
        }
        r
      }
    }
  };
  ("nr", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = JacobianPoint;

      fn $op_fn(self, rhs: $rhs) -> JacobianPoint {
        let mut r = JacobianPoint::new();
        unsafe {
          $ffi_fn(&mut r, &self, rhs);
        }
        r
      }
    }
  };
  ("rn", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = JacobianPoint;

      fn $op_fn(self, rhs: $rhs) -> JacobianPoint {
        let mut r = JacobianPoint::new();
        unsafe {
          $ffi_fn(&mut r, self, &rhs);
        }
        r
      }
    }
  };
  ("rr", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = JacobianPoint;

      fn $op_fn(self, rhs: $rhs) -> JacobianPoint {
        let mut r = JacobianPoint::new();
        unsafe {
          $ffi_fn(&mut r, self, rhs);
        }
        r
      }
    }
  };
}

// Add
impl_op!("nn", Add, add, group_add, JacobianPoint, JacobianPoint);
impl_op!("nr", Add, add, group_add, JacobianPoint, &JacobianPoint);
impl_op!("rn", Add, add, group_add, &JacobianPoint, JacobianPoint);
impl_op!("rr", Add, add, group_add, &JacobianPoint, &JacobianPoint);

// Mul
impl_op!("nr", Mul, mul, group_mul, JacobianPoint, Scalar);
impl_op!("rr", Mul, mul, group_mul, &JacobianPoint, Scalar);

impl Mul<&Scalar> for JacobianPoint {
  type Output = JacobianPoint;

  fn mul(self, rhs: &Scalar) -> JacobianPoint {
    let mut r = JacobianPoint::new();
    unsafe {
      group_mul(&mut r, &self, *rhs);
    }
    r
  }
}

impl Mul<&Scalar> for &JacobianPoint {
  type Output = JacobianPoint;

  fn mul(self, rhs: &Scalar) -> JacobianPoint {
    let mut r = JacobianPoint::new();
    unsafe {
      group_mul(&mut r, self, *rhs);
    }
    r
  }
}

impl AddAssign<JacobianPoint> for JacobianPoint {
  fn add_assign(&mut self, rhs: Self) {
    let res = self.clone() + rhs;

    self.x = res.x;
    self.y = res.y;
    self.z = res.z;
    self.infinity = res.infinity;
  }
}

impl PartialEq for JacobianPoint {
  fn eq(&self, rhs: &Self) -> bool {
    let r;
    unsafe {
      r = group_eq(self, rhs);
    }
    r != 0
  }
}
impl Eq for JacobianPoint {} // JacobianPoint has total equality

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_add_mul() {
    let two = Scalar::from(2u32);
    let a = JacobianPoint::get_base_point();
    let b = a + a;
    let c = a * two;

    assert_eq!(b, c);
    assert_ne!(a, c);
  }

  #[test]
  fn test_eq() {
    let a = JacobianPoint::get_base_point();
    let b = a.clone();
    let c = a + b;

    assert_eq!(a, a);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
  }
}
