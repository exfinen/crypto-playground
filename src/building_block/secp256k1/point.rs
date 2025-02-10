#![allow(non_snake_case)]
#![allow(dead_code)]

use std::{
  ffi::c_int,
  ops::{Add, AddAssign, Mul},
  cmp::PartialEq,
};
use crate::building_block::secp256k1::scalar::Scalar;

extern "C" {
  #[link_name = "secp256k1_export_group_add"]
  fn group_add(r: *mut Point, a: *const Point, b: *const Point);

  #[link_name = "secp256k1_export_group_ecmult"]
  fn group_mul(r: *mut Point, a: *const Point, q: Scalar);

  #[link_name = "secp256k1_export_group_eq"]
  fn group_eq(a: *const Point, b: *const Point) -> c_int;

  #[link_name = "secp256k1_export_group_get_base_point"]
  fn group_get_base_point(r: *mut Point);
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Point { // using 5x52 expecting 64-bit arch
  x: [u64; 5], 
  y: [u64; 5],
  z: [u64; 5],
  infinity: c_int,
}

impl Point {
  fn new() -> Self { // returns point at infinity
    Point {
      x: [0; 5],
      y: [0; 5],
      z: [0; 5],
      infinity: 1,
    }
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
}

impl From<Scalar> for Point {
  fn from(n: Scalar) -> Self {
    let g = Point::get_base_point();
    g * n
  }
}

impl From<&Scalar> for Point {
  fn from(n: &Scalar) -> Self {
    let g = Point::get_base_point();
    g * n
  }
}

macro_rules! impl_op {
  ("nn", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = Point;

      fn $op_fn(self, rhs: $rhs) -> Point {
        let mut r = Point::new();
        unsafe {
          $ffi_fn(&mut r, &self, &rhs);
        }
        r
      }
    }
  };
  ("nr", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = Point;

      fn $op_fn(self, rhs: $rhs) -> Point {
        let mut r = Point::new();
        unsafe {
          $ffi_fn(&mut r, &self, rhs);
        }
        r
      }
    }
  };
  ("rn", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = Point;

      fn $op_fn(self, rhs: $rhs) -> Point {
        let mut r = Point::new();
        unsafe {
          $ffi_fn(&mut r, self, &rhs);
        }
        r
      }
    }
  };
  ("rr", $trait:ident, $op_fn:ident, $ffi_fn:ident, $lhs:ty, $rhs:ty) => {
    impl $trait<$rhs> for $lhs {
      type Output = Point;

      fn $op_fn(self, rhs: $rhs) -> Point {
        let mut r = Point::new();
        unsafe {
          $ffi_fn(&mut r, self, rhs);
        }
        r
      }
    }
  };
}

// Add
impl_op!("nn", Add, add, group_add, Point, Point);
impl_op!("nr", Add, add, group_add, Point, &Point);
impl_op!("rn", Add, add, group_add, &Point, Point);
impl_op!("rr", Add, add, group_add, &Point, &Point);

// Mul
impl_op!("nr", Mul, mul, group_mul, Point, Scalar);
impl_op!("rr", Mul, mul, group_mul, &Point, Scalar);

impl Mul<&Scalar> for Point {
  type Output = Point;

  fn mul(self, rhs: &Scalar) -> Point {
    let mut r = Point::new();
    unsafe {
      group_mul(&mut r, &self, *rhs);
    }
    r
  }
}

impl Mul<&Scalar> for &Point {
  type Output = Point;

  fn mul(self, rhs: &Scalar) -> Point {
    let mut r = Point::new();
    unsafe {
      group_mul(&mut r, self, *rhs);
    }
    r
  }
}

impl AddAssign<Point> for Point {
  fn add_assign(&mut self, rhs: Self) {
    let res = self.clone() + rhs;

    self.x = res.x;
    self.y = res.y;
    self.z = res.z;
    self.infinity = res.infinity;
  }
}

impl PartialEq for Point {
  fn eq(&self, rhs: &Self) -> bool {
    let r;
    unsafe {
      r = group_eq(self, rhs);
    }
    r != 0
  }
}
impl Eq for Point {} // Point has total equality

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_add_mul() {
    let two = Scalar::from(2u32);
    let a = Point::get_base_point();
    let b = a + a;
    let c = a * two;

    assert_eq!(b, c);
    assert_ne!(a, c);
  }

  #[test]
  fn test_eq() {
    let a = Point::get_base_point();
    let b = a.clone();
    let c = a + b;

    assert_eq!(a, a);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
  }
}
