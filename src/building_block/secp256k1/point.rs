#![allow(non_snake_case)]
#![allow(dead_code)]

use std::{
  ffi::c_int,
  ops::{Add, Mul},
  cmp::PartialEq,
};
use crate::building_block::secp256k1::scalar::Scalar;

extern "C" {
  fn secp256k1_export_group_add(r: *mut Point, a: *const Point, b: *const Point);
  fn secp256k1_export_group_ecmult(r: *mut Point, q: Scalar);
  fn secp256k1_export_group_eq(a: *const Point, b: *const Point) -> c_int;
  fn secp256k1_export_group_get_base_point(r: *mut Point);
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
  pub fn new() -> Self { // returns point at infinity
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
      secp256k1_export_group_get_base_point(&mut p);
    }
    p
  }
}

impl Add<Point> for Point {
  type Output = Point;

  fn add(self, rhs: Point) -> Point {
    let mut r = Point::new();
    unsafe {
      secp256k1_export_group_add(&mut r, &self, &rhs);
    }
    r
  }
}

impl Add<&Point> for Point {
  type Output = Point;

  fn add(self, rhs: &Point) -> Point {
    let mut r = Point::new();
    unsafe {
      secp256k1_export_group_add(&mut r, &self, rhs);
    }
    r
  }
}

impl Mul<Scalar> for Point {
  type Output = Point;

  fn mul(self, rhs: Scalar) -> Point {
    let mut r = Point::new();
    unsafe {
      secp256k1_export_group_ecmult(&mut r, rhs);
    }
    r
  }
}

impl Mul<&Scalar> for Point {
  type Output = Point;

  fn mul(self, rhs: &Scalar) -> Point {
    let mut r = Point::new();
    unsafe {
      secp256k1_export_group_ecmult(&mut r, *rhs);
    }
    r
  }
}

impl PartialEq for Point {
  fn eq(&self, rhs: &Self) -> bool {
    let r;
    unsafe {
      r = secp256k1_export_group_eq(self, rhs);
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
    let two = Scalar::from(2);
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
