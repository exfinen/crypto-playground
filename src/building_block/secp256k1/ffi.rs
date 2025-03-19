#![allow(dead_code)]

use std::ffi::{
  c_int,
  c_uchar,
};
use crate::building_block::secp256k1::{
  field::Field,
  scalar::Scalar,
  jacobian_point::JacobianPoint,
};

// Scalar
extern "C" {
  #[link_name = "secp256k1_export_scalar_set_int"]
  pub fn scalar_set_int(r: *mut Scalar, n: u32);

  #[link_name = "secp256k1_export_scalar_inverse"]
  pub fn scalar_inverse(r: *mut Scalar, a: *const Scalar);

  #[link_name = "secp256k1_export_scalar_is_zero"]
  pub fn scalar_is_zero(ra: *const Scalar) -> c_int;

  #[link_name = "secp256k1_export_scalar_negate"]
  pub fn scalar_negate(r: *mut Scalar, a: *const Scalar);

  #[link_name = "secp256k1_export_scalar_eq"]
  pub fn scalar_eq(a: *const Scalar, b: *const Scalar) -> c_int;

  #[link_name = "secp256k1_export_scalar_set_b32"]
  pub fn scalar_set_b32(r: *mut Scalar, buf: *const u8);

  #[link_name = "secp256k1_export_scalar_get_b32"]
  pub fn scalar_get_b32(buf: *mut u8, a: *const Scalar);

  #[link_name = "secp256k1_export_scalar_add"]
  pub fn scalar_add(r: *mut Scalar, a: *const Scalar, b: *const Scalar);

  #[link_name = "secp256k1_export_scalar_sub"]
  pub fn scalar_sub(r: *mut Scalar, a: *const Scalar, b: *const Scalar);

  #[link_name = "secp256k1_export_scalar_mul"]
  pub fn scalar_mul(r: *mut Scalar, a: *const Scalar, b: *const Scalar);
}

// Field
extern "C" {
  #[link_name = "secp256k1_export_fe_add"]
  pub fn fe_add(r: *mut Field, a: *const Field, b: *const Field);

  #[link_name = "secp256k1_export_fe_equal"]
  pub fn fe_is_equal(a: *const Field, b: *const Field) -> c_int;

  #[link_name = "secp256k1_export_fe_get_b32"]
  pub fn fe_get_b32(r: *mut c_uchar, a: *const Field);

  #[link_name = "secp256k1_export_fe_inv"]
  pub fn fe_inv(r: *mut Field, a: *const Field);

  #[link_name = "secp256k1_export_fe_is_zero"]
  pub fn fe_is_zero(a: *const Field) -> c_int;

  #[link_name = "secp256k1_export_fe_mul"]
  pub fn fe_mul(r: *mut Field, a: *const Field, b: *const Field);

  #[link_name = "secp256k1_export_fe_normalize"]
  pub fn fe_normalize(a: *const Field);

  #[link_name = "secp256k1_export_fe_set_int"]
  pub fn fe_set_int(r: *mut Field, n: u32);

  #[link_name = "secp256k1_export_fe_sqr"]
  pub fn fe_sq(r: *mut Field, a: *const Field);
}

// Point
extern "C" {
  #[link_name = "secp256k1_export_group_add"]
  pub fn group_add(r: *mut JacobianPoint, a: *const JacobianPoint, b: *const JacobianPoint);

  #[link_name = "secp256k1_export_group_ecmult"]
  pub fn group_mul(r: *mut JacobianPoint, a: *const JacobianPoint, q: Scalar);

  #[link_name = "secp256k1_export_group_eq"]
  pub fn group_eq(a: *const JacobianPoint, b: *const JacobianPoint) -> c_int;

  #[link_name = "secp256k1_export_group_get_base_point"]
  pub fn group_get_base_point(r: *mut JacobianPoint);
}

