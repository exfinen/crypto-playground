#![allow(dead_code)]

use std::ffi::c_int;
use crate::building_block::secp256k1::{
  field::{
    Field,
    Fe5x52,
  },
  jacobian_point::JacobianPoint,
};
use serde::{
  Serialize,
  Deserialize,
};

extern "C" {
  #[link_name = "secp256k1_export_group_ge_set_gej"]
  fn group_ge_set_gej(r: *mut AffinePoint, a: *const JacobianPoint);
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct AffinePoint { // using 5x52 assuming 64-bit arch
  x: Fe5x52,
  y: Fe5x52,
  infinity: c_int,
}

impl AffinePoint {
  pub fn new() -> Self { // returns point at infinity
    AffinePoint {
      x: [0; 5],
      y: [0; 5],
      infinity: 1,
    }
  }

  pub fn x(&self) -> Field {
    self.x.into()
  }
}

impl From<JacobianPoint> for AffinePoint {
  fn from(jacob_pt: JacobianPoint) -> Self {
    let mut affine_pt = AffinePoint::new();
    unsafe {
      group_ge_set_gej(
        &mut affine_pt,
        &jacob_pt as *const JacobianPoint
      );
    }
    affine_pt
  }
}
