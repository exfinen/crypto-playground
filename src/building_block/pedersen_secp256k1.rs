#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::secp256k1::{
  point::Point,
  scalar::Scalar,
};

#[derive(Debug, Copy, Clone)]
pub struct Decommitment {
  m: Scalar,
  r: Scalar,
}

impl Decommitment {
  pub fn new(m: &Scalar, r: &Scalar) -> Self {
    Self {
      m: m.clone(),
      r: r.clone(),
    }
  }
}

#[derive(Debug, Copy, Clone)]
pub struct CommitmentPair {
  comm: Point,
  decomm: Decommitment,
}

impl CommitmentPair {
  pub fn new(
    comm: Point,
    decomm: Decommitment,
  ) -> Self {
    Self {
      comm,
      decomm,
    }
  }
}

#[derive(Debug, Copy, Clone)]
pub struct PedersenCommitment {
  g: Point,
  h: Point,
}

impl PedersenCommitment {
  pub fn new() -> Self {
    let g = Point::get_base_point();
    let h = g * Scalar::rand();

    Self {
      g,
      h,
    }
  }

  pub fn commit(
    &self,
    secret: &Scalar,
    blinding_factor: &Scalar,
  ) -> CommitmentPair {
    let comm = &self.g * secret + &self.h * blinding_factor;
    let decomm = Decommitment::new(secret, blinding_factor);

    CommitmentPair::new(comm, decomm)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_pedersen() {
    let pedersen = PedersenCommitment::new();

    let secret = Scalar::rand();
    let blinding_factor = Scalar::rand();
    let comm_pair = pedersen.commit(&secret, &blinding_factor);
    println!("comm: {:?}, decomm: {:?}", comm_pair.comm, comm_pair.decomm);
  } 
}

