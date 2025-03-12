#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::secp256k1::{
  point::Point,
  scalar::Scalar,
};
use serde::{
  Serialize,
  Deserialize,
};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Decommitment {
  pub secret: Point,
  pub blinding_factor: Scalar,
}

impl Decommitment {
  pub fn new(
    secret: &Point,
    blinding_factor: &Scalar,
  ) -> Self {
    Self {
      secret: m.clone(),
      blinding_factor: r.clone(),
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    bincode::serialize(self).unwrap()
  }

  pub fn deserialize(buf: &[u8]) -> Self {
    bincode::deserialize(buf).unwrap()
  }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CommitmentPair {
  pub comm: Point,
  pub decomm: Decommitment,
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
    let U_i = &self.g * secret;
    let comm = &U_i + &self.h * blinding_factor;
    let decomm = Decommitment::new(&U_i, blinding_factor);

    CommitmentPair::new(comm, decomm)
  }

  pub fn verify(
    &self,
    comm: &Point,
    decomm: &Decommitment,
  ) -> bool {
    let U_i = &self.g * decom.secret;
    let comm_prime = &U_i + &self.h * decom.blinding_factor;

    comm == comm_prime
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

    assert!(pedersen.verify(&comm_pair.comm, &comm_pair.decomm));
  } 
}

