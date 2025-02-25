#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::pedersen_secp256k1::{
  CommitmentPair,
  PedersenCommitment,
};
use crate::building_block::secp256k1::scalar::Scalar;

struct GG18();

fn main() {
  ////// Key generation

  let num_players = 3;

  //// Phase 1:

  // Each player P_i select u_i in Z_q
  let u_is: Vec<Scalar> =
    (0..num_players)
    .map(|_| Scalar::rand())
    .collect();

  // Computes [KGC_i, KGD_i] = Com(u_i * G)
  let pedersen = PedersenCommitment::new();
  let _comm_pairs: Vec<CommitmentPair> =
    u_is.iter()
    .map(|u_i| {
      let blinding_factor = &Scalar::rand();
      pedersen.commit(u_i, blinding_factor)
    })
    .collect();

  //// Phase 2:

}
