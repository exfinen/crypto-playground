#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::pedersen_secp256k1::{
  CommitmentPair,
  Decommitment,
  Pedersen,
};
use crate::building_block::secp256k1::{
  point::Point,
  scalar::Scalar,
};

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
  let comm_pairs: Vec<CommitmentPair> =
    u_is.iter()
    .map(|u_i| {
      let blinding_factor = Scalar::rand();
      let KGC_i = Pedersen::commit(u_i);
      let KGD_i = Decommitment::new(u_i, &blinding_factor);
      CommitmentPair::new(KGC_i, KGD_i)
    })
    .collect();

  //// Phase 2:

}
