#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::{
  paillier::{
    GCalcMethod,
    Paillier,
    PaillierInstance,
  },
  pedersen_secp256k1::{
    CommitmentPair,
    PedersenCommitment,
  },
  secp256k1::scalar::Scalar,
};
use rug::{Integer, Complete};

struct GG18();

// returns a Paillier instance that supports the full range of 256-bit integers
fn get_seck256k1_paillier() -> PaillierInstance {
  let max_256_bits = Integer::u_pow_u(2, 256).complete() - Integer::ONE;
  loop {
    let inst = Paillier::new(256, GCalcMethod::Random);
    if inst.n > max_256_bits {
      return inst
    }
  }
}

fn main() {
  let num_players = 3;

  ////// Key generation

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

  // Each Player P_i broadcasts the Paillier's public key E_i
  // Ensure all the public keys are distinct
  let _pailliers: Vec<PaillierInstance> = {
    'outer: loop {
      let vec: Vec<PaillierInstance> =
        (0..num_players).map(|_| get_seck256k1_paillier()).collect();

      for i in 0..num_players {
        for j in i+1..num_players {
          if vec[i].pk.n == vec[j].pk.n {
            continue 'outer;
          }
        }
      }
      break vec;
    }
  };

  //// Phase 2:

}
