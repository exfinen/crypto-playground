#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::{
  building_block::{
    mta::{
      Alice,
      Bob,
      MtA,
    },
    paillier::{
      GCalcMethod,
      Paillier,
      PaillierInstance,
      PublicKey,
    },
    pedersen_secp256k1::{
      CommitmentPair,
      Decommitment,
      PedersenCommitment,
    },
    secp256k1::{point::Point, scalar::Scalar},
  },
  protocols::gg18::{
    key_gen::KeyGen,
    signing::Signing,
  }
};
use rug::{Integer, Complete};

pub struct Player {
  player_id: usize,
  pub key_gen: KeyGen, 
  //pub signing: Signing,
}

impl Player {
  pub fn new(
    q: &Integer,
    player_id: usize,
    num_players: usize,
  ) -> Self {
    let q_sig_bits = q.significant_bits();
    let paillier = Paillier::new(q_sig_bits, GCalcMethod::Random);

    let key_gen = KeyGen {
      q: q.clone(),
      num_players,
      u_i: None,
      comm_pair: None,
      paillier,
      pk: None,
      p_i: None,
      a_i: None,
      A_i: None,
      x_i: None,
      X_is: None,
    };

    // let signing = Signing {
    //   k_i: None,
    //   gamma_i: None,
    //   comm_pair: None,
    //   k_i_gamma_i: None,
    //   k_i_omega_i: None,
    // };

    Self {
      player_id,
      key_gen,
      //signing,
    }
  }
}

#[cfg(test)]
mod tests {
  //use super::*;
}



