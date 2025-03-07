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
    secp256k1::{
      point::Point,
      scalar::Scalar,
    },
    util::get_32_byte_rng,
  },
  protocols::gg18::player::Player,
};
use rug::Integer;

pub enum MtATarget {
  Gamma,
  Omega,
}

pub struct Signature {
  pub r: Scalar,
  pub s: Scalar,
}

pub struct Signing {
  pub k_i: Option<Integer>,
  pub gamma_i: Option<Integer>,
  pub omega_i: Option<Scalar>,
  pub comm_pair: Option<CommitmentPair>,
  pub k_i_gamma_i: Option<Integer>,
  pub k_i_omega_i: Option<Integer>,
}

impl Signing {
  // let lambda_i_j = calc_lambda_i_j(1, 2); // 2
  // let lambda_j_i = calc_lambda_j_i(1, 2); // -1
  // 
  // let omega_1 = lambda_i_j * x1;
  // let omega_2 = lambda_j_i * x2;

  // i and j are evaluation points assigned to players
  // e.g. player i uses evaluation point i+1
  fn calc_lambda_i_j(i: usize, j: usize) -> Scalar {
    assert!(i < j);
    let x = j / (j - i);
    Scalar::from(x)
  }

  // i and j are evaluation points assigned to players
  // e.g. player i uses evaluation point i+1
  fn calc_lambda_j_i(i: i32, j: i32) -> Scalar {
    assert!(i < j);
    let x = (i - j) * -1;  // i - j is always negative
    Scalar::from(x as usize).inv()
  }

  // each player selects k_i and gamma_i in Z_q and
  // broadcasts C_i
  pub fn phase_1(&mut self) -> Point {
    // select from Z_q
    self.k_i = Some(Integer::from(&Scalar::rand()));
    self.gamma_i = Some(Integer::from(&Scalar::rand()));
    
    // Computes [C_i, D_i] = Com(gamma_i * G)
    let pedersen = PedersenCommitment::new();
    let blinding_factor = &Scalar::rand();
    self.comm_pair = Some(
      pedersen.commit(&self.gamma_i.unwrap(), blinding_factor)
    );

    // return C_i for broadcasting
    self.comm_pair.unwrap().comm.clone()
  }

  pub fn phase_2_MtA_alice_1(
    &mut self,
    num_bits: u32,
    paillier_n: &Integer,
  ) -> (Integer, Integer) {
    let mta = MtA::new(paillier_n);
    let k_i = Integer::from(&self.k_i.unwrap());
    let alice = Alice::new(
      num_bits,
      &k_i,
    );
    (alice.c_a.clone(), alice.rp_a_lt_q3.clone())
  }

  pub fn phase_2_MtA_bob(
    &mut self,
    c_a: &Point,
    q: &Integer,
    pk: &PublicKey,
    rp_a_lt_q3: &Scalar,
    target: MtATarget,
  ) -> (Integer, Integer) {
    let value = match target {
      MtATarget::Gamma => &self.gamma_i.unwrap(),
      MtATarget::Omega => &self.omega_i.unwrap(),
    };
    let bob = Bob::new(
      c_a,
      q,
      pk,
      rp_a_lt_q3,
      &value
    );
    (bob.c_b.clone(), bob.beta.clone())
  }

  pub fn phase_2_MtA_alice_2(
    &mut self,
    c_b: &Integer,
    beta: &Integer,
    rp_b_it_q3: &Integer,
    rp_b_lt_q3_bp_le_q7: &Integer,
    target_value: MtATarget,
  ) {
    let alpha = alice.calc_alpha(
      &c_b,
      &rp_b_lt_q3,
      &rp_b_lt_q3_bp_le_q7,
    ).unwrap();

    match target_value {
      MtATarget::Gamma => self.k_i_gamma_i = alpha + beta,
      MtATarget::Omega => self.k_i_omega_i = alpha + beta,
    }
  }

  pub fn sign_by_2_parties(
    m: &Vec<u8>, // message to sign
    player_a: &Player,
    player_b: &Player,
  ) -> Signature {
    let players = vec![player_a, player_b];

    // Phase 1
    let mut C_is = vec![];
    for player in &mut players {
      let C_i = player.signing.phase_1();
      C_is.push(C_i);
    }

    // Phase 2

    // // MtAs with P2's Pailier public key:
    // let (k_2_gamma_1, k_2_omega_1) = {
    //   let k_2_gamma_1 = {
    //     let mta = MtA::new(num_bits);
    // 
    //     let mut alice = Alice::new(&k_2);
    //     let mut bob = Bob::new(&gamma_1);
    // 
    //     let c_a = alice.calc_c_a(num_bits, &mta, &mut *rng);
    //     let c_b = bob.calc_c_b_and_beta(&c_a, &mta, &mut *rng);
    // 
    //     alice.calc_alpha(&c_b, &mta);
    //     let alpha = alice.alpha.clone().unwrap();
    //     let beta = bob.beta.clone().unwrap();
    //     alpha + beta
    //   };
    //  
    //   let k_2_omega_1 = {
    //     let mta = MtA::new(num_bits);
    // 
    //     let mut alice = Alice::new(&k_2);
    //     let mut bob = Bob::new(&omega_1);
    // 
    //     let c_a = alice.calc_c_a(num_bits, &mta, &mut *rng);
    //     let c_b = bob.calc_c_b_and_beta(&c_a, &mta, &mut *rng);
    // 
    //     alice.calc_alpha(&c_b, &mta);
    //     let alpha = alice.alpha.clone().unwrap();
    //     let beta = bob.beta.clone().unwrap();
    //     alpha + beta
    //   };
    //   (k_2_gamma_1, k_2_omega_1)
    // };
    // 
    // // - Player 1
    // let delta_1 = &k_1 * &gamma_1 + &k_1_gamma_2;
    // let sigma_1 = &k_1 * &omega_1 + &k_1_omega_2;
    // 
    // // - Player 2
    // let delta_2 = &k_2 * &gamma_2 + &k_2_gamma_1;
    // let sigma_2 = &k_2 * &omega_2 + &k_2_omega_1;
    // 
    // // ** Phase 3
    // 
    // // P_1 and P_2 broadcast delta_1 and delta_2 respectively
    // // and both calculate delta and then the inverse of delta
    // let delta = &delta_1 + &delta_2;
    // let delta_inv = delta.inv().unwrap(); // TODO mod by group order
    // 
    // // ** Phase 4
    // 
    // // P_1 and P_2 decommit gamma_1*G and gamma_2*G respectively and broadcast
    // let gamma_1_g = comm_pair_1.decomm.m;
    // // TODO assert that gamma_1_g + comm_pair_1.decomm.r * h == comm_pair_1.comm
    // 
    // let gamma_2_g = comm_pair_2.decomm.m;
    // // TODO assert that gamma_2_g + comm_pair_2.decomm.r * h == comm_pair_2.comm
    // 
    // // R = k^-1 * G 
    // let R = delta_inv * (gamma_1_g + gamma_2_g);
    // 
    // let r_x = Scalar::from(45u8); // TODO get the x-coordinate of R r_x instead
    // 
    // let r = r_x; // TODO mod by group order
    // 
    // // ** Phase 5
    // 
    // // - Player 1
    // // calculate s_1 = m * k_1 + r * sigma_1
    // let s_1 = m * k_1 + r * sigma_1;
    // 
    // // - Player 2
    // // calculate s_2 = m * k_2 + r * sigma_2
    // let s_2 = m * k_2 + r * sigma_2;
    // 
    // // TODO take commit-open-verify steps before sharing s_1 and s_2
    // let s = &s_1 + &s_2; 
    // 
    // // signature is (r, s)
    // // TODO verify signature. fails if signature is invalid
    // 
    // Signature { r, s }

    Signature { r: Scalar::zero(), s: Scalar::zero() }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::protocols::gg18::key_gen::gen_keys;

  #[test]
  fn test_gen_sig() {
    let players = gen_keys(3).unwrap();
    let m = b"test".to_vec();
    let _sig = sign_by_2_parties(&m,  &players[0], &players[1]);
  }
}
