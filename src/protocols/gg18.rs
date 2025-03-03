#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::{
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
};
use rug::{Integer, Complete};

pub struct Signature {
  pub r: Scalar,
  pub s: Scalar,
}

pub struct KeyGenPlayer {
  player_id: usize,
  q: Integer,
  u_i: Option<Scalar>, // sk
  phase1_comm_pair: Option<CommitmentPair>,
  paillier: PaillierInstance,
  pk: Option<Point>,
  p_i: Option<Box<dyn Fn(usize) -> Scalar>>,
  a_i: Option<Scalar>,
  A_i: Option<Point>,
  x_i: Option<Scalar>, // shard private key
  X_i: Option<Point>, // shared public key
}

impl KeyGenPlayer {
  pub fn new(q: &Integer, player_id: usize) -> Self {
    let q_sig_bits = q.significant_bits();
    let paillier = Paillier::new(q_sig_bits, GCalcMethod::Random);

    Self {
      player_id,
      q: q.clone(),
      u_i: None,
      phase1_comm_pair: None,
      paillier,
      pk: None,
      p_i: None,
      a_i: None,
      A_i: None,
      x_i: None,
      X_i: None,
    }
  }

  pub fn phase_1(&mut self) -> (Point, PublicKey) {
    self.u_i = Some(Scalar::rand());
    let pedersen = PedersenCommitment::new();

    let blinding_factor = &Scalar::rand();
    self.phase1_comm_pair = Some(
      pedersen.commit(&self.u_i.unwrap(), blinding_factor)
    );

    (self.phase1_comm_pair.unwrap().comm.clone(), self.paillier.pk.clone())
  }

  // call this after phase 1
  pub fn all_pubkeys_distinct(points: &Vec<PublicKey>) -> bool {
    for i in 0..points.len() {
      for j in i+1..points.len() {
        if points[i].n == points[j].n {
          return false;
        }
      }
    }
    true
  }

  // Each player P_i broadcasts KGD_i
  fn phase_2_1(&self) -> Decommitment {
    self.phase1_comm_pair.unwrap().decomm.clone()
  }

  // Decommit KGC_i/KGD_i to obtain U_i (=u_i*G)
  // Then: 
  // - calculate PK = sum(U_i)
  // - return validated commitments
  fn phase_2_2(
    &mut self,
    comm_decomms: &Vec<(&Point,&Decommitment)>,
  ) -> Result<Vec<Point>, &'static str> {
    // aggregate commitments to construct the public key
    // making sure each commitment is valid
    let g = Point::get_base_point();
    let mut pk = Point::point_at_infinity();

    let mut U_is = vec![];
    for comm_decomm in comm_decomms {
      let (comm, decomm) = comm_decomm;
      let comm_rec = decomm.m + g * decomm.r;
      if &comm_rec != *comm {
        return Err("Phase 2-2: Invalid commitment");
      }
      pk = pk + *comm;
      U_is.push(*comm.clone());
    }
    self.pk = Some(pk);
    Ok(U_is)
  }

  // each player constructs a polynomial of degree 1:
  // p_i(x) = u_i + a_i*x (a_i->$Z_p)
  fn phase_2_3(&mut self) -> Point {
    let a_i = Scalar::rand();
    let u_i = self.u_i.unwrap();
    let G = Point::get_base_point();
    self.p_i = Some(Box::new(move |x: usize| { u_i + a_i * Scalar::from(x) }));
    self.A_i = Some(G * a_i);

    self.A_i.unwrap().clone()
  }

  fn phase_2_4_eval_p(&self, i: usize) -> Scalar {
    self.p_i.as_ref().unwrap()(i)
  }

  // using Feldman VSS, verify that the same polynomial is used
  // to generate all shares
  fn phase_2_4(
    &self,
    p_is: &Vec<Scalar>,
    U_is: &Vec<Point>,
    A_is: &Vec<Point>,
  ) -> Result<(), &'static str> {
    let g = Point::get_base_point();
    for x in p_is.iter().zip(U_is.iter()).zip(A_is.iter()) {
      let ((p_i, U_i), A_i) = x;
      let lhs = g * p_i;
      let rhs = U_i + A_i;
      if lhs != rhs {
        return Err("Phase 2-4: Malformed polynomial");
      }
    }
    Ok(())
  }

  // calculate:
  // - shard private key: sum(u_i) + sum(a_i)
  // - shared public key: PK + sum(A_i)
  fn phase_2_5(&mut self, p_is: &Vec<Scalar>, A_is: &Vec<Point>) {
    let sum_p_is = p_is.iter().fold(Scalar::zero(), |acc, p| acc + *p);
    self.x_i = Some(sum_p_is);

    let sum_A_i = A_is.iter().fold(self.pk.unwrap(), |acc, A| acc + *A);
    let pk = &self.pk.unwrap();
    self.X_i = Some(pk + sum_A_i);
  }
}

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

fn generate_keys(
  num_players: usize,
) {
  ////// Prepare

  // Player 1
  let a1 = Scalar::rand();
  let p1 = |x: u8| { u_is[0] + a1 * Scalar::from(x) };
  let A1 = G * a1;

  let p1_of_1 = p1(1);
  let p1_of_2 = p1(2); // send to Player 2
  let p1_of_3 = p1(3); // send to Player 3

  // Player 2
  let a2 = Scalar::rand();
  let p2 = |x: u8| { u_is[1] + a2 * Scalar::from(x) };
  let A2 = G * a2;

  let p2_of_1 = p2(1); // send to Player 1
  let p2_of_2 = p2(2);
  let p2_of_3 = p2(3); // send to Player 3

  // Player 3
  let a3 = Scalar::rand();
  let p3 = |x: u8| { u_is[2] + a3 * Scalar::from(x) };
  let A3 = G * a3;

  let p3_of_1 = p3(1); // send to Player 1
  let p3_of_2 = p3(2); // send to Player 2
  let p3_of_3 = p3(3);

  ////// Private data

  //// Player 1

  // Veify
  assert_eq!(G * p1_of_1, U1 + A1);
  assert_eq!(G * p2_of_1, U2 + A2);
  assert_eq!(G * p3_of_1, U3 + A3);

  // Calculate shard private key
  let x1 = p1_of_1 + p2_of_1 + p3_of_1;

  // Calculate shared public key
  let X1 = &PK + &A1 + &A2 + &A3;

  //// Player 2

  // Verify
  let two = Scalar::from(2u8);
  assert_eq!(G * p1_of_2, U1 + A1 * &two);
  assert_eq!(G * p2_of_2, U2 + A2 * &two);
  assert_eq!(G * p3_of_2, U3 + A3 * &two);

  // Calculate shard private key
  let x2 = p1_of_2 + p2_of_2 + p3_of_2;

  // Calculate shared public key
  let X2 = &PK + &A1 * &two + &A2 * &two + &A3 * &two;

  //// Player 3

  // Verify
  let three = Scalar::from(3u8);
  assert_eq!(G * p1_of_3, U1 + A1 * &three);
  assert_eq!(G * p2_of_3, U2 + A2 * &three);
  assert_eq!(G * p3_of_3, U3 + A3 * &three);

  // Calculate shard private key
  let x3 = p1_of_3 + p2_of_3 + p3_of_3;

  // Calculate shared public key
  let X3 = &PK + &A1 * &three +j &A2 * &three + &A3 * &three;

  ///// Use Lagrange interpolation to recover PK and sk by
  ///// Player 1 and Player 2

  // i = 1, j = 2
  let calc_lambda_i_j = |i, j| { j / (j - i) };
  let calc_lambda_j_i = |i, j| { i - j };
  let lambda_i_j = calc_lambda_i_j(1, 2); // lamb Scalar::from(2);
  let lambda_j_i = calc_lambda_j_i(1, 2); // Scalar::from(1).inv();

  let omega_1 = lambda_i_j * x1;
  let omega_2 = lambda_j_i * x2;
}


pub fn gen_keys(num_players: usize) -> Result<(), &'static str> {
  let q = Integer::from(123u8); // TODO change to secp256k1 base field order

  // Phase 1
  let mut players: Vec<KeyGenPlayer> =
    (0..num_players).map(|i| KeyGenPlayer::new(&q, i)).collect();

  let mut bcast_KGC_is = vec![];
  let mut bcast_E_is = vec![];

  for player in &mut players {
    let (KGC_i, E_i) = player.phase_1();
    bcast_KGC_is.push(KGC_i);
    bcast_E_is.push(E_i);
  }

  // Phase 2
  let mut bcast_KGD_is = vec![];
  for player in &mut players {
    let KGD_i = player.phase_2_1();
    bcast_KGD_is.push(KGD_i);
  }

  let KGC_is_KDC_is = bcast_KGC_is.iter().zip(bcast_KGD_is.iter()).collect();
  let mut U_is = vec![];
  for player in &mut players {
    let U_i = player.phase_2_2(&KGC_is_KDC_is)?;
    U_is.push(U_i);
  }

  let mut A_is = vec![];
  for player in &mut players {
    let A_i = player.phase_2_3();
    A_is.push(A_i);
  }

  let mut p_is_list = vec![];
  for (i, player) in players.iter().enumerate() {
    let eval_point = i + 1;
    let p_is: Vec<Scalar> = players.iter().map(|p| p.phase_2_4_eval_p(eval_point)).collect();
    player.phase_2_4(&p_is, &U_is[i], &A_is)?;
    p_is_list.push(p_is);
  }

  for x in (&mut players).iter_mut().zip(p_is_list.iter()) {
    let player = x.0;
    let p_is = x.1;
    player.phase_2_5(&p_is, &A_is);
  }

  // Phase 3 (TO BE IMPLEMENTED)

  Ok(())
}

pub fn sign(
  m: Vec<u8>, // message to sign
  players: Vec<usize>, // players that participate in the signing
  omega_1: Scalar,
  omega_2: Scalar,
) -> Signature {
  // // Phase 1
  // let pedersen = PedersenCommitment::new();
  // 
  // // - Player 1
  // let k_1 = Scalar::rand();
  // let gamma_1 = Scalar::rand();
  // 
  // // Computes [C_i, D_i] = Com(gamma_i * G)
  // let comm_pair_1 = {
  //     let blinding_factor = &Scalar::rand();
  //     pedersen.commit(&gamma_1, blinding_factor)
  // };
  // 
  // // - Player 2
  // let k_2 = Scalar::rand();
  // let gamma_2 = Scalar::rand();
  // 
  // let comm_pair_2 = {
  //     let blinding_factor = &Scalar::rand();
  //     pedersen.commit(&gamma_2, blinding_factor)
  // };
  // 
  // // broadcast comm_pair_{1,2}.comm
  // 
  // // >> Phase 2
  // let num_bits = 256;
  // let mut rng = get_32_byte_rng();
  // 
  // let n = Integer::from(123u8);
  // let mta = MtA::new(&n);
  // 
  // // MtAs wth P1's Paillier public key:
  // let (k_1_gamma_2, k_1, omega_2) = {
  //   // k_1, gamma_2 -> k_1 * gamma_2
  //   let k_1_gamma_2 = {
  //     let k_1 = Integer::from(&k_1);
  //     let party_1 = Alice::new(
  //       num_bits,
  //       &k_1,
  //       &mut rng,
  //     );
  //     let party_2 = Bob::new(
  //       Integer::from(&gamma_2),
  //       &party_1.c_a,
  //       &party_1.rp_a_lt_q3,
  //       &party_1.pk,
  //       &mta,
  //     );
  //     let alpha = party_1.calc_alpha(
  //       &party_2.c_b,
  //       &party_2.rp_b_lt_q3,
  //       &party_2.rp_b_lt_q3_bp_le_q7,
  //     ).unwrap();
  // 
  //     alpha + party_2.beta
  //   };
  // 
  //   // k_1, omega_2 -> k_1 * omega_2
  //   let k_1_omega_2 = {
  // 
  //     let mut alice = Alice::new(&k_1);
  //     let mut bob = Bob::new(&omega_2);
  // 
  //     alice.calc_alpha(
  //       &c_b, &mta);
  //     let alpha = alice.alpha.clone().unwrap();
  //     let beta = bob.beta.clone().unwrap();
  //     alpha + beta
  //   };
  //   (k_1_omega_2, k_1, omega_2)
  // };
  // 
  // 
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

pub fn run() {
  let num_players = 3;
  match gen_keys(num_players) {
    Ok(_) => (),
    Err(e) => println!("Key generation failed: {}", e),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_gen_keys() {
    gen_keys(3);
  }

  #[test]
  fn test_gen_sig() {
    let keys = gen_keys(3);
    let m = "test";
    let _sig = sign(&m, vec![0, 1], &keys);
  }
}



