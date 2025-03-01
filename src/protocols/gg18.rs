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
  },
  pedersen_secp256k1::{
    CommitmentPair,
    PedersenCommitment,
  },
  secp256k1::{point::Point, scalar::Scalar},
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

fn check_commitment(G: &Point, cp: &CommitmentPair) -> bool {
  let lhs = cp.decomm.m + G * cp.decomm.r;
  let rhs = cp.comm;
  lhs == rhs
}

fn main() {
  let num_players = 3;

  let G = Point::get_base_point();

  ////// Key generation

  ///// Phase 1:

  // Each player P_i select u_i in Z_q
  let u_is: Vec<Scalar> =
    (0..num_players)
    .map(|_| Scalar::rand())
    .collect();

  // Computes [KGC_i, KGD_i] = Com(u_i * G)
  let pedersen = PedersenCommitment::new();
  let comm_pairs: Vec<CommitmentPair> =
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

  ///// Phase 2:

  // All 3 parties calculate the pulic key PK = U_1 + U_2 + U_3 and
  // the private key is sk = x = u_1 + u_2 + u_3 (unknown to all 3 parties)
  //
  // Using Feldman-VSS Protocol, each player constructs a polynomial of degree 1
  // p_i(x) = u_i + a_i*x (a_i->$Z_p)

  
  // Each player P_i broadcasts KDG_i and decommit it,
  // obtaining U_i (U_i=u_i*G)
  let U1 = comm_pairs[0].decomm.m;
  let U2 = comm_pairs[1].decomm.m;
  let U3 = comm_pairs[1].decomm.m;

  let PK = U1 + U2 + U3;

  // check if each party didn't change their mind
  assert!(check_commitment(&G, &comm_pairs[0])); 
  assert!(check_commitment(&G, &comm_pairs[1]); 
  assert!(check_commitment(&G, &comm_pairs[2])); 

  //// Prepare

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

  //// Private data

  /// Player 1

  // Veify
  assert_eq!(G * p1_of_1, U1 + A1);
  assert_eq!(G * p2_of_1, U2 + A2);
  assert_eq!(G * p3_of_1, U3 + A3);

  // Calculate shard private key
  let x1 = p1_of_1 + p2_of_1 + p3_of_1;

  // Calculate shared public key
  let X1 = &PK + &A1 + &A2 + &A3;

  /// Player 2

  // Verify
  let two = Scalar::from(2u8);
  assert_eq!(G * p1_of_2, U1 + A1 * &two);
  assert_eq!(G * p2_of_2, U2 + A2 * &two);
  assert_eq!(G * p3_of_2, U3 + A3 * &two);

  // Calculate shard private key
  let x2 = p1_of_2 + p2_of_2 + p3_of_2;

  // Calculate shared public key
  let X2 = &PK + &A1 * &two + &A2 * &two + &A3 * &two;

  /// Player 3

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

  ////// Signature generation by Player 1 and Player 2

  //// Phase 1
  let pedersen = PedersenCommitment::new();

  /// Player 1
  let k_1 = Scalar::rand();
  let gamma_1 = Scalar::rand();

  // Computes [C_i, D_i] = Com(gamma_i * G)
  let comm_pair_1 = {
      let blinding_factor = &Scalar::rand();
      pedersen.commit(gamma_1, blinding_factor)
  };

  /// Player 2
  let k_2 = Scalar::rand();
  let gamma_2 = Scalar::rand();

  let comm_pair_2 = {
      let blinding_factor = &Scalar::rand();
      pedersen.commit(gamma_2, blinding_factor)
  };

  // broadcast comm_pair_{1,2}.comm

  //// Phase 2
  let num_bits = 256;
  let mut rng = get_32_byte_rng();

  // MtAs wth P1's Paillier public key:
  let (k_1_gamma_2, k_1, omega_2) = {
    // k_1, gamma_2 -> k_1 * gamma_2
    let k_1_gamma_2 = {
      let mta = MtA::new(num_bits);

      let mut alice = Alice::new(&k_1);
      let mut bob = Bob::new(&gamma_2);

      let c_a = alice.calc_c_a(num_bits, &mta, &mut *rng);
      let c_b = bob.calc_c_b_and_beta(&c_a, &mta, &mut *rng);

      alice.calc_alpha(&c_b, &mta);
      let alpha = alice.alpha.clone().unwrap();
      let beta = bob.beta.clone().unwrap();
      alpha + beta
    };

    // k_1, omega_2 -> k_1 * omega_2
    let k_1_omega_2 = {
      let mta = MtA::new(num_bits);

      let mut alice = Alice::new(&k_1);
      let mut bob = Bob::new(&omega_2);

      let c_a = alice.calc_c_a(num_bits, &mta, &mut *rng);
      let c_b = bob.calc_c_b_and_beta(&c_a, &mta, &mut *rng);

      alice.calc_alpha(&c_b, &mta);
      let alpha = alice.alpha.clone().unwrap();
      let beta = bob.beta.clone().unwrap();
      alpha + beta
    };
    (k_1_omega_2, k_1, omega_2)
  };


  // MtAs with P2's Pailier public key:
  let (k_2_gamma_1, k_2_omega_1) = {
    let k_2_gamma_1 = {
      let mta = MtA::new(num_bits);

      let mut alice = Alice::new(&k_2);
      let mut bob = Bob::new(&gamma_1);

      let c_a = alice.calc_c_a(num_bits, &mta, &mut *rng);
      let c_b = bob.calc_c_b_and_beta(&c_a, &mta, &mut *rng);

      alice.calc_alpha(&c_b, &mta);
      let alpha = alice.alpha.clone().unwrap();
      let beta = bob.beta.clone().unwrap();
      alpha + beta
    };
   
    let k_2_omega_1 = {
      let mta = MtA::new(num_bits);

      let mut alice = Alice::new(&k_2);
      let mut bob = Bob::new(&omega_1);

      let c_a = alice.calc_c_a(num_bits, &mta, &mut *rng);
      let c_b = bob.calc_c_b_and_beta(&c_a, &mta, &mut *rng);

      alice.calc_alpha(&c_b, &mta);
      let alpha = alice.alpha.clone().unwrap();
      let beta = bob.beta.clone().unwrap();
      alpha + beta
    };
    (k_2_gamma_1, k_2_omega_1)
  };

  /// Player 1
  let delta_1 = &k_1 * &gamma_1 + &k_1_gamma_2;
  let sigma_1 = &k_1 * &omega_1 + &k_1_omega_2;

  /// Player 2
  let delta_2 = &k_2 * &gamma_2 + &k_2_gamma_1;
  let sigma_2 = &k_2 * &omega_2 + &k_2_omega_1;

  //// Phase 3
  
  // P_1 and P_2 broadcast delta_1 and delta_2 respectively
  // and both calculate delta and then the inverse of delta
  let delta = &delta_1 + &delta_2;
  let delta_inv = delta.inv().unwrap(); // TODO mod by group order

  //// Phase 4

  // P_1 and P_2 decommit gamma_1*G and gamma_2*G respectively and broadcast
  let gamma_1_g = comm_pair_1.decomm.m;
  // TODO assert that gamma_1_g + comm_pair_1.decomm.r * h == comm_pair_1.comm
 
  let gamma_2_g = comm_pair_2.decomm.m;
  // TODO assert that gamma_2_g + comm_pair_2.decomm.r * h == comm_pair_2.comm

  // R = k^-1 * G 
  let R = delta_inv * (gamma_1_g + gamma_2_g);
 
  let r_x = Scalar::from(45u8); // TODO get the x-coordinate of R r_x instead

  let r = r_x; // TODO mod by group order

  //// Phase 5

  // TODO hash message instead
  let m = Scalar::from(12u8);

  /// Player 1
  // calculate s_1 = m * k_1 + r * sigma_1
  let s_1 = m * k_1 + r * signa_1;

  /// Player 2
  // calculate s_2 = m * k_2 + r * sigma_2
  let s_2 = m * k_2 + r * signa_2;

  // TODO take commit-open-verify steps before sharing s_1 and s_2
  let s = &s_1 + &s_2; 

  // signature is (r, s)
  // TODO verify signature. fails if signature is invalid
}




































