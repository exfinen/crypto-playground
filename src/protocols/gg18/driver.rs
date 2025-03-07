#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::{
  building_block::{
    mta::MtA,
    secp256k1::scalar::Scalar,
    util::get_32_byte_rng,
  },
  protocols::gg18::{
    player::Player,
    signing::Signature,
  },
};
use rug::Integer;
use std::thread;

pub fn generate_keys() {
  let num_players = 3;
  let q = Integer::from(123u8); // TODO change to secp256k1 base field order

  let mut players: Vec<Player> =
    (0..num_players).map(|i| Player::new(&q, i, num_players)).collect();

  let handles = vec![];
  for player in &mut players {
    let handle = thread::spawn(|| {
      player.generate_key();
    });
    handles.push(handle);
  }

  for handle in handles {
    handle.join().unwrap();
  }
}

//     let (KGC_i, E_i) = player.key_gen.phase_1();
//     bcast_KGC_is.push(KGC_i);
//     bcast_E_is.push(E_i);
//   }
// 
// 
//   // Phase 1
//   let mut bcast_KGC_is = vec![];
//   let mut bcast_E_is = vec![];
// 
//   for player in &mut players {
//     let (KGC_i, E_i) = player.key_gen.phase_1();
//     bcast_KGC_is.push(KGC_i);
//     bcast_E_is.push(E_i);
//   }
// 
//   // Phase 2
//   let mut bcast_KGD_is = vec![];
//   for player in &mut players {
//     let KGD_i = player.key_gen.phase_2_1();
//     bcast_KGD_is.push(KGD_i);
//   }
// 
//   let KGC_is_KDC_is = bcast_KGC_is.iter().zip(bcast_KGD_is.iter()).collect();
//   let mut U_is = vec![];
//   for player in &mut players {
//     let U_i = player.key_gen.phase_2_2(&KGC_is_KDC_is)?;
//     U_is.push(U_i);
//   }
// 
//   let mut A_is = vec![];
//   for player in &mut players {
//     let A_i = player.key_gen.phase_2_3();
//     A_is.push(A_i);
//   }
// 
//   let mut p_is_list = vec![];
//   for (i, player) in players.iter().enumerate() {
//     let eval_point = i + 1;
//     let p_is: Vec<Scalar> = players.iter()
//       .map(|p| p.key_gen.phase_2_4_eval_p(eval_point)).collect();
//     player.key_gen.phase_2_4(&p_is, &U_is[i], &A_is)?;
//     p_is_list.push(p_is);
//   }
// 
//   for x in (&mut players).iter_mut().zip(p_is_list.iter()) {
//     let player = x.0;
//     let p_is = x.1;
//     player.phase_2_5(&p_is, &A_is);
//   }
// 
//   // broadcast X_i to other players
//   for (i, this_player) in players.iter().enumerate() {
//     for (j, other_player) in players.iter().enumerate() {
//       if i == j { // this_player already has its own shard public key
//         continue;
//       }
//       // TODO fix this
//       // this_player.X_is[i] = other_player.X_i;
//     }
//   }
// 
//   // Phase 3 (TO BE IMPLEMENTED)
// }

pub fn sign_message_by_two_parties(
  _msg: &Vec<u8>,
  paillier_n: &Integer,
  player_1: &Player,
  player_2: &Player,
) -> Signature {
  let r = Scalar::rand();
  let s = Scalar::rand();

  let mut players = vec![player_1, player_2];

  // phase 1
  let mut bcast_C_is = vec![];
  for player in &mut players {
    let C_i = player.signing.phase_1();
    bcast_C_is.push(C_i);
  }

  // phase 2
  let num_bits = 256u32;

  // MtA with player 1's k_i and player 2's gamma_i
  let (c_a, rp_a_lt_q3) = player_1.signing.phase_2_alice_to_bob(
    num_bits,
    paillier_n,
  );

  let (c_b, beta) = player_2.signing.phase_2_bob_to_alice_gamma_i(
    &c_a,
    &q,
    &player_1.pk,
    &rp_a_lt_q3,
  );

  player_1.signing.phase_2_alice_obtains_k_i_gamma_i(
    &c_b,
    &beta,
    &rp_b_it_q3,
    &rp_b_lt_q3_bp_le_q7,
  );

  Signature { r, s }
}


























