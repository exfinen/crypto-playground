#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::{
  building_block::{
    mta::{
      Alice,
      Bob,
      MtA,
    },
    pedersen_secp256k1::{
      CommitmentPair, Decommitment, PedersenCommitment
    },
    secp256k1::{
      point::Point,
      scalar::Scalar,
    },
  },
  protocols::gg18::network::{
    BroadcastId,
    Network,
    UnicastId,
  },
};
use std::sync::Arc;
use rug::Integer;

pub struct Signature {
  pub r: Scalar,
  pub s: Scalar,
}

pub enum PlayerId {
  A,
  B,
}

pub struct Player {
  num_bits: u32,
  paillier_n: Integer,
  network: Arc<Network>,
  player_id: PlayerId
}

const PARTY_A_UNICAST: UnicastId = UnicastId(1);
const PARTY_B_UNICAST: UnicastId = UnicastId(2);

const C_I_BROADCAST: BroadcastId = BroadcastId(11);
const D_I_BROADCAST: BroadcastId = BroadcastId(12);
const DELTA_I_BROADCAST: BroadcastId = BroadcastId(13);
const S_I_COMM_BROADCAST: BroadcastId = BroadcastId(14);

pub struct K_i(pub Integer);
pub struct Gamma_i(pub Integer);
pub struct Delta_i(pub Integer);
pub struct Sigma_i(pub Integer);

impl Player {
  pub fn new(
    num_bits: u32,
    paillier_n: &Integer,
    network: Arc<Network>,
    player_id: PlayerId,
  ) -> Self {
    Self {
      num_bits,
      paillier_n: paillier_n.clone(),
      network,
      player_id
    }
  }

  pub async fn run_phase_1(&mut self)
    -> (k_i, Gamma_i, Vec<Point>, CommitmentPair, PedersenCommitment) {

    // select k_i and gamma_i in Z_q and broadcasts C_i
    let k_i = Integer::from(Scalar::rand());
    let gamma_i = Integer::from(Scalar::rand());
    
    // Computes [C_i, D_i] = Com(gamma_i * G)
    let pedersen = PedersenCommitment::new();
    let blinding_factor = &Scalar::rand();
    let comm_pair = pedersen.commit(&Scalar::from(&gamma_i), blinding_factor);

    // broadcast C_i
    self.network.broadcast(
      &C_I_BROADCAST,
      &comm_pair.comm.serialize(),
    ).await;

    // correct all broadcast C_is
    let C_is: Vec<Point> = {
      let xs = self.network.receive_broadcasts(C_I_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    (K_i(k_i), Gamma_i(gamma_i), C_is, comm_pair, pedersen)
  }

  pub async fn perfrom_mta_as_alice(
    &mut self,
    additive_share: &Integer,
  ) -> Integer {
    let mta = MtA::new(&self.paillier_n);
    let alice = Alice::new(
      self.num_bits,
      additive_share,
    );
 
    // Send C_A, E_A(pk), and range proof to Bob
    self.network.unicast(PARTY_B_UNICAST, &alice.c_a.serialize()).await;
    self.network.unicast(PARTY_B_UNICAST, &alice.pk.serialize()).await;
    self.network.unicast(PARTY_B_UNICAST, &alice.rp_a_lt_q3.serialize()).await;

    // Receive C_b, beta, and range proofs from Bob
    let c_b = {
      let x = self.network.receive_unicast(PARTY_A_UNICAST).await;
      Point::deserialize(&x)
    };
    let beta = {
      let x = self.network.receive_unicast(PARTY_A_UNICAST).await;
      Scalar::deserialize(&x)
    };
    let rp_b_lt_q3 = {
      let x = self.network.receive_unicast(PARTY_A_UNICAST).await;
      Scalar::deserialize(&x)
    };
    let rp_b_lt_q3_bp_le_q7 = {
      let x = self.network.receive_unicast(PARTY_A_UNICAST).await;
      Scalar::deserialize(&x)
    };
  
    // Calculate Alpha
    let alpha = alice.calc_alpha(
      &c_b,
      &rp_b_lt_q3,
      &rp_b_lt_q3_bp_le_q7,
    ).unwrap();

    // Calculate multiplicative share
    alpha + beta
  }

  pub async fn perfrom_MtA_as_Bob(
    &mut self,
    additive_share: &Integer,
  ) {
    // Receive c_a, pk, and range proof from Alice
    let c_a = {
      let x = self.network.receive_unicast(PARTY_B_UNICAST).await;
      Point::deserialize(&x)
    };
    let pk = {
      let x = self.network.receive_unicast(PARTY_B_UNICAST).await;
      Point::deserialize(&x)
    };
    let rp_a_lt_q3 = {
      let x = self.network.receive_unicast(PARTY_B_UNICAST).await;
      Scalar::deserialize(&x)
    };

    // Calculate C_B, beta, and range proofs
    let bob = Bob::new(
      c_a,
      q,
      pk,
      rp_a_lt_q3,
      &additive_share,
    );

    // Send C_b, beta, and range proofs to Alice
    self.network.unicast(PARTY_A_UNICAST, &bob.c_b.serialize()).await;
    self.network.unicast(PARTY_A_UNICAST, &bob.beta.serialize()).await;
    self.network.unicast(PARTY_A_UNICAST, &bob.rp_b_lt_q3.serialize()).await;
    self.network.unicast(PARTY_A_UNICAST, &bob.rp_b_lt_q3_bp_le_q7.serialize()).await;
  }

  pub async fn run_phase_2_Player_A(
    &mut self,
    k_i: &Integer,
    gamma_i: &Integer,
  ) -> (Delta_i, Sigma_i) {
    let k_gamma = Self::perfrom_mta_as_alice(
      &k_i,
    ).await; 

    let k_omega = Self::perfrom_mta_as_alice(
      &k_i,
    ).await; 

    Self::perfrom_MtA_as_Bob(&gamma_i).await;
    Self::perfrom_MtA_as_Bob(&omega_i).await;

    let delta_i = &k_i * &gamma_i + &k_i_gamma_i;
    let sigma_i = &k_i * &omega_i + &k_i_omega_i;

    (Delta_i(delta_i), Sigma_i(sigma_i))
  }

  pub async fn run_phase_2_Player_B(
    &mut self,
    k_i: &Integer,
    gamma_i: &Integer,
    delta_i: &Integer,
    sigma_i: &Integer,
  ) -> (Delta_i, Sigma_i) {
    Self::perfrom_MtA_as_Bob(&gamma_i).await;
    Self::perfrom_MtA_as_Bob(&omega_i).await;

    let k_i_gamma_i = Self::perfrom_mta_as_alice(
      &k_i,
    ).await; 

    let k_i_omega_i = Self::perfrom_mta_as_alice(
      &k_i,
    ).await; 
     
    let delta_i = &k_i * &gamma_i + &k_i_gamma_i;
    let sigma_i = &k_i * &omega_i + &k_i_omega_i;

    (Delta_i(delta_i), Sigma_i(sigma_i))
  }

  pub async fn run_phase_3(
    &mut self,
    delta_i: &Delta_i,
  ) -> Vec<Integer> {
    // broadcast delta_i
    self.network.broadcast(
      &DELTA_I_BROADCAST,
      &delta_i.serialize(),
    ).await;

    // correct all broadcast delta_is
    let delta_is: Vec<Integer> = {
      let xs = network.receive_broadcasts(DELTA_I_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    delta_is
  }

  pub async fn run_phase_4(
    &mut self,
    pedersen: &PedersenCommitment,
    decomm: &Decommitment,
    C_is: &Vec<Point>,
    delta_inv: &Scalar,
  ) -> Result<Scalar, ()> {
    // broadcasst D_i
    self.network.broadcast(
      &D_I_BROADCAST,
      &decomm.serialize(),
    ).await;
    
    // correct all broadcast D_is
    let D_is: Vec<Decommitment> = {
      let xs = self.network.receive_broadcasts(D_I_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    // Decommit the committed value along with the blinding factor
    for comm_pair in C_is.iter().zip(&D_is.iter()) {
      let (C_i, D_i) = comm_pair;
      if !pedersen.verify(C_i, D_i) {
        return Err("Gamma decommitment failed".to_string());
      }
    }

    // TODO prove that the party know gamma_i using zk proof

    // R = k^-1 * G 
    let aggr_gamma: Point = C_is.iter().fold(Point::zero(), |acc, c_i| acc + c_i);

    let R: Point = aggr_gamma * delta_inv; // TODO mod by group order

    // R is a Jacobian point, so convert it to Affine point
    let z_inv_sq = R.z.inv().unwrap().square().unwrap();
    let r_x = R.x * z_inv_sq;  // TODO modulo field order

    // if r_x == 0, start over
    if r_x == Integer::ZERO() {
      return Err(());
    }
    Ok(r_x)
  }

  pub async fn run_phase_5(
    &mut self,
    comm_pair: &CommitmentPair,
    sigma_i: &Sigma_i,
  ) -> Scalar {
    let s_i = m * &k_i + &r * &sigma_i;

    // generate a commitment of s_i and broadcast
    pedersen = PedersenCommitment::new();
    let blinding_factor = &Scalar::rand();
    let comm_pair = pedersen.commit(&s_i, &blinding_factor);

    self.network.broadcast(
      &S_I_COMM_BROADCAST,
      &comm_pair.comm.serialize(),
    ).await;

    // Correct all broadcast s_i commitments
    let comm_pairs: Vec<CommitmentPair> = {
      let xs = network.receive_broadcasts(S_I_COMM_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    // Verify the commitments
    for comm_pair in comm_pairs.iter() {
      let (C_i, D_i) = comm_pair;
      if !pedersen.verify(C_i, D_i) {
        return Err("s_i decommitment failed".to_string());
      }
    }

    let s = comm_pairs.iter().fold(Scalar::zero(),
      |acc, comm_pair| acc + comm_pair.decomm.secret
    );
    Ok(s)
  }

  pub async fn create_signature(
    &mut self,
    m: &Scalar, // message to sign
    omega_i: &Scalar, // additive component of the private key
  ) -> Result<Signature, String> {
    // Phase 1
    let (k_i, gamma_i, C_is, comm_pair, pedersen) =
      Self::phase1(Arc::clone(&self.network)).await;

    // Phase 2
    let (delta_i, sigma_i) = {
      if self.player_id == PlayerId::A {
        Self::run_phase_2_Player_A(&k_i, &gamma_i).await
      } else {
        Self::run_phase_2_Player_B(&k_i, &gamma_i).await
      }
    };

    // Phase 3
    let delta_inv = {
      let delta_is = Self::run_phase_3(&delta_i).await;
      let aggr_delta = delta_is.iter().fold(Scalar::zero(), |acc, c_i| acc + c_i);
      aggr_delta.inv().unwrap() // TODO mod by group order
    };

    // Phase 4
    let r = Self::run_phase_4(
      &pedersen,
      &comm_pair.decomm,
      &C_is,
      &delta_inv,
    ).await;

    // Phase 5
    let s = Self::run_phase_5(
      &comm_pair,
      &sigma_i,
    ).await;

    let sig = Signature {
      r: Scalar::zero(),
      s: Scalar::zero(),
    };
    Ok(sig)
  }
}

  // let lambda_i_j = calc_lambda_i_j(1, 2); // 2
  // let lambda_j_i = calc_lambda_j_i(1, 2); // -1
  // 
  // let omega_1 = lambda_i_j * x1;
  // let omega_2 = lambda_j_i * x2;

  // i and j are evaluation points assigned to players
  // e.g. player i uses evaluation point i+1
  // fn calc_lambda_i_j(i: usize, j: usize) -> Scalar {
  //   assert!(i < j);
  //   let x = j / (j - i);
  //   Scalar::from(x)
  // }
  // 
  // // i and j are evaluation points assigned to players
  // // e.g. player i uses evaluation point i+1
  // fn calc_lambda_j_i(i: i32, j: i32) -> Scalar {
  //   assert!(i < j);
  //   let x = (i - j) * -1;  // i - j is always negative
  //   Scalar::from(x as usize).inv()
  // }
  // 

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::spawn;
  use std::sync::Arc;

  #[tokio::test]
  async fn test_key_gen() {
    let network = Arc::new(Network::new(3));
    let num_parties = 3;

    let mut players = vec![];
    let player_a = Player::new(
      num_parties,
      party_id,
      Arc::clone(&network),
      PlayerId::A,
    );

      parties.push(party);
    }

    let mut handles = vec![];
    for mut party in parties {
      handles.push(spawn(async move {
        party.create_signature().await;
      }));
    }

    for handle in handles {
      handle.await.unwrap();
    }
  }
}
