#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::{
  building_block::secp256k1::{
    affine_point::AffinePoint,
    jacobian_point::JacobianPoint,
    scalar::Scalar,
  },
  protocols::gg18::{
    mta::{
      Alice,
      Bob,
      MtA,
    },
    paillier::PublicKey,
    pedersen_secp256k1::{
      CommitmentPair, Decommitment, PedersenCommitment
    },
    network::{
      BroadcastId,
      Network,
      UnicastId,
      UnicastDest,
    },
    signature::Signature,
    signer_id::SignerId,
  },
};
use std::{
  ops::Deref,
  sync::Arc,
};
use rug::Integer;

pub struct Signer {
  signer_id: SignerId,
  num_bits: u32,
  paillier_n: Integer,
  network: Arc<Network>,
  q: Integer,
}

const UNICAST_TO_SIGNER_A: UnicastId = UnicastId(1);
const UNICAST_TO_SIGNER_B: UnicastId = UnicastId(2);

const C_I_BROADCAST: BroadcastId = BroadcastId(11);
const D_I_BROADCAST: BroadcastId = BroadcastId(12);
const DELTA_I_BROADCAST: BroadcastId = BroadcastId(13);
const S_I_COMM_BROADCAST: BroadcastId = BroadcastId(14);

macro_rules! define_scalar_wrappers {
  ($($name:ident),*) => {
    $(
      pub struct $name(pub Scalar);

      impl Deref for $name {
        type Target = Scalar;

        fn deref(&self) -> &Self::Target {
          &self.0
        }
      }
    )*
  };
}
define_scalar_wrappers!(K_i, Gamma_i, Delta_i, Sigma_i);

impl Signer {
  pub fn new(
    signer_id: SignerId,
    num_bits: u32,
    paillier_n: &Integer,
    network: Arc<Network>,
  ) -> Self {
    // secp256k1 group order
    let q = Integer::from_str_radix(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
      16,
    ).unwrap();
    Self {
      signer_id,
      num_bits,
      paillier_n: paillier_n.clone(),
      network,
      q,
    }
  }

  pub async fn run_phase_1(&mut self)
    -> (K_i, Gamma_i, Vec<JacobianPoint>, CommitmentPair, PedersenCommitment) {

    // select k_i and gamma_i in Z_q and broadcasts C_i
    let k_i = Scalar::rand();
    let gamma_i = Scalar::rand();
    
    // Computes [C_i, D_i] = Com(gamma_i * G)
    let pedersen = PedersenCommitment::new();
    let blinding_factor = &Scalar::rand();
    let comm_pair = pedersen.commit(&gamma_i, blinding_factor);

    // broadcast C_i
    self.network.broadcast(
      &C_I_BROADCAST,
      &comm_pair.comm.serialize(),
    ).await;

    // correct all broadcast C_is
    let C_is: Vec<JacobianPoint> = {
      let xs = self.network.receive_broadcasts(C_I_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    (K_i(k_i), Gamma_i(gamma_i), C_is, comm_pair, pedersen)
  }

  pub async fn perfrom_mta_as_alice(
    &mut self,
    alice_id: &SignerId,
    additive_share: &Scalar,
  ) -> Scalar {
    // TODO use this to get q, q^3, and q^5 from n
    let _mta = MtA::new(&self.paillier_n);

    let alice = Alice::new(
      self.num_bits,
      &additive_share.into(),
    );
 
    let bob_id = &alice_id.the_other();

    // Send C_A, E_A(pk), and range proof to Bob
    let to_bob = &UnicastDest::new(
      UNICAST_TO_SIGNER_B,
      alice_id.into(),
      bob_id.into(),
    );
    self.network.unicast(to_bob, &bincode::serialize(&alice.c_a).unwrap()).await;
    self.network.unicast(to_bob, &bincode::serialize(&alice.pk).unwrap()).await;
    self.network.unicast(to_bob, &bincode::serialize(&alice.rp_a_lt_q3).unwrap()).await;

    // Receive C_b, beta, and range proofs from Bob
    let to_alice = &UnicastDest::new(
      UNICAST_TO_SIGNER_A,
      bob_id.into(),
      alice_id.into(),
    );
    let c_b: Integer = {
      let x = self.network.receive_unicast(to_alice).await;
      bincode::deserialize(&x).unwrap()
    };
    let beta: Integer = {
      let x = self.network.receive_unicast(to_alice).await;
      bincode::deserialize(&x).unwrap()
    };
    let rp_b_lt_q3: Integer = {
      let x = self.network.receive_unicast(to_alice).await;
      bincode::deserialize(&x).unwrap()
    };
    let rp_b_lt_q3_bp_le_q7: Integer = {
      let x = self.network.receive_unicast(to_alice).await;
      bincode::deserialize(&x).unwrap()
    };
  
    // Calculate Alpha
    let alpha = alice.calc_alpha(
      &c_b,
      &rp_b_lt_q3,
      &rp_b_lt_q3_bp_le_q7,
    ).unwrap();

    // Calculate multiplicative share
    (alpha + beta).into()
  }

  pub async fn perfrom_MtA_as_Bob(
    &mut self,
    bob_id: &SignerId,
    additive_share: &Scalar,
  ) {
    let alice_id = &bob_id.the_other();

    // Receive c_a, pk, and range proof from Alice
    let to_bob = &UnicastDest::new(
      UNICAST_TO_SIGNER_B,
      alice_id.into(),
      bob_id.into(),
    );
    let c_a: Integer = {
      let x = self.network.receive_unicast(to_bob).await;
      bincode::deserialize(&x).unwrap()
    };
    let pk: PublicKey = {
      let x = self.network.receive_unicast(to_bob).await;
      bincode::deserialize(&x).unwrap()
    };
    let rp_a_lt_q3: Integer = {
      let x = self.network.receive_unicast(to_bob).await;
      bincode::deserialize(&x).unwrap()
    };

    // Calculate C_B, beta, and range proofs
    let bob = Bob::new(
      &c_a,
      &self.q,
      &pk,
      &rp_a_lt_q3,
      &additive_share.into(),
    );

    // Send C_b, beta, and range proofs to Alice
    let to_alice = &UnicastDest::new(
      UNICAST_TO_SIGNER_A,
      bob_id.into(),
      alice_id.into(),
    );
    self.network.unicast(to_alice, &bincode::serialize(&bob.c_b).unwrap()).await;
    self.network.unicast(to_alice, &bincode::serialize(&bob.beta).unwrap()).await;
    self.network.unicast(to_alice, &bincode::serialize(&bob.rp_b_lt_q3).unwrap()).await;
    self.network.unicast(to_alice, &bincode::serialize(&bob.rp_b_lt_q3_bp_le_q7).unwrap()).await;
  }

  pub async fn run_phase_2_Player_A(
    &mut self,
    k_i: &Scalar,
    gamma_i: &Scalar,
    omega_i: &Scalar,
  ) -> (Delta_i, Sigma_i) {
    let k_i_gamma_i: Scalar = self.perfrom_mta_as_alice(
      &SignerId::A,
      k_i,
    ).await.into(); 

    let k_i_omega_i: Scalar = self.perfrom_mta_as_alice(
      &SignerId::A,
      k_i,
    ).await.into(); 

    self.perfrom_MtA_as_Bob(&SignerId::A, gamma_i).await;
    self.perfrom_MtA_as_Bob(&SignerId::A, omega_i).await;

    let delta_i = k_i * gamma_i + &k_i_gamma_i;
    let sigma_i = k_i * omega_i + &k_i_omega_i;

    (Delta_i(delta_i), Sigma_i(sigma_i))
  }

  pub async fn run_phase_2_Player_B(
    &mut self,
    k_i: &Scalar,
    gamma_i: &Scalar,
    omega_i: &Scalar,
  ) -> (Delta_i, Sigma_i) {
    self.perfrom_MtA_as_Bob(
      &SignerId::B,
      gamma_i,
    ).await;

    self.perfrom_MtA_as_Bob(
      &SignerId::B,
      omega_i,
    ).await;

    let k_i_gamma_i = self.perfrom_mta_as_alice(
      &SignerId::B,
      k_i,
    ).await; 

    let k_i_omega_i = self.perfrom_mta_as_alice(
      &SignerId::B,
      k_i,
    ).await; 
     
    let delta_i = k_i * gamma_i + &k_i_gamma_i;
    let sigma_i = k_i * omega_i + &k_i_omega_i;

    (Delta_i(delta_i), Sigma_i(sigma_i))
  }

  pub async fn run_phase_3(
    &mut self,
    delta_i: &Delta_i,
  ) -> Vec<Scalar> {
    // broadcast delta_i
    self.network.broadcast(
      &DELTA_I_BROADCAST,
      &delta_i.serialize(),
    ).await;

    // correct all broadcast delta_is
    let delta_is: Vec<Scalar> = {
      let xs = self.network.receive_broadcasts(DELTA_I_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    delta_is
  }

  pub async fn run_phase_4(
    &mut self,
    pedersen: &PedersenCommitment,
    decomm: &Decommitment,
    C_is: &Vec<JacobianPoint>,
    delta_inv: &Scalar,
  ) -> Result<Scalar, String> {
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
    for comm_pair in C_is.iter().zip(&D_is) {
      let (C_i, D_i) = &comm_pair;
      if !pedersen.verify(C_i, D_i) {
        return Err("Gamma decommitment failed".to_string());
      }
    }

    // TODO prove that the party know gamma_i using zk proof

    // R = k^-1 * G 
    let aggr_gamma: JacobianPoint = C_is.iter().fold(
      JacobianPoint::point_at_infinity(),
      |acc, c_i| acc + c_i
    );

    let jacob_R = aggr_gamma * delta_inv;

    // R is a Jacobian point, so convert it to Affine point
    let affine_R: AffinePoint = jacob_R.into();
    let r_x: Scalar = affine_R.x().into();

    // if r_x is 0, start over
    if r_x.is_zero() {
      return Err("r_x is zero".to_string());
    }
    Ok(r_x)
  }

  pub async fn run_phase_5(
    &mut self,
    k_i: &K_i,
    sigma_i: &Sigma_i,
    m: &Scalar,
    r: &Scalar,
  ) -> Result<Scalar,String> {
    let s_i = m * k_i.0 + r * sigma_i.0;

    // generate a commitment of s_i and broadcast
    let pedersen = PedersenCommitment::new();
    let blinding_factor = &Scalar::rand();
    let comm_pair = pedersen.commit(&s_i, &blinding_factor);

    self.network.broadcast(
      &S_I_COMM_BROADCAST,
      &comm_pair.comm.serialize(),
    ).await;

    // Correct all broadcast s_i commitments
    let comm_pairs: Vec<CommitmentPair> = {
      let xs = self.network.receive_broadcasts(S_I_COMM_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    // Verify the commitments
    for comm_pair in comm_pairs.iter() {
      if !pedersen.verify(&comm_pair.comm, &comm_pair.decomm) {
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
    let (k_i, gamma_i, C_is, comm_pair, pedersen) = self.run_phase_1().await;

    // Phase 2
    let (delta_i, sigma_i) = {
      if self.signer_id == SignerId::A {
        self.run_phase_2_Player_A(
          &k_i,
          &gamma_i,
          omega_i,
        ).await
      } else {
        self.run_phase_2_Player_B(
          &k_i,
          &gamma_i,
          omega_i,
        ).await
      }
    };

    // Phase 3
    let delta_inv = {
      let delta_is = self.run_phase_3(&delta_i).await;
      let aggr_delta = delta_is.iter().fold(Scalar::zero(), |acc, c_i| acc + c_i);
      aggr_delta.inv()
    };

    // Phase 4
    let r = self.run_phase_4(
      &pedersen,
      &comm_pair.decomm,
      &C_is,
      &delta_inv,
    ).await?;

    // Phase 5
    let s = self.run_phase_5(
      &k_i,
      &sigma_i,
      m,
      &r,
    ).await?;

    let sig = Signature {
      r: r.clone(),
      s: s.clone(),
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
    let paillier_n = Integer::from(421); // TODO fix this

    let player_a = Signer::new(
      num_parties,
      &paillier_n,
      Arc::clone(&network),
      PlayerId::A,
    );
    let player_b = Signer::new(
      num_parties,
      &paillier_n,
      Arc::clone(&network),
      PlayerId::B,
    );
    let players = vec![
      player_a,
      player_b,
    ];
    
    let m = "test";
    let omega_a = Scalar::from(1); // TODO use the value from the key
    let omega_b = Scalar::from(2);

    let handles = vec![
      spawn(async move {
        player_a.create_signature(
          m,
          omega_a,
        ).await;
      }),
      spawn(async move {
        player_b.create_signature(
          m,
          omega_b,
        ).await;
      }),
    ];

    for handle in handles {
      handle.await.unwrap();
    }
  }
}
