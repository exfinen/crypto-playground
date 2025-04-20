#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::{
  building_block::secp256k1::{
    jacobian_point::JacobianPoint,
    scalar::Scalar,
    util::secp256k1_group_order,
  },
  protocols::gg18::{
    mta::{
      Alice,
      Bob,
    },
    paillier::PublicKey,
    pedersen_secp256k1::{
      Decommitment,
      PedersenCommitment
    },
    network::{
      BroadcastId,
      Network,
      UnicastId,
      UnicastDest,
      ValueId,
    },
    signature::Signature,
    signer_id::SignerId,
  },
};
use std::sync::Arc;
use rug::Integer;
use rug::ops::Pow;

pub struct Signer {
  signer_id: SignerId,
  network: Arc<Network>,
  ss_group_order: Integer,
  pedersen: PedersenCommitment,
  M: Scalar,
  hasher: Box<dyn Fn(&Scalar) -> Scalar + Send + Sync>,
  omega_i: Scalar,

  // phase 1 result
  k_i: Option<Scalar>,
  gamma_i: Option<Scalar>,
  dec_Gamma_i: Option<Decommitment>,
  
  // phase 2 result
  delta_i: Option<Scalar>,
  sigma_i: Option<Scalar>,

  // phase 3 result
  delta: Option<Scalar>,
 
  // phase 4 result
  r: Option<Scalar>,

  // phase 5 result
  s: Option<Scalar>,
}

const UNICAST_TO_SIGNER_A: UnicastId = UnicastId(1);
const UNICAST_TO_SIGNER_B: UnicastId = UnicastId(2);

const COM_GAMMA_I_BCAST: BroadcastId = BroadcastId(11);
const DEC_GAMMA_I_BCAST: BroadcastId = BroadcastId(12);
const DELTA_I_BCAST: BroadcastId = BroadcastId(13);
const COM_S_I_BCAST: BroadcastId = BroadcastId(14);
const DEC_S_I_BCAST: BroadcastId = BroadcastId(15);

const TEST1_BCAST: BroadcastId = BroadcastId(100);
const TEST2_BCAST: BroadcastId = BroadcastId(101);

const C_A: ValueId = ValueId(1);
const PK: ValueId = ValueId(2);
const RP_A_LT_Q3: ValueId = ValueId(3);
const C_B: ValueId = ValueId(4);
const BETA: ValueId = ValueId(5);
const RP_B_LT_Q3: ValueId = ValueId(6);
const RP_B_LT_Q3_BP_LE_Q7: ValueId = ValueId(7);

impl Signer {
  pub fn new(
    signer_id: SignerId,
    network: Arc<Network>,
    pedersen: PedersenCommitment,
    M: &Scalar,
    hasher: Box<dyn Fn(&Scalar) -> Scalar + Send + Sync>,
    omega_i: &Scalar,
  ) -> Self {
    Self {
      signer_id,
      network,
      ss_group_order: secp256k1_group_order(),
      pedersen,
      M: M.clone(),
      hasher,
      omega_i: omega_i.clone(),
      //
      k_i: None,
      dec_Gamma_i: None,
      delta_i: None,
      sigma_i: None,
      gamma_i: None,
      delta: None,
      r: None,
      s: None,
    }
  }

  pub async fn perfrom_mta_as_alice(
    &mut self,
    alice_id: &SignerId,
    secret: &Scalar,
  ) -> Scalar {
    let alice = Alice::new(&secret.into());
 
    let bob_id = &alice_id.the_other();

    // Send C_A, E_A(pk), and range proof to Bob
    let to_bob = |value_id| UnicastDest::new(
      UNICAST_TO_SIGNER_B,
      alice_id.into(),
      bob_id.into(),
      value_id,
    );
    self.network.unicast(
      &to_bob(C_A),
      &alice.c_a,
    ).await;

    self.network.unicast(
      &to_bob(PK),
      &alice.pk,
    ).await;

    self.network.unicast( 
      &to_bob(RP_A_LT_Q3), &alice.rp_a_lt_q3
    ).await;

    // Receive C_b, beta, and range proofs from Bob
    let to_alice = |value_id| UnicastDest::new(
      UNICAST_TO_SIGNER_A,
      bob_id.into(),
      alice_id.into(),
      value_id,
    );
    let c_b: Integer = 
      self.network.receive_unicast( &to_alice(C_B)).await;

    let beta: Integer = 
      self.network.receive_unicast( &to_alice(BETA)).await;

    let rp_b_lt_q3: Integer = self.network.receive_unicast(
      &to_alice(RP_B_LT_Q3),
    ).await;

    let rp_b_lt_q3_bp_le_q7: Integer = self.network.receive_unicast(
      &to_alice(RP_B_LT_Q3_BP_LE_Q7),
    ).await;
  
    // Calculate Alpha
    let alpha = alice.calc_alpha(
      &c_b,
      &rp_b_lt_q3,
      &rp_b_lt_q3_bp_le_q7,
    ).unwrap();

    // Calculate multiplicative share
    ((alpha + beta) % &self.ss_group_order).into()
  }

  pub async fn perfrom_MtA_as_Bob(
    &mut self,
    bob_id: &SignerId,
    secret: &Scalar,
  ) {
    let alice_id = &bob_id.the_other();

    // Receive c_a, pk, and range proof from Alice
    let to_bob = |value_id| UnicastDest::new(
      UNICAST_TO_SIGNER_B,
      alice_id.into(),
      bob_id.into(),
      value_id,
    );
    let c_a: Integer = self.network.receive_unicast(
      &to_bob(C_A),
    ).await;

    let pk: PublicKey = self.network.receive_unicast(
      &to_bob(PK),
    ).await;

    let rp_a_lt_q3: Integer = self.network.receive_unicast(
      &to_bob(RP_A_LT_Q3),
    ).await;

    // Calculate C_B, beta, and range proofs
    let bob = Bob::new(
      &secp256k1_group_order(),
      &c_a,
      &pk,
      &rp_a_lt_q3,
      &secret.into(),
    );

    // Send C_b, beta, and range proofs to Alice
    let to_alice = |value_id| UnicastDest::new(
      UNICAST_TO_SIGNER_A,
      bob_id.into(),
      alice_id.into(),
      value_id,
    );
    self.network.unicast( 
      &to_alice(C_B), 
      &bob.c_b,
    ).await;

    self.network.unicast( 
      &to_alice(BETA),
      &bob.beta,
    ).await;

    self.network.unicast(
      &to_alice(RP_B_LT_Q3),
      &bob.rp_b_lt_q3,
    ).await;

    self.network.unicast(
      &to_alice(RP_B_LT_Q3_BP_LE_Q7),
      &bob.rp_b_lt_q3_bp_le_q7,
    ).await;
  }

  pub async fn run_phase_1(&mut self) {
    // select k_i and gamma_i in Z_q and broadcasts C_i
    let k_i = Scalar::rand();
    let gamma_i = Scalar::rand();
    self.k_i = Some(k_i);
    self.gamma_i = Some(gamma_i);

    // calculate Com(Gamma_i = gamma_i * G)
    let comm_pair = self.pedersen.commit(&gamma_i);
    self.dec_Gamma_i = Some(comm_pair.decomm);

    // broadcast Com(Gamma_i)
    self.network.broadcast_with_index(
      &COM_GAMMA_I_BCAST,
      &self.signer_id,
      &comm_pair.comm,
    ).await;
  }

  pub async fn run_phase_2_Player_A(
    &mut self,
  ) {
    // MtA 1: k_A * gamma B
    let k_A = &self.k_i.unwrap().clone();
    let k_A_gamma_B: Scalar = self.perfrom_mta_as_alice(
      &SignerId::A,
      k_A
    ).await.into(); 

    // MtA 2: k_B * gamma A
    let gamma_A = &self.gamma_i.unwrap().clone();
    self.perfrom_MtA_as_Bob(
      &SignerId::A,
      gamma_A,
    ).await;

    // MtA 3: k_A * omega B
    let k_A_omega_B: Scalar = self.perfrom_mta_as_alice(
      &SignerId::A,
      k_A,
    ).await.into(); 

    let omega_A = &self.omega_i.clone();

    // MtA 4: k_B * omega A
    self.perfrom_MtA_as_Bob(
      &SignerId::A,
      omega_A,
    ).await;

    let delta_A = k_A * gamma_A + &k_A_gamma_B;
    let sigma_A = k_A * omega_A + &k_A_omega_B;

    self.delta_i = Some(delta_A);
    self.sigma_i = Some(sigma_A);
  }

  pub async fn run_phase_2_Player_B(
    &mut self,
  ) {
    // MtA 1: k_A * gamma B
    let gamma_B = &self.gamma_i.unwrap().clone();
    self.perfrom_MtA_as_Bob(
      &SignerId::B,
      gamma_B,
    ).await;

    // MtA 2: k_B * gamma A
    let k_B = &self.k_i.unwrap().clone();
    let k_B_gamma_A = self.perfrom_mta_as_alice(
      &SignerId::B,
      k_B,
    ).await; 

    let omega_B = &self.omega_i.clone();

    // MtA 3: k_A * omega B
    self.perfrom_MtA_as_Bob(
      &SignerId::B,
      omega_B,
    ).await;

    // MtA 4: k_B * omega A
    let k_B_omega_A = self.perfrom_mta_as_alice(
      &SignerId::B,
      k_B,
    ).await; 

    let delta_B = k_B * gamma_B + &k_B_gamma_A;
    let sigma_B = k_B * omega_B + &k_B_omega_A;

    self.delta_i = Some(delta_B);
    self.sigma_i = Some(sigma_B);
  }

  pub async fn run_phase_3(&mut self) {
    let delta_i = self.delta_i.unwrap().clone();

    // broadcast delta_i
    self.network.broadcast( &DELTA_I_BCAST, &delta_i).await;

    // retrieve delta_is to construct delta
    let delta_is: Vec<Scalar> = 
      self.network.receive_broadcasts(&DELTA_I_BCAST).await;

    let delta = delta_is.iter().fold(Scalar::zero(), |acc, x| acc + x);
    self.delta = Some(delta);
  }

  pub async fn run_phase_4(&mut self) -> Result<(), String> {
    // retrieve Com(Gamma_i) from broadcast
    let com_Gamma_is: Vec<JacobianPoint> =
      self.network.receive_idx_broadcasts(&COM_GAMMA_I_BCAST).await;

    // broadcasst Decommitment of Com(Gamma_i)
    self.network.broadcast_with_index(
      &DEC_GAMMA_I_BCAST,
      &self.signer_id,
      &self.dec_Gamma_i.unwrap(),
    ).await;
    
    // retrieve decommitment of Com(Gamma_i)s
    let dec_Gamma_is: Vec<Decommitment> = 
      self.network.receive_idx_broadcasts(&DEC_GAMMA_I_BCAST).await;

    // verify decommitment of Com(Gamma_i)
    if !self.pedersen.verify_vec(&com_Gamma_is, &dec_Gamma_is) {
      return Err("Gamma decommitment failed".to_string());
    }

    // TODO prove that the party know gamma_i using zk proof

    // compute Gamma
    let Gamma: JacobianPoint = dec_Gamma_is.iter().fold(
      JacobianPoint::point_at_infinity(),
      |acc, decomm| acc + self.pedersen.g * decomm.secret
    );

    let delta_inv = self.delta.unwrap().inv();
    let R = Gamma * &delta_inv;
    let r: Scalar = R.to_affine().x().into();

    // if r is 0, start over
    if r.is_zero() {
      return Err("r is zero".to_string());
    }
    self.r = Some(r);

    Ok(())
  }

  pub async fn run_phase_5(&mut self) -> Result<(),String> {
    let k_i = self.k_i.as_ref().unwrap();
    let sigma_i = self.sigma_i.as_ref().unwrap();
    let r = self.r.as_ref().unwrap();
    let m = (self.hasher)(&self.M);

    let s_i = m * k_i + r * sigma_i;

    // broadcast Com(S_i)
    let s_i_comm_pair = self.pedersen.commit(&s_i);
    self.network.broadcast_with_index(
      &COM_S_I_BCAST,
      &self.signer_id,
      &s_i_comm_pair.comm,
    ).await;

    // retrieve Com(S_i)s
    let com_S_is: Vec<JacobianPoint> =
      self.network.receive_idx_broadcasts(&COM_S_I_BCAST).await;

    // broadcast Decommitment of Com(S_i) w/ index
    self.network.broadcast_with_index(
      &DEC_S_I_BCAST,
      &self.signer_id,
      &s_i_comm_pair.decomm,
    ).await;

    // retrieve decommitment of Com(S_i)s
    let dec_S_is: Vec<Decommitment> = 
      self.network.receive_idx_broadcasts(&DEC_S_I_BCAST).await;

    // verify decommitment of Com(S_i)
    if !self.pedersen.verify_vec(&com_S_is, &dec_S_is) {
      return Err("S_is decommitment failed".to_string());
    }

    let s = PedersenCommitment::aggr_secrets(&dec_S_is);
    self.s = Some(s);

    Ok(()) 
  }

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
    Scalar::from(x as usize).neg()
  }

  pub async fn create_signature(
    &mut self,
  ) -> Result<Signature, String> {
    // Phase 1
    self.run_phase_1().await;

    // Phase 2
    if self.signer_id == SignerId::A {
      self.run_phase_2_Player_A().await
    } else {
      self.run_phase_2_Player_B().await
    }

    // Phase 3
    self.run_phase_3().await;

    // Phase 4
    self.run_phase_4().await?;

    // Phase 5
    self.run_phase_5().await?;

    let sig = Signature::new(
      &self.r.as_ref().unwrap(),
      &self.s.as_ref().unwrap(),
    );
    Ok(sig)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::{
    task::JoinHandle,
    spawn,
  };
  use std::sync::Arc;
  use crate::{
    building_block::util::bitcoin_hasher,
    protocols::gg18::{
      key_generator::KeyGenerator,
      paillier::Paillier,
   },
  };

  async fn generate_keys(
    n: &Integer,
    num_generators: usize,
  ) -> Result<Vec<KeyGenerator>, String> {
    let network = Arc::new(Network::new(num_generators));
    let pedersen = Arc::new(PedersenCommitment::new());

    let mut handles = vec![];

    for generator_id in 0..num_generators as u32 {
      // Create the generator.
      let generator = KeyGenerator::new(
        n,
        num_generators,
        generator_id,
        Arc::clone(&network),
        Arc::clone(&pedersen),
      );

      let handle: JoinHandle<Result<KeyGenerator, String>> = tokio::spawn(async move {
        let mut gen = generator;
        gen.generate_key().await?;
        Ok(gen)
      });
      handles.push(handle);
    }

    // Await all tasks and collect the generators.
    let mut generators = vec![];
    for handle in handles {
      generators.push(handle.await.map_err(|e| e.to_string())??);
    }
    
    Ok(generators)
  }

  #[tokio::test]
  async fn test_signing() {
    let num_generators = 3;

    // group/field order for the secrets 
    let ss_order = secp256k1_group_order();

    // requirement: n > {ss_order}^8
    let n = &ss_order.clone().pow(8u32);

    // sign with 2 key shard sets from generator 1 and 2
    let num_signers = 2;
    let network = Arc::new(Network::new(num_signers));
    let pedersen = PedersenCommitment::new();

    // message M to sign in Z_n 
    let M = Scalar::rand();

    let _ = Paillier::gen_p_q(&ss_order);

    // calculate pk and omegas with lagrange interpolation
    let lambda_1_2 = Signer::calc_lambda_i_j(1, 2);
    let lambda_2_1 = Signer::calc_lambda_j_i(1, 2);
    assert_eq!(lambda_1_2, Scalar::from(2u8));
    assert_eq!(lambda_2_1, Scalar::from(1u8).neg());

    // generate key shard sets 
    let generators = generate_keys(n, num_generators).await.unwrap();

    let omega_1 = lambda_1_2 * generators[0].x_i.unwrap();
    let omega_2 = lambda_2_1 * generators[1].x_i.unwrap();

    let pk = 
      generators[0].X_i.unwrap() * lambda_1_2 +
      generators[1].X_i.unwrap() * lambda_2_1;

    // confirm that pk and omegas are consistent
    assert!(pk == JacobianPoint::get_base_point() * (omega_1 + omega_2));

    let mut signer_a = Signer::new(
      SignerId::A,
      Arc::clone(&network),
      pedersen.clone(),
      &M,
      Box::new(bitcoin_hasher),
      &omega_1,
    );
    let mut signer_b = Signer::new(
      SignerId::B,
      Arc::clone(&network),
      pedersen,
      &M,
      Box::new(bitcoin_hasher),
      &omega_2,
    );
    
    let handles = vec![
      spawn(async move {
        signer_a.create_signature().await.unwrap()
      }),
      spawn(async move {
        signer_b.create_signature().await.unwrap()
      }),
    ];

    let sigs: Vec<_> = futures::future::join_all(handles).await
      .into_iter()
      .map(|res| res.unwrap())
      .collect();

    let is_sig_valid = sigs[0].verify(
      &pk,
      &M,
      bitcoin_hasher,
    );
    assert!(is_sig_valid);
  }
}
