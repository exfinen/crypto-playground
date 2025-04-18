#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::secp256k1::jacobian_point::JacobianPoint;
use crate::building_block::secp256k1::{
  jacobian_point::JacobianPoint as Point,
  scalar::Scalar,
};
// use rug::Integer;
use crate::protocols::gg18::{
  network::{
    BroadcastId,
    Network,
    UnicastId,
    UnicastDest,
    ValueId,
  },
  paillier::{
    GCalcMethod,
    Paillier,
    PublicKey,
  },
  pedersen_secp256k1::{
    // CommitmentPair,
    Decommitment,
    PedersenCommitment,
  },
};
use std::sync::Arc;

pub struct KeyGenerator {
  generator_id: u32,
  num_generators: usize,
  network: Arc<Network>,
  pedersen: Arc<PedersenCommitment>,
  num_n_bits: u32,
  // phase 1 result
  u_i: Option<Scalar>,
  dec_U_i: Option<Decommitment>,
  // phase 2 result
  pub x_i: Option<Scalar>, // shard private key
  pub X_i: Option<Point>, // shard public key
  // phase 3 result
}

const COM_U_I_BCAST: BroadcastId = BroadcastId(1);
const DEC_U_I_BCAST: BroadcastId = BroadcastId(2);
const E_I_BCAST: BroadcastId = BroadcastId(3);
const DECOMM_BCAST: BroadcastId = BroadcastId(4);
const A_I_BCAST: BroadcastId = BroadcastId(5);

const P_I_UNICAST: UnicastId = UnicastId(1);
const P_I: ValueId = ValueId(1);

impl KeyGenerator {
  pub fn new(
    num_generators: usize,
    generator_id: u32,
    network: Arc<Network>,
    pedersen: Arc<PedersenCommitment>,
    num_n_bits: u32,
  ) -> Self {
    Self {
      num_generators,
      generator_id,
      network,
      pedersen,
      num_n_bits, 
      //
      u_i: None,
      dec_U_i: None,
      //
      x_i: None,
      X_i: None,
    }
  }

  pub async fn run_phase_1(&mut self) {
    let u_i = Scalar::from(self.generator_id + 1);
    self.u_i = Some(u_i);

    let comm_pair = self.pedersen.commit(&u_i);

    // broadcast Com(U_i)
    self.network.broadcast_with_index(
      &COM_U_I_BCAST,
      self.generator_id,
      &comm_pair.comm,
    ).await;

    self.dec_U_i = Some(comm_pair.decomm);

    // broadcast E_i the public key for Paillier’s cryptosystem
    let (p, q) = Paillier::gen_p_q(self.num_n_bits);
    let paillier = Paillier::new(
      256,
      &p,
      &q,
      GCalcMethod::Random,
    );
    self.network.broadcast_with_index(
      &E_I_BCAST,
      self.generator_id,
      &paillier.pk,
    ).await;
  }

  pub async fn run_phase_2(&mut self) -> Result<(), String> {
    // retrieve decommitment of Com(U_i)s
    // construct a polynomial of degree 1 using u_i as the constant term
    let a_i = Scalar::rand();
    let u_i = self.u_i.unwrap();
    let p_i = Box::new(move |x: u32| { &u_i + a_i * Scalar::from(x) });

    //// make sure all public keys are unique
    //for i in 0..E_is.len() {
    //  for j in i+1..E_is.len() {
    //    if E_is[i].n == E_is[j].n {
    //      panic!("Not all public keys are unique");
    //    }
    //  }
    //}
    let generators: Vec<u32> = (0..self.num_generators as u32).collect();

    // unicast p_i(gen_id) to other generators
    for to in &generators {
      if to == &self.generator_id { // don't seit it to self
        continue;
      }
      let dest = UnicastDest::new(
        P_I_UNICAST,
        self.generator_id,
        *to,
        P_I,
      );
      let p_i_eval = p_i(to + 1);
      self.network.unicast(&dest, &p_i_eval).await;
    }

    let eval_point = self.generator_id + 1;

    // construct p_i(this_gen_id)s from local p_i 
    // and p_is received from other generators
    let eval_p_is = {
      let mut eval_p_is = vec![];
      for from in generators {
        if from == self.generator_id { // if self to self, eval locally
          eval_p_is.push(p_i(eval_point));
        } else { // otherwise, receive from other generators
          let dest = UnicastDest::new(
            P_I_UNICAST,
            from,
            self.generator_id,
            P_I,
          );
          let eval_p_i = self.network.receive_unicast(&dest).await;
          eval_p_is.push(eval_p_i);
        }
      }
      eval_p_is
    };

    // create A_i (hiding of a_i) and broadcast
    let A_i = Point::get_base_point() * a_i;
    self.network.broadcast_with_index(
      &A_I_BCAST,
      self.generator_id,
      &A_i,
    ).await;

    // retrieve broadcast A_is
    let A_is = self.network.receive_idx_broadcasts(&A_I_BCAST).await;
    
    // broadcast Decommitment of Com(U_i)
    self.network.broadcast_with_index(
      &DEC_U_I_BCAST,
      self.generator_id,
      &self.dec_U_i.as_ref().unwrap(),
    ).await;

    // retrieve decommits of Com(U_i)
    let dec_U_is: Vec<Decommitment> =
      self.network.receive_idx_broadcasts(&DEC_U_I_BCAST).await;

    // reconstruct U_is
    let g = JacobianPoint::get_base_point();
    let U_is: Vec<JacobianPoint> = dec_U_is.iter().map(|x| g * x.secret).collect();

    // verify polynomials received from other generators are not compromised
    // i.e. p_i(gen_id) * G ==  U_i + A_i
    for (p_i, (A_i, U_i)) in eval_p_is.iter().zip(A_is.iter().zip(&U_is)) {
      let lhs = g * p_i;
      let rhs = U_i + A_i * Scalar::from(eval_point);
      if lhs != rhs {
        return Err(format!("---> {}: Phase 2: compromised polynomial found", self.generator_id));
      }
    }
 
    // calculate shard private key
    let x_i = eval_p_is.iter().fold(
      Scalar::zero(),
      |acc, x| acc + x, 
    );
    self.x_i = Some(x_i);

    // calculate shard public key
    let PK = U_is.iter().fold(
      JacobianPoint::point_at_infinity(),
      |acc, x| acc + x, 
    );
    let X_i = A_is.iter().fold(
      JacobianPoint::point_at_infinity(),
      |acc, x| acc + x, 
    );
    self.X_i = Some(PK + X_i * Scalar::from(eval_point));

    Ok(())
  }

  pub async fn run_phase_3(&mut self) {
    // retrieve E_is here?
    let _E_is: Vec<PublicKey> =
      self.network.receive_idx_broadcasts(&E_I_BCAST).await;

    // 1. prove that the generator knows the shard private key x_i through zkp

    // 2. prove that the generator knows the priv key for E_i

    // N_i = p_i * q_i is the RSA modulus associated with E_i,
    // i.e. use zkp of knowing the p_i and q_i
  }

  pub async fn generate_key(&mut self) -> Result<(Scalar, JacobianPoint), String> {
    self.run_phase_1().await;
    self.run_phase_2().await?;
    self.run_phase_3().await;

    Ok((self.x_i.unwrap(), self.X_i.unwrap()))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::spawn;
  use std::sync::Arc;

  #[tokio::test]
  async fn test_key_gen() -> Result<(), String> {
    let network = Arc::new(Network::new(3));
    let num_generators = 3;
    let pedersen = Arc::new(PedersenCommitment::new());
    let num_n_bits = 6u32;

    let mut generators = vec![];
    for generator_id in 0..3 {
      let generator = KeyGenerator::new(
        num_generators,
        generator_id,
        Arc::clone(&network),
        Arc::clone(&pedersen),
        num_n_bits,
      );
      generators.push(generator);
    }

    let mut handles = vec![];
    for mut generator in generators {
      handles.push(spawn(async move {
        generator.generate_key().await
      }))
    }

    // TODO don't return shared private key
    let res: Vec<_> = futures::future::join_all(handles).await
      .into_iter()
      .map(|res| res.unwrap().unwrap())
      .collect();

    let x_is = res.iter().map(|(x_i, _)| x_i).collect::<Vec<_>>();
    let X_is = res.iter().map(|(_, X_i)| X_i).collect::<Vec<_>>();

    let G = JacobianPoint::get_base_point();

    // lagrange intepolation with generator 0 and 1 key pairs
    let lambda_1_2 = Scalar::from(2u32);
    let lambda_2_1 = Scalar::from(1u32).neg();

    let sk = lambda_1_2 * x_is[0] + lambda_2_1 * x_is[1];
    let pk = X_is[0] * lambda_1_2 + X_is[1] * lambda_2_1;

    // sign message 
    let m = Scalar::rand();
    let k = Scalar::rand();
    let R = {
      let p = G * k.inv();
      p.to_affine()
    };
    let r: Scalar = R.x().into();
    let s = k * m + k * r * sk;

    // verify signature
    let u1 = &s.inv() * m;
    let u2 = &s.inv() * &r;

    let R_prime = G * u1 + pk * u2;
    let r_prime: Scalar = R_prime.to_affine().x().into();

    assert!(r == r_prime);

    Ok(())
  }
}

