#![allow(non_snake_case)]
#![allow(dead_code)]

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
  pub x_i: Option<Scalar>, // shard private key
  pub X_i: Option<Point>, // shard public key
}

const KGC_BROADCAST: BroadcastId = BroadcastId(1);
const KGD_BROADCAST: BroadcastId = BroadcastId(2);
const PUBKEY_BROADCAST: BroadcastId = BroadcastId(3);
const DECOMM_BROADCAST: BroadcastId = BroadcastId(4);
const A_I_BROADCAST: BroadcastId = BroadcastId(5);

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
      x_i: None,
      X_i: None,
    }
  }

  pub async fn generate_key(&mut self) {
    let pedersen = &self.pedersen;

    //// Phase 1
    let u_i = Scalar::from(self.generator_id + 1);

    let comm_pair = {
      let blinding_factor = &Scalar::rand();
      pedersen.commit(&u_i, blinding_factor)
    };

    // broadcast KGC_i commitment
    let KGC_i = (self.generator_id, comm_pair.comm);
    self.network.broadcast(
      &KGC_BROADCAST,
      &bincode::serialize(&KGC_i).unwrap(),
    ).await;

    let mut KGC_is: Vec<(u32, Point)> = {
      let xs = self.network.receive_broadcasts(KGC_BROADCAST).await;
      xs.iter().map(|x| {
        bincode::deserialize(&x).expect("Failed to deserialize KGC_i")
      }).collect()
    };

    // broadcast paillier pk: E_i
    let (p, q) = Paillier::gen_p_q(self.num_n_bits);
    let paillier = Paillier::new(
      256,
      &p,
      &q,
      GCalcMethod::Random,
    );
    self.network.broadcast(
      &PUBKEY_BROADCAST,
      &bincode::serialize(&paillier.pk).unwrap(),
    ).await;

    // get all broadcast E_is
    let E_is: Vec<PublicKey> = {
      let xs = self.network.receive_broadcasts(PUBKEY_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    // make sure all public keys are unique
    for i in 0..E_is.len() {
      for j in i+1..E_is.len() {
        if E_is[i].n == E_is[j].n {
          panic!("Not all public keys are unique");
        }
      }
    }

    //// Phase 2

    // broadcast KGD_i -> obtains U_i
    let KGD_i = (self.generator_id, comm_pair.decomm);

    self.network.broadcast(
      &DECOMM_BROADCAST,
      &bincode::serialize(&KGD_i).unwrap(),
    ).await;

    // receive KGD_i from other parties
    let mut KGD_is: Vec<(u32, Decommitment)> = {
      let xs = self.network.receive_broadcasts(DECOMM_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    // Decommit KGC_i/KGD_i to obtain U_i. then
    // aggregate U_is to construct the public key
    // also return a vector of U_is
    let (pk, U_is) = {
      let g = &pedersen.g;
      let h = &pedersen.h;

      // sort KCG_is and KGD_is by id
      KGC_is.sort_by_key(|(id, _)| *id);
      KGD_is.sort_by_key(|(id, _)| *id);
      if KGC_is.len() != KGD_is.len() {
        panic!("Phase 2: number of commitments and decommitments don't match");
      }

      let mut pk = Point::point_at_infinity();
      let mut U_is = vec![];

      for x in KGC_is.iter().zip(KGD_is.iter())  {
        let ((comm_id, comm),(decomm_id, decomm)) = x;
        if comm_id != decomm_id {
          panic!("Phase 2: IDs of commitment and decommitment don't match");
        }
        let comm_rec = g * decomm.secret + h * decomm.blinding_factor;
        if &comm_rec != comm {
          panic!("Phase 2: Invalid commitment");
        }
        let U_i = g * decomm.secret;
        pk = pk + U_i;
        U_is.push(U_i.clone());
      }
      (pk, U_is)
    };

    // construct a random polynomial of degree 1
    // with the constant term u_i
    let a_i = Scalar::rand();
    let p_i = Box::new(move |x: u32| { u_i + a_i * Scalar::from(x) });

    // create a hiding of the coefficient of the degree 1 term and
    // broadcast
    let A_i = {
      let g = Point::get_base_point();
      let A_i = g * a_i;
      (self.generator_id, A_i)
    };

    self.network.broadcast(
      &A_I_BROADCAST,
      &bincode::serialize(&A_i).unwrap(),
    ).await;

    // receive A_is of all parties including this party
    let A_is: Vec<(u32, Point)> = {
      let xs = self.network.receive_broadcasts(A_I_BROADCAST).await;
      let mut xs: Vec<(u32, Point)> = 
        xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect();
      xs.sort_by_key(|(id, _)| *id);
      xs
    };

    // evaluate the polynomial at the points for other parties
    // and send the results to them
    for id in 0..self.num_generators as u32 {
      if id == self.generator_id {
        continue;
      }
      let pt = id + 1;
      let res = p_i(pt);
      let dest = UnicastDest::new(
        P_I_UNICAST,
        self.generator_id,
        id,
        P_I,
      );
      let ser_res = bincode::serialize(&res).unwrap(); 
      self.network.unicast(&dest, &ser_res).await;
    }

    // construct p_is receiving missing p_is from other parties
    let p_is = {
      let mut p_is = vec![];
      for id in 0..self.num_generators as u32 {
        if id == self.generator_id {
          let pt = id + 1;
          let p_i = p_i(pt);
          p_is.push(p_i);
        } else {
          let dest = UnicastDest::new(
            P_I_UNICAST,
            id,
            self.generator_id,
            P_I,
          );
          let ser_p_i: Vec<u8> = self.network.receive_unicast(&dest).await;
          let p_i = bincode::deserialize(&ser_p_i).unwrap();
          p_is.push(p_i);
        }
      }
      p_is
    };

    // using Feldman VSS, verify that a compromiseed polynomial is not used
    // to generate any of the shares
    let g = Point::get_base_point();
    for x in p_is.iter().zip(U_is.iter()).zip(A_is.iter()) {
      let ((p_i, U_i), (_, A_i)) = x;
      let lhs = g * p_i;
      let pt = Scalar::from(self.generator_id + 1);
      let rhs = U_i + A_i * pt;
      if lhs != rhs {
        panic!("Phase 2: Malformed polynomial found");
      }
    }

    // calculate shard private key + sum(a_i)
    self.x_i = Some(
      p_is.iter().fold(Scalar::zero(), |acc, p_i| acc + p_i)
    );

    // calculate shard public key
    self.X_i = Some(
      pk + A_is.iter().fold(Point::point_at_infinity(), |acc, (_, A_i)| acc + A_i)
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::spawn;
  use std::sync::Arc;

  #[tokio::test]
  async fn test_key_gen() {
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
        generator.generate_key().await;
      }));
    }

    for handle in handles {
      handle.await.unwrap();
    }
  }
}

