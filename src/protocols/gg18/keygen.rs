#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::{
  paillier::{
    GCalcMethod,
    Paillier,
  },
  pedersen_secp256k1::{
    // CommitmentPair,
    // Decommitment,
    PedersenCommitment,
  },
  secp256k1::{
    point::Point,
    scalar::Scalar,
  },
};
// use rug::Integer;
use crate::protocols::gg18::network::{
  BroadcastId,
  Network,
};
use std::sync::Arc;
use serde::{Serialize, Deserialize};

pub struct Party {
  num_parties: usize,
  party_id: usize,
  network: Arc<Network>,
}

const KGC_BROADCAST: BroadcastId = BroadcastId(1);

impl Party {
  pub fn new(
    num_parties: usize,
    party_id: usize,
    network: Arc<Network>,
  ) -> Self {
    Self {
      num_parties,
      party_id,
      network,
    }
  }

  pub async fn generate_key(&mut self) {
    let _paillier = Paillier::new(
      32, // TODO change to 256
      GCalcMethod::Random,
    );

    //// Phase 1  
    let u_i = Scalar::rand();

    let pedersen = PedersenCommitment::new();
    let comm_pair = {
      let blinding_factor = &Scalar::rand();
      pedersen.commit(&u_i, blinding_factor)
    };

    // broadcast KGC_i (comm)
    self.network.broadcast(
      &KGC_BROADCAST,
      comm_pair.comm.serialize(),
    ).await;

    let KGC_is: Vec<Point> = {
      let xs = self.network.receive_broadcasts(KGC_BROADCAST).await;
      xs.iter().map(|x| Point::deserialize(&x)).collect()
    };
    for KGC_i in KGC_is {
      println!("Party {} received: {:?}", self.party_id, KGC_i);
    }

    // let KGC_is: Vec<Point> = 
    //   self.network.receive_broadcasts().iter().map(|x| x.deserialize()).collect();

    // broadcast E_i
    // self.network.broadcast(paillier.pk);

    //// Phase 2
    // broadcast KGD_i -> obtains U_i
    // send p_i(other_parties) to other_parties
  }

  // // call this after phase 1
  // pub fn all_pubkeys_distinct(points: &Vec<PublicKey>) -> bool {
  //   for i in 0..points.len() {
  //     for j in i+1..points.len() {
  //       if points[i].n == points[j].n {
  //         return false;
  //       }
  //     }
  //   }
  //   true
  // }
  // 
  // // Each player P_i broadcasts KGD_i
  // pub fn phase_2_1(&self) -> Decommitment {
  //   self.comm_pair.unwrap().decomm.clone()
  // }
  // 
  // // Decommit KGC_i/KGD_i to obtain U_i (=u_i*G)
  // // Then: 
  // // - calculate PK = sum(U_i)
  // // - return validated commitments
  // pub fn phase_2_2(
  //   &mut self,
  //   comm_decomms: &Vec<(&Point,&Decommitment)>,
  // ) -> Result<Vec<Point>, &'static str> {
  //   // aggregate commitments to construct the public key
  //   // making sure each commitment is valid
  //   let g = Point::get_base_point();
  //   let mut pk = Point::point_at_infinity();
  // 
  //   let mut U_is = vec![];
  //   for comm_decomm in comm_decomms {
  //     let (comm, decomm) = comm_decomm;
  //     let comm_rec = decomm.m + g * decomm.r;
  //     if &comm_rec != *comm {
  //       return Err("Phase 2-2: Invalid commitment");
  //     }
  //     pk = pk + *comm;
  //     U_is.push(*comm.clone());
  //   }
  //   self.pk = Some(pk);
  //   Ok(U_is)
  // }
  // 
  // // each player constructs a polynomial of degree 1:
  // // p_i(x) = u_i + a_i*x (a_i->$Z_p)
  // pub fn phase_2_3(&mut self) -> Point {
  //   let a_i = Scalar::rand();
  //   let u_i = self.u_i.unwrap();
  //   let G = Point::get_base_point();
  //   self.p_i = Some(Box::new(move |x: usize| { u_i + a_i * Scalar::from(x) }));
  //   self.A_i = Some(G * a_i);
  // 
  //   self.A_i.unwrap().clone()
  // }
  // 
  // fn key_gen_phase_2_4_eval_p(&self, i: usize) -> Scalar {
  //   self.p_i.as_ref().unwrap()(i)
  // }
  // 
  // // using Feldman VSS, verify that the same polynomial is used
  // // to generate all shares
  // pub fn phase_2_4(
  //   &self,
  //   p_is: &Vec<Scalar>,
  //   U_is: &Vec<Point>,
  //   A_is: &Vec<Point>,
  // ) -> Result<(), &'static str> {
  //   let g = Point::get_base_point();
  //   for x in p_is.iter().zip(U_is.iter()).zip(A_is.iter()) {
  //     let ((p_i, U_i), A_i) = x;
  //     let lhs = g * p_i;
  //     let rhs = U_i + A_i;
  //     if lhs != rhs {
  //       return Err("Phase 2-4: Malformed polynomial");
  //     }
  //   }
  //   Ok(())
  // }
  // 
  // // calculate:
  // // - shard private key: sum(u_i) + sum(a_i)
  // // - shared public key: PK + sum(A_i)
  // pub fn phase_2_5(
  //   &mut self,
  //   player_id: usize,
  //   p_is: &Vec<Scalar>,
  //   A_is: &Vec<Point>,
  // ) {
  //   let sum_p_is = p_is.iter().fold(Scalar::zero(), |acc, p| acc + *p);
  //   self.x_i = Some(sum_p_is);
  // 
  //   let sum_A_i = A_is.iter().fold(self.pk.unwrap(), |acc, A| acc + *A);
  //   let pk = &self.pk.unwrap();
  //   let X_i = pk + sum_A_i;
  // 
  //   // fill this player's PK shard only
  //   self.X_is.as_mut().unwrap()[player_id - 1] = X_i;
  // }
  // 
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokio::spawn;
  use std::sync::Arc;

  #[tokio::test]
  async fn test_key_gen() {
    let network = Arc::new(Network::new(3));
    let num_parties = 3;

    let mut parties = vec![];
    for party_id in 0..3 {
      let party = Party::new(num_parties, party_id, Arc::clone(&network));
      parties.push(party);
    }

    let mut handles = vec![];
    for mut party in parties {
      handles.push(spawn(async move {
        party.generate_key().await;
      }));
    }

    for handle in handles {
      handle.await.unwrap();
    }
  }
}
