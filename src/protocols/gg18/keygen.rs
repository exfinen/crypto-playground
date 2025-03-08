#![allow(non_snake_case)]
#![allow(dead_code)]

use serde::Deserialize;

use crate::building_block::{
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
  secp256k1::{
    point::Point,
    scalar::Scalar,
  },
};
// use rug::Integer;
use crate::protocols::gg18::network::{
  BroadcastId,
  Network,
  UnicastId,
  UnicastDest
};
use std::sync::Arc;

pub struct Party {
  num_parties: usize,
  party_id: usize,
  network: Arc<Network>,
  x_i: Option<Scalar>, // shard private key
  X_i: Option<Point>, // shard public key
}

const KGC_BROADCAST: BroadcastId = BroadcastId(1);
const KGD_BROADCAST: BroadcastId = BroadcastId(2);
const PUBKEY_BROADCAST: BroadcastId = BroadcastId(3);
const DECOMM_BROADCAST: BroadcastId = BroadcastId(4);
const A_I_BROADCAST: BroadcastId = BroadcastId(5);

const P_I_UNICAST: UnicastId = UnicastId(1);

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
      x_i: None,
      X_i: None,
    }
  }

  pub async fn generate_key(&mut self) {
    //// Phase 1
    let u_i = Scalar::rand();

    let pedersen = PedersenCommitment::new();
    let comm_pair = {
      let blinding_factor = &Scalar::rand();
      pedersen.commit(&u_i, blinding_factor)
    };

    // broadcast KGC_i commitment
    self.network.broadcast(
      &KGC_BROADCAST,
      &comm_pair.comm.serialize(),
    ).await;

    let KGC_is: Vec<Point> = {
      let xs = self.network.receive_broadcasts(KGC_BROADCAST).await;
      xs.iter().map(|x| Point::deserialize(&x)).collect()
    };

    // broadcast paillier pk: E_i
    let paillier = Paillier::new(
      32, // TODO change to 256
      GCalcMethod::Random,
    );
    self.network.broadcast(
      &PUBKEY_BROADCAST,
      &bincode::serialize(&paillier.pk).unwrap(),
    ).await;

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
    self.network.broadcast(
      &DECOMM_BROADCAST,
      &comm_pair.decomm.serialize(),
    ).await;

    // receive KGD_i from other parties
    let KGD_is: Vec<Decommitment> = {
      let xs = self.network.receive_broadcasts(DECOMM_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    // Decommit KGC_i/KGD_i to obtain U_i. then
    // aggregate U_is to construct the public key
    // also return a vector of U_is
    let (pk, U_is) = {
      let g = Point::get_base_point();
      let mut pk = Point::point_at_infinity();

      let mut U_is = vec![];
      for comm_decomm in KGC_is.iter().zip(KGD_is.iter())  {
        let (comm, decomm) = comm_decomm;
        let comm_rec = decomm.m + g * decomm.r;
        if &comm_rec != comm {
          panic!("Phase 2: Invalid commitment");
        }
        pk = pk + *comm;
        U_is.push(comm.clone());
      }
      (pk, U_is)
    };

    // construct a random polynomial of degree 1
    // with the constant term u_i
    let a_i = Scalar::rand();
    let p_i = Box::new(move |x: usize| { u_i + a_i * Scalar::from(x) });

    // create a hiding of the coefficient of the degree 1 term and
    // broadcast
    let A_i = {
      let g = Point::get_base_point();
      g * a_i
    };
    self.network.broadcast(
      &A_I_BROADCAST,
      &A_i.serialize(),
    ).await;

    // receive A_is of all parties including this party
    let A_is: Vec<Point> = {
      let xs = self.network.receive_broadcasts(A_I_BROADCAST).await;
      xs.iter().map(|x| bincode::deserialize(&x).unwrap()).collect()
    };

    // evaluate the polynomial at the points for other parties
    // and send the results to them
    for i in 0..self.num_parties {
      if i == self.party_id {
        continue;
      }
      let result: Scalar = p_i(i + 1);
      let dest = UnicastDest::new(
        P_I_UNICAST,
        self.party_id,
        i,
      );
      self.network.unicast(&dest, &result.serialize()).await;
    }

    // construct p_is receiving missing p_is from other parties
    let p_is = {
      let mut p_is = vec![];
      for i in 0..self.num_parties {
        if i == self.party_id {
          let p_i = p_i(i + 1);
          p_is.push(p_i);
        } else {
          let dest = UnicastDest::new(
            P_I_UNICAST,
            i,
            self.party_id,
          );
          let ser_p_i: Vec<u8> = self.network.receive_unicast(&dest).await;
          let p_i = Scalar::deserialize(&ser_p_i).unwrap();
          p_is.push(p_i);
        }
      }
      p_is
    };

    // using Feldman VSS, verify that a compromiseed polynomial is not used
    // to generate any of the shares
    let g = Point::get_base_point();
    for x in p_is.iter().zip(U_is.iter()).zip(A_is.iter()) {
      let ((p_i, U_i), A_i) = x;
      let lhs = g * p_i;
      let rhs = U_i + A_i;
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
      pk + A_is.iter().fold(Point::point_at_infinity(), |acc, A_i| acc + A_i)
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
