#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use rug::ops::Pow;
use rug::Complete;
use rug::{
  Integer,
  rand::MutRandState,
};
use crate::building_block::paillier::{
  GCalcMethod,
  Paillier,
  PublicKey,
  SecretKey,
};
use crate::building_block::util::gen_random_number;

pub struct Alice {
  a: Integer, // additive share
  alpha: Option<Integer>, // multiplicative share
}

pub struct Bob {
  b: Integer, // additive share
  beta: Option<Integer>, // multiplicative share
}

pub struct C_a_RangeProof {
  value: Integer,
  range_proof_a: Integer,
}

pub struct C_b_RangeProofs {
  value: Integer,
  range_proof_b: Integer,
  range_proof_beta_prime: Integer,
}

impl Alice {
  pub fn new(a: &Integer) -> Alice {
    Alice {
      a: a.clone(),
      alpha: None,
    }
  }

  pub fn calc_alpha(
    &mut self,
    c_b: &C_b_RangeProofs,
    mta: &MtA,
  ) -> () {
    // TODO check if c_b's range proofs are valid here
 
    // alice decrypts c_b to get alpha = ab + beta'
    let alpha = Paillier::decrypt(&c_b.value, &mta.sk, &mta.pk);
    self.alpha = Some(alpha);
  }

  pub fn calc_c_a(
    &mut self,
    num_rand_bits: u32,
    mta: &MtA,
    rng: &mut dyn MutRandState,
  ) -> C_a_RangeProof {
    let c_a = Paillier::encrypt(
      num_rand_bits, &mut *rng, &self.a, &mta.pk
    );

    // range proof of a < q^3
    let range_proof_a = Integer::ZERO; // TODO implement this

    C_a_RangeProof {
      value: c_a,
      range_proof_a,
    }
  }
}

impl Bob {
  pub fn new(b: &Integer) -> Bob {
    Bob {
      b: b.clone(),
      beta: None,
    }
  }

  pub fn calc_c_b_and_beta(
    &mut self,
    c_a: &C_a_RangeProof,
    mta: &MtA,
    rng: &mut dyn MutRandState,
  ) -> C_b_RangeProofs {
    // TODO check if range proof of c_a is valid here
  
    let beta_prime = gen_random_number(
      mta.q5.significant_bits(),
      &mut *rng,
    );
    let c_beta_prime = Paillier::encrypt(
      mta.pk.n.significant_bits(),
      &mut *rng,
      &beta_prime,
      &mta.pk,
    );

    // c_b = ENC(ab) + c_beta'
    let c_b = {
      let c_a_times_b = Paillier::scalar_mul(
        &c_a.value,
        &self.b,
        &mta.pk,
      );
      Paillier::add(&c_a_times_b, &c_beta_prime, &mta.pk)
    };

    // beta in Z_q
    self.beta = Some({
      let neg_beta_prime = (&beta_prime * -1i8).complete() % &mta.q;
      &mta.q + neg_beta_prime
    });

    // beta' is in Z_q^5
    // b < q^3 and beta' < q^7
    // TODO implement this
    let range_proof_b = Integer::ZERO; // TODO implement this
    let range_proof_beta_prime = Integer::ZERO; // TODO implement this

    C_b_RangeProofs {
      value: c_b,
      range_proof_b,
      range_proof_beta_prime,
    }
  }
}

pub struct MtA {
  pub q: Integer,
  pub q3: Integer, // q^3
  pub q5: Integer, // q^5
  pub pk: PublicKey,
  pub sk: SecretKey,
}

impl MtA {
  // calculate q s.t. q^8 is less than n and very close to n
  fn calc_q(n: &Integer) -> Integer {
    let mut q = n.clone().root(8);
    if n.pow(8).complete() == q {
      q -= 1;
    }
    q
  }

  pub fn new(num_bits: u32) -> MtA {
    let (pk, sk) = Paillier::new(num_bits, GCalcMethod::Random);
    let q = Self::calc_q(&pk.n);
    let q3 = &q.clone().pow(3);
    let q5 = &q.clone().pow(5);
    MtA {
      q,
      q3: q3.clone(),
      q5: q5.clone(),
      pk,
      sk,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::building_block::util::get_32_byte_rng;

  #[test]
  fn test_mta() {
    let num_bits = 64;
    let mta = MtA::new(num_bits);
    let mut rng = get_32_byte_rng();

    let a = gen_random_number(mta.q3.significant_bits(), &mut *rng);
    let mut alice = Alice::new(&a);

    let b = gen_random_number(mta.q3.significant_bits(), &mut *rng);
    let mut bob = Bob::new(&b);

    // alice calculates c_a and range proof of a
    let c_a = alice.calc_c_a(num_bits, &mta, &mut *rng);

    // bob recieves c_a from alice and checks if the range_proof 
    // is valid. then bob calculates c_b, range proofs and beta
    let c_b = bob.calc_c_b_and_beta(&c_a, &mta, &mut *rng);

    // alice receives c_b from bob and checks if range_proof of b 
    // and beta' are valid. then alice decrypts c_b to get alpha
    alice.calc_alpha(&c_b, &mta);

    // now a and b are multiplicatively shared between alice and bob
    // as alpha and beta respectively
    let alpha = alice.alpha.clone().unwrap();
    let beta = bob.beta.clone().unwrap();

    println!("q: {}", &mta.q);

    println!("a: {}", &a);
    println!("b: {}", &b);
    let ab = (a * b) % &mta.q;
    println!("ab: {}", ab);

    println!("alpha: {}", &alpha);
    println!("beta: {}", &beta);
    let alpha_plus_beta = (alpha + beta) % &mta.q;
    println!("alpha_plus_beta: {}", alpha_plus_beta);

    assert_eq!(ab, alpha_plus_beta);
  } 
}

