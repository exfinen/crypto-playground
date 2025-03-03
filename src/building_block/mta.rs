#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use rug::{
  ops::Pow,
  Complete,
  rand::RandState,
};
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
use crate::building_block::util::{
  gen_random_number,
  get_32_byte_rng,
};

pub struct Alice {
  pub c_a: Integer,
  pub rp_a_lt_q3: Integer,
  pub pk: PublicKey,
  pub sk: SecretKey,
}

impl Alice {
  pub fn new(
    num_bits: u32,
    a: &Integer,
    rng: &mut dyn MutRandState,
  ) -> Alice {
    let inst = Paillier::new(num_bits, GCalcMethod::Random);
    let (pk, sk) = (inst.pk, inst.sk);

    let c_a = Paillier::encrypt(
      num_bits, &mut *rng, a, &pk
    );

    // TODO implement range proof of a < q^3
    let rp_a_lt_q3 = Integer::ZERO;

    Alice {
      c_a,
      rp_a_lt_q3,
      pk,
      sk,
    }
  }

  pub fn calc_alpha(
    &self,
    c_b: &Integer,
    _rp_b_lt_q3: &Integer,
    _rp_b_lt_q3_bp_le_q7: &Integer,
  ) -> Option<Integer> {
    // TODO check if given range proofs are valid
 
    // alice decrypts c_b to get alpha = ab + beta'
    let alpha = Paillier::decrypt(c_b, &self.sk, &self.pk);
    Some(alpha)
  }
}

pub struct Bob {
  pub c_b: Integer,
  pub beta: Integer,
  pub rp_b_lt_q3: Integer, // b < q^3
  pub rp_b_lt_q3_bp_le_q7: Integer, // b < q^3 and beta' < q^7(q^5?)
}

impl Bob {
  pub fn new(
    b: &Integer,
    c_a: &Integer,
    _rp_a_lt_q3: &Integer,
    pk: &PublicKey,
    mta: &MtA,
  ) -> Bob {
    // TODO check if range proof of c_a is valid
    
    let mut rng = get_32_byte_rng();

    // choose beta' uniformly at random in Z_q^5
    let beta_prime = gen_random_number(
      mta.q5.significant_bits(),
      &mut rng,
    );

    let c_beta_prime = Paillier::encrypt(
      pk.n.significant_bits(),
      &mut rng,
      &beta_prime,
      pk,
    );

    // c_b = ENC(ab) + c_beta'
    let c_b = {
      let c_a_times_b = Paillier::scalar_mul(
        &c_a,
        b,
        pk,
      );
      Paillier::add(&c_a_times_b, &c_beta_prime, pk)
    };

    // beta in Z_q
    let beta = {
      let neg_beta_prime = (&beta_prime * -1i8).complete() % &mta.q;
      &mta.q + neg_beta_prime
    };

    // TODO implement this
    let rp_b_lt_q3 = Integer::ZERO; // beta' is in Z_q^5
    let rp_b_lt_q3_bp_le_q7 = Integer::ZERO; // b < q^3 and beta' < q^7

    Bob {
      c_b,
      beta,
      rp_b_lt_q3,
      rp_b_lt_q3_bp_le_q7,
    }
  }
}

pub struct MtA {
  pub q: Integer,
  pub q3: Integer, // q^3
  pub q5: Integer, // q^5
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

  pub fn new(n: &Integer) -> MtA {
    let q = Self::calc_q(n);
    let q3 = &q.clone().pow(3);
    let q5 = &q.clone().pow(5);

    MtA {
      q,
      q3: q3.clone(),
      q5: q5.clone(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_mta() {
    let num_bits = 256u32; // assuming secp256k1 case
    let alice = Alice::new(num_bits, &Integer::from(2), &mut get_32_byte_rng());
    let mta = MtA::new(&alice.pk.n);
    let mut rng = get_32_byte_rng();

    let a = gen_random_number(mta.q3.significant_bits(), &mut rng);
    let alice = Alice::new(
      alice.pk.n.significant_bits(),
      &a,
      &mut rng,
    );

    let b = gen_random_number(mta.q3.significant_bits(), &mut rng);
    let bob = Bob::new(
      &b,
      &alice.c_a,
      &alice.rp_a_lt_q3,
      &alice.pk,
      &mta,
    );

    let alpha = alice.calc_alpha(
      &bob.c_b,
      &bob.rp_b_lt_q3,
      &bob.rp_b_lt_q3_bp_le_q7,
    );
    let alpha = alpha.expect("Failed to decrypt c_b");

    println!("q: {}", &mta.q);

    println!("a: {}", &a);
    println!("b: {}", &b);
    let ab = (a * b) % &mta.q;
    println!("ab: {}", ab);

    println!("alpha: {}", &alpha);
    println!("beta: {}", &bob.beta);
    let alpha_plus_beta = (alpha + &bob.beta) % &mta.q;
    println!("alpha_plus_beta: {}", alpha_plus_beta);

    assert_eq!(ab, alpha_plus_beta);
  } 
}

