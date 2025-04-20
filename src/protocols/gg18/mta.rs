#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use rug::{
  ops::Pow,
  Complete,
};
use rug::Integer;
use crate::{
  building_block::{
    secp256k1::util::secp256k1_group_order,
    util::{
      gen_random_number,
      get_32_byte_rng,
    },
  },
  protocols::gg18::paillier::{
    GCalcMethod,
    Paillier,
    PublicKey,
    SecretKey,
  },
};

pub struct Alice {
  pub c_a: Integer,
  pub rp_a_lt_q3: Integer,
  pub pk: PublicKey,
  pub sk: SecretKey,
}

impl Alice {
  pub fn new(
    a: &Integer,
  ) -> Alice {
    let ss_order = secp256k1_group_order();
    let (pail_p, pail_q) = Paillier::gen_p_q(&ss_order);
    let inst = Paillier::new(
      &pail_p,
      &pail_q,
      GCalcMethod::Random,
    );
    let (pk, sk) = (inst.pk, inst.sk);
    let mut rng = get_32_byte_rng();

    let c_a = Paillier::encrypt(&mut rng, a, &pk);

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
    // TODO check if the two range proofs are valid
 
    // alice decrypts c_b to get alpha = ab + beta'
    let alpha = Paillier::decrypt(c_b, &self.sk, &self.pk) % &self.pk.n;
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
    ss_order: &Integer, // order of group/field for secret sharing
    c_a: &Integer,
    pk: &PublicKey,
    _rp_a_lt_q3: &Integer,
    b: &Integer,
  ) -> Bob {
    // TODO check if range proof of c_a is valid
    
    let mut rng = get_32_byte_rng();

    // sample beta' from z_{ss_order^5}
    let ss_order_bits_pow_5 = ss_order.pow(5).complete();
    let beta_prime = gen_random_number(
      ss_order_bits_pow_5.significant_bits(),
      &mut rng,
    ) % ss_order_bits_pow_5;
    
    let c_beta_prime = Paillier::encrypt(
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

    // beta in Z_ss_order
    let beta_prime = beta_prime % ss_order;
    let beta: Integer = ((ss_order - &beta_prime).complete() % ss_order).into();

    // TODO implement rp
 
    // beta' is in Z_{ss_order^5}
    let rp_b_lt_q3 = Integer::ZERO; 
                                   
    // b < {ss_order}^3 and beta' < {ss_order}^7
    let rp_b_lt_q3_bp_le_q7 = Integer::ZERO;

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
    let alice = Alice::new(&Integer::from(2));
    let mta = MtA::new(&alice.pk.n);
    let mut rng = get_32_byte_rng();

    let a = gen_random_number(mta.q3.significant_bits(), &mut rng);
    let alice = Alice::new(&a);

    let b = gen_random_number(mta.q3.significant_bits(), &mut rng);
    let bob = Bob::new(
      &mta.q,
      &alice.c_a,
      &alice.pk,
      &alice.rp_a_lt_q3,
      &b,
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

