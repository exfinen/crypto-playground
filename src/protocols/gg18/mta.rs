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
    pail_n_bits: u32,
    a: &Integer, // additive secret share of Alice
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
    let rec_a = Paillier::decrypt(&c_a, &sk, &pk);
    assert!(a == &rec_a);
    println!("Confirmed that Alice c_a can be recovered");

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
    assert!(((&beta + &beta_prime).complete() % ss_order).is_zero());
    println!("Confirmed that beta + beta' == 0 mod ss_order");

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
    let num_bits = 256u32; // assuming secp256k1 case
    let alice = Alice::new(num_bits, &Integer::from(2));
    let mta = MtA::new(&alice.pk.n);
    let mut rng = get_32_byte_rng();

    let a = gen_random_number(mta.q3.significant_bits(), &mut rng);
    let alice = Alice::new(
      alice.pk.n.significant_bits(),
      &a,
    );

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

  #[test]
  fn test_large_num_mta() {
    use rug::integer::Order;

    let alice_value = Integer::from_digits(
      &[
        7917987850906152763u64,
        46774261152u64,
        0u64,
        0u64,
      ],
      Order::LsfLe,
    );
    //let k_A = Integer::from_digits(
    //  &[
    //    1895104715543811988,
    //    12,
    //    0u64,
    //    0u64,
    //  ],
    //  Order::LsfLe,
    //);
    let bob_value = Integer::from_digits(
      &[
        3128132900u64,
        0u64,
        0u64,
        0u64,
      ],
      Order::LsfLe,
    );
 
    // when alice_value * bob_value is calculated with MtA, the result is wrong
    // MtA should return this value (calc_act) instead
    let exp = Integer::from_str_radix(
        "2699055746193167158622976923188177095500",
        10,
    ).unwrap();

    // this returns `exp`
    let calc_act = (&alice_value * &bob_value).complete();
    assert_eq!(calc_act, exp);

    use crate::building_block::secp256k1::util::secp256k1_group_order;
    let ss_order = &secp256k1_group_order();

    // calculate with MtA
    use crate::protocols::gg18::mta::{Alice, Bob};

    let alice = Alice::new(
      ss_order.significant_bits(),
      &alice_value,
    );
    println!("Constructed Alice");
 
    let bob = Bob::new(
      ss_order,
      &alice.c_a,
      &alice.pk,
      &alice.rp_a_lt_q3,
      &bob_value,
    );
    println!("Constructed Bob");

    let mut rng = get_32_byte_rng();
    let beta_prime = gen_random_number(
      ss_order.significant_bits(),
      &mut rng,
    ) % ss_order;

    let c_a_times_b = Paillier::scalar_mul(
      &alice.c_a,
      &bob_value,
      &alice.pk,
    );
    let rec_c_a_times_b = Paillier::decrypt(&c_a_times_b, &alice.sk, &alice.pk);
    let a_times_b = alice_value * bob_value;
    assert!(&rec_c_a_times_b == &a_times_b);
    println!("Confirmed that c_a*b can be recovered");

    let rec_c_b = Paillier::decrypt(&bob.c_b, &alice.sk, &alice.pk);
    assert!(&rec_c_b == &bob.c_b);
    println!("Confirmed that c_b can be recovered");

    let alpha = alice.calc_alpha(
      &bob.c_b,
      &Integer::ZERO,
      &Integer::ZERO,
    ).unwrap();

    let act = (alpha + bob.beta) % ss_order;

    assert!(act == exp);
  }

}

