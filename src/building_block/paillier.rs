#![allow(non_snake_case)]
#![allow(dead_code)]

use rug::{
  Complete,
  Integer,
  rand::MutRandState,
};
use crate::building_block::util::{
  gen_random_number,
  gen_random_prime,
  get_rng,
};

pub enum GCalcMethod {
  Random,
  KnPlusOne,
}

pub struct Paillier();

pub struct PublicKey {
  pub n: Integer,
  pub g: Integer,
}

pub struct SecretKey {
  // p: Integer,
  // q: Integer,
  lambda: Integer,
  mu: Integer,
}

impl Paillier {
  // mod nn -> mod n
  fn L(u: &Integer, n: &Integer) -> Integer {
    let u_minus_1 = (u - 1u8).complete();
    u_minus_1 / n
  }

  fn calc_g(
    num_bits: u32,
    rng: &mut dyn MutRandState,
    calc_method: &GCalcMethod,
    n: &Integer,
    nn: &Integer,
  ) -> Integer {
    match calc_method {
      GCalcMethod::Random => {
        // g is an element of Z^*_n^2
        // such that gcd(g, n^2) = 1
        loop {
          let g = gen_random_number(num_bits, rng);
          if &g.clone().gcd(&nn) == Integer::ONE {
            break g;
          }
        }
      },
      GCalcMethod::KnPlusOne => {
        loop {
          // find k that is coprime to n
          let k = loop {
            let k = gen_random_number(num_bits, rng);
            if &k.clone().gcd(&n) == Integer::ONE {
              break k;
            }
          };
          let g = ((k * n) + Integer::ONE) % nn;
          if &g.clone().gcd(&nn) == Integer::ONE {
            break g;
          }
        }
      },
    }
  }

  pub fn new(
    num_bits: u32,
    g_calc_method: GCalcMethod,
  ) -> (PublicKey, SecretKey) {
    let mut rng = get_rng();

    // generate distinct primes p and q
    let p = gen_random_prime(num_bits, &mut *rng);
    let q = loop {
      let q = gen_random_prime(num_bits, &mut *rng);
      if &p != &q {
        break q;
      }
    };

    let n = Integer::from(&p * &q);
    let nn = (&n * &n).complete();

    let p_minus_1 = (&p - 1u8).complete();
    let q_minus_1 = (&q - 1u8).complete();
    let lambda = p_minus_1.lcm(&q_minus_1);

    let (g, mu) = {
      loop {
        let g = Self::calc_g(
          num_bits, &mut *rng, &g_calc_method, &n, &nn,
        );
        let g_lambda = g.clone().pow_mod(&lambda, &nn).unwrap();
        let k = Self::L(&g_lambda, &n);
        // k needs be a coprime to g to have an inverse
        if &g.clone().gcd(&k) == Integer::ONE {
          let mu = k.invert(&n).unwrap();
          break (g, mu);
        }
      }
    };

    let pk = PublicKey { n: n.clone(), g };
    let sk = SecretKey { lambda, mu };
    (pk, sk)
  }

  // encrypted message is in multiplicative group modulo n^2
  pub fn encrypt(
    num_bits: u32,
    rng: &mut dyn MutRandState,
    m: &Integer, // plaintext
    pk: &PublicKey,
  ) -> Integer {
    if m < &Integer::ZERO || m >= &pk.n {
      panic!("m should be in additive group module n");
    }

    let nn = &(&pk.n * &pk.n).complete();

    // Z_{n^2} is multiplicative group of integers modulo n^2 (Z/n^2Z)
    // select r randomly from Z_{n^2}
    let r = loop {
      let r = gen_random_number(num_bits, rng) % nn;
      if &r.clone().gcd(nn) == Integer::ONE {
        break r;
      }
    };

    let gm = pk.g.clone().pow_mod(m, nn).unwrap();
    let rn = r.pow_mod(&pk.n, nn).unwrap();

    (gm * rn) % nn
  }

  // decrypted message is in additive group modulo n
  pub fn decrypt(
    c: &Integer, // cyphertext
    sk: &SecretKey,
    pk: &PublicKey,
  ) -> Integer {
    let n = &pk.n;
    let nn = &(n * n).complete();

    let num = c.clone().pow_mod(&sk.lambda, nn).unwrap();

    Self::L(&num, n) * &sk.mu % &pk.n
  }

  pub fn add(
    c1: &Integer, // cyphertext
    c2: &Integer, // cyphertext
    pk: &PublicKey,
  ) -> Integer {
    let nn = (&pk.n * &pk.n).complete();
    (c1 * c2).complete() % nn
  }

  pub fn scalar_mul(
    c: &Integer, // cyphertext 
    m: &Integer, // plaintext multiplier
    pk: &PublicKey,
  ) -> Integer {
    let nn = &(&pk.n * &pk.n).complete();
    c.clone().pow_mod(m, &nn).unwrap()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_add() {
    // p = 3, q = 5, n = 15, n^2 = 225
    let pk = PublicKey {
        n: Integer::from(15),
        g: Integer::ONE.clone(),
    };
    // Homomorphic addition is performed as multiplication modulo n^2.
    // Compute: (44 * 55) mod 225.
    // 44 * 55 = 2420 and 2420 mod 225 = 2420 - (225 * 10) = 2420 - 2250 = 170.
    let res = Paillier::add(&Integer::from(44), &Integer::from(55), &pk);
    assert_eq!(res, Integer::from(170));
  }

  #[test]
  fn test_scalar_mul() {
      let pk = PublicKey {
          n: Integer::from(15),
          g: Integer::from(16),
      };
      // 11^9 mod 225 should be 116
      let res = Paillier::scalar_mul(&Integer::from(11), &Integer::from(9), &pk);
      assert_eq!(res, Integer::from(116));
  }

  #[test]
  fn test_enc_dec() {
    use std::io::{self, Write};

    let mut rng = get_rng();
    let num_bits = 64;

    for _ in 0..10 {
      let (pk, sk) = Paillier::new(num_bits, GCalcMethod::Random);
      let m = gen_random_number(num_bits, &mut *rng) % &pk.n;

      let c = Paillier::encrypt(num_bits, &mut *rng, &m, &pk);
      let m_prime = Paillier::decrypt(&c, &sk, &pk);
      assert_eq!(m, m_prime);

      print!(".");
      io::stdout().flush().unwrap();
    }
  } 

  #[test]
  fn test_additive_homomorphic_property() {
    let mut rng = get_rng();
    let num_bits = 64;

    let (pk, sk) = Paillier::new(num_bits, GCalcMethod::Random);
    let m1 = gen_random_number(num_bits, &mut *rng) % &pk.n;
    let m2 = gen_random_number(num_bits, &mut *rng) % &pk.n;

    let c1 = Paillier::encrypt(num_bits, &mut *rng, &m1, &pk);
    let c2 = Paillier::encrypt(num_bits, &mut *rng, &m2, &pk);

    let c3 = Paillier::add(&c1, &c2, &pk);
    let m3 = Paillier::decrypt(&c3, &sk, &pk);

    let m3_prime = (m1 + m2) % &pk.n;
    assert_eq!(m3, m3_prime);
  }
}

