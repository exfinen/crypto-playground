#![allow(non_snake_case)]
#![allow(dead_code)]

use rand::Rng;
use rug::{Assign, Complete, Integer};
use rug::integer::IsPrime;
use rug::rand::{MutRandState, RandState};

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
  fn gen_random_number() -> Integer {
    let mut rng = rand::thread_rng();
    Integer::from(rng.gen::<u128>())
  }

  pub fn gen_random_prime(
    num_bits: u32,
    rng: &mut dyn MutRandState,
  ) -> Integer {
    let mut n = Integer::from(Integer::random_bits(num_bits, rng));

    let num_ite = 25;
    while n.is_probably_prime(num_ite) != IsPrime::Yes {
      n.assign(Integer::random_bits(num_bits, rng));
    }
    n
  }

  // mod nn -> mod n
  fn L(u: &Integer, n: &Integer) -> Integer {
    let u_minus_1 = (u - 1u8).complete();
    u_minus_1 / n
  }

  fn calc_g(
    calc_method: &GCalcMethod,
    n: &Integer,
    nn: &Integer,
  ) -> Integer {
    match calc_method {
      GCalcMethod::Random => {
        // g is an element of Z^*_n^2
        // such that gcd(g, n^2) = 1
        loop {
          let g = Self::gen_random_number();
          if &g.clone().gcd(&nn) == Integer::ONE {
            break g;
          }
        }
      },
      GCalcMethod::KnPlusOne => {
        loop {
          // find k that is coprime to n
          let k = loop {
            let k = Self::gen_random_number();
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

  pub fn new(num_bits: u32, g_calc_method: GCalcMethod) -> (PublicKey, SecretKey) {
    let mut rng = RandState::new();
    let seed = {
      use rand::thread_rng;
      let mut rng = thread_rng();
      Integer::from(rng.gen::<u128>())
    };
    rng.seed(&seed);

    // generate distinct primes p and q
    let p = Self::gen_random_prime(num_bits, &mut rng);
    let q = loop {
      let q = Self::gen_random_prime(num_bits, &mut rng);
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
        let g = Self::calc_g(&g_calc_method, &n, &nn);
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
  pub fn encrypt(m: &Integer, pk: &PublicKey) -> Integer {
    if m < &Integer::ZERO || m >= &pk.n {
      panic!("m should be in additive group module n");
    }

    let nn = &(&pk.n * &pk.n).complete();

    // Z_{n^2} is multiplicative group of integers modulo n^2 (Z/n^2Z)
    // select r randomly from Z_{n^2}
    let r = loop {
      let r = Self::gen_random_number() % nn;
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
    c: &Integer,
    sk: &SecretKey,
    pk: &PublicKey,
  ) -> Integer {
    let n = &pk.n;
    let nn = &(n * n).complete();

    let num = c.clone().pow_mod(&sk.lambda, nn).unwrap();

    Self::L(&num, n) * &sk.mu % &pk.n
  }

  pub fn add(
    c1: &Integer,
    c2: &Integer,
    pk: &PublicKey,
  ) -> Integer {
    let nn = (&pk.n * &pk.n).complete();
    let sum = (c1 + c2).complete();
    sum % &nn
  }

  pub fn scalar_mul(
    c: &Integer,
    m: &Integer, // multiplier
    pk: &PublicKey,
  ) -> Integer {
    let nn = &(&pk.n * &pk.n).complete();

    let mut res = Integer::ZERO;
    let mut m = m.clone();
    let mut bit_amount = c.clone();

    while &m != &Integer::ZERO {
      // if the least significant bit is 1
      let lsb = (&m & Integer::ONE).complete();
      if &lsb == Integer::ONE {
        // add the amount for the current bit to res
        res += &bit_amount;
        if &res > nn {
          res = res % nn;
        }
      }
      // update bit_amount to represent the next bit 
      bit_amount = (&bit_amount + &bit_amount).complete();
      m = m >> &1u32; // shift to the right to test the next bit
    }
    res
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_add() {
    let pk = PublicKey {
      n: Integer::from(8),
      g: Integer::ONE.clone(),
    };
    let res = Paillier::add(&Integer::from(44), &Integer::from(55), &pk);
    // 99 mod 64 = 35
    assert_eq!(res, Integer::from(35));
  }

  #[test]
  fn test_scalar_mul() {
    let pk = PublicKey {
      n: Integer::from(8),
      g: Integer::ONE.clone(),
    };
    let res = Paillier::scalar_mul(&Integer::from(11), &Integer::from(9), &pk);
    // 99 mod 64 = 35
    assert_eq!(res, Integer::from(35));
  }

  #[test]
  fn test_enc_dec() {
    use rand::thread_rng;
    use std::io::{self, Write};

    let mut rng = thread_rng();

    for _ in 0..100 {
      let (pk, sk) = Paillier::new(64, GCalcMethod::Random);
      let m = Integer::from(rng.gen::<u128>()) % &pk.n;

      let c = Paillier::encrypt(&m, &pk);
      let m_prime = Paillier::decrypt(&c, &sk, &pk);
      assert_eq!(m, m_prime);

      print!(".");
      io::stdout().flush().unwrap();
    }
  } 
}

