#![allow(non_snake_case)]
#![allow(dead_code)]

use rand::Rng;
use rug::{Assign, Complete, Integer};
use rug::integer::IsPrime;
use rug::rand::{MutRandState, RandState};
use crate::building_block::additive_group::{
  AdditiveGroup,
  Element,
};

pub enum GCalculation {
  Random,
  KnPlusOne,
}

pub struct Paillier {
  n: Integer,
  nn: Integer,
  pub z_n: AdditiveGroup,
  pub z_nn: AdditiveGroup,
  pub pk: PublicKey,
  pub sk: SecretKey,
}

pub struct PublicKey {
  n: Integer,
  g: Integer,
}

pub struct SecretKey {
  p: Integer,
  q: Integer,
}

impl Paillier {
  fn gen_random_number() -> Integer {
    let mut rng = rand::thread_rng();
    Integer::from(rng.gen::<u128>())
  }

  pub fn gen_random_prime(num_bits: u32, rng: &mut dyn MutRandState) -> Integer {
    let mut n = Integer::from(Integer::random_bits(num_bits, rng));

    let num_ite = 25;
    while n.is_probably_prime(num_ite) != IsPrime::Yes {
        n.assign(Integer::random_bits(num_bits, rng));
    }
    n
  }

  pub fn new(num_bits: u32, g_calc: GCalculation) -> Paillier {
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
    let z_n = AdditiveGroup::new(&n);
 
    let nn = (&n * &n).complete();
    let z_nn = AdditiveGroup::new(&nn);

    let g = match g_calc {
      GCalculation::Random => {
        // g is an element of Z^*_n^2
        // such that gcd(g, n^2) = 1
        loop {
          let g = Self::gen_random_number();
          if &g.clone().gcd(&nn) == Integer::ONE {
            break g;
          }
        }
      },
      GCalculation::KnPlusOne => {
        loop {
          // // k is coprime to n
          // let k = loop {
          //   let k = Self::gen_random_number();
          //   if &k.clone().gcd(&n) == Integer::ONE {
          //     break k;
          //   }
          // };
          let k = Self::gen_random_number() % &n;
          let g = ((k * &n) + Integer::ONE) % &nn;
          if &g.clone().gcd(&nn) == Integer::ONE {
            break g;
          }
        }
      },
    };

    let pk = PublicKey { n: n.clone(), g };
    let sk = SecretKey { p, q };

    Paillier {
      n,
      nn,
      z_n,
      z_nn,
      pk,
      sk,
    }
  }

  // returns an element in Z_n^2
  pub fn encrypt(&self, pk: &PublicKey, m: &Element) -> Element {
    // TODO m = m mod n; m in Z_n

    let nn = &self.z_nn.order_ref();

    // Z_{n^2} is multiplicative group of integers modulo n^2 (Z/n^2Z)
    // select r randomly from Z_{n^2}
    let r = loop {
      let r = Self::gen_random_number();
      if &r.clone().gcd(nn) == Integer::ONE {
        break self.z_nn.element(&r);
      }
    };

    let gm = pk.g.clone().pow_mod(m.value_ref(), nn).unwrap();
    let rn = r.value().clone().pow_mod(&pk.n, nn).unwrap();

    let c = gm * rn;
    self.z_nn.element(&c)
  }

  fn L(&self, u: &Element) -> Integer {
    let u_minus_1 = (u.value_ref() - Integer::ONE).complete();
    u_minus_1 / &self.n
  }

  pub fn decrypt(
    &self,
    c: &Element,
    sk: &SecretKey,
    pk: &PublicKey,
  ) -> Element {
    let p_minus_1 = (&sk.p - 1u8).complete();
    let q_minus_1 = (&sk.q - 1u8).complete();
    let lambda = p_minus_1.lcm(&q_minus_1);

    let nn = &self.nn;

    let lhs = self.z_nn.element(&(c.value().clone().pow_mod(&lambda, nn).unwrap()));
    let rhs = self.z_nn.element(&(pk.g.clone().pow_mod(&lambda, nn).unwrap()));

    let lhs = self.L(&lhs);

    let rhs = self.L(&rhs);

    let rhs_inv = rhs.invert(&self.n).unwrap();

    let m = lhs * rhs_inv;
    self.z_n.element(&m)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_pallier() {
    use rand::thread_rng;
    use std::io::{self, Write};

    let mut rng = thread_rng();

    for _ in 0..100 {
      let pal = Paillier::new(64, GCalculation::Random);
      let m = pal.z_n.element(&Integer::from(rng.gen::<u128>()));

      let c = pal.encrypt(&pal.pk, &m);
      let m_rec = pal.decrypt(&c, &pal.sk, &pal.pk);
      assert_eq!(m.value(), m_rec.value());
      print!(".");
      io::stdout().flush().unwrap();
    }
  } 
}

