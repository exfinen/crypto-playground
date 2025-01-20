#![allow(non_snake_case)]
#![allow(dead_code)]

use rand::Rng;
use rug::{Assign, Complete, Integer};
use rug::integer::IsPrime;
use crate::building_block::additive_group::{
  AdditiveGroup,
  Element,
};

pub struct Paillier {
  n: Integer,
  nn: Integer,
}

pub struct PublicKey {
  n: Integer,
  g: Integer,
}

pub struct SecretKey {
  p: Integer,
  q: Integer,
}

pub struct KeyPair {
  pub pk: PublicKey,
  pub sk: SecretKey,
}

impl Paillier {
  // p and q need to be prime
  pub fn new(p: Integer, q: Integer) -> Paillier {
    let n = p * q;
    let nn = n.clone().square();
    Paillier { n, nn }
  }

  fn gen_random_number() -> Integer {
    let mut rng = rand::thread_rng();
    Integer::from(rng.gen::<u128>())
  }

  pub fn gen_random_prime(num_bits: u32) -> Integer {
    let mut rng = rug::rand::RandState::new();
    let mut n = Integer::from(Integer::random_bits(num_bits, &mut rng));

    let num_ite = 25;
    while n.is_probably_prime(num_ite) != IsPrime::Yes {
        n.assign(Integer::random_bits(num_bits, &mut rng));
    }
    n
  }

  pub fn gen_key() -> KeyPair {
    let num_bits = 128;
    let p = Self::gen_random_prime(num_bits);
    let q = Self::gen_random_prime(num_bits);
    let n = Integer::from(&p * &q);

    let k = {
      let k = Self::gen_random_number();
      let group_n = AdditiveGroup::new(&n);
      group_n.element(&k)
    }; // k in Z_n

    let nn = Integer::from(&n * &n);
    let g = {
      let kn: Integer = (k.value() * &n).into();
      let group_nn = AdditiveGroup::new(&nn);
      group_nn.element(&(kn + Integer::from(1)))
    };

    let pk = PublicKey { n: n.clone(), g: g.value() };
    let sk = SecretKey { p, q };
    KeyPair { pk, sk }
  }

  // returns an element in Z_n^2
  pub fn encrypt(&self, pk: &PublicKey, m: &Element) -> Element {
    let nn = (&pk.n * &pk.n).complete();
    let group_nn = AdditiveGroup::new(&nn);

    // select r randomly from Z_n^2
    let r = group_nn.get_random_element();

    // m must be an element of Z_n
    m.assert_order(&self.n);

    // g is in Z_n^2
    // c is in Z_n^2
    let c = {
      let lhs = pk.g.clone().pow_mod(m.value_ref(), &nn).unwrap();
      let rhs: Integer = r.value().pow_mod(&pk.n, &nn).unwrap();
      group_nn.element(&(lhs + rhs))
    };
    c
  }

  pub fn L(&self, u: &Element) -> Integer {
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

    let group_nn = AdditiveGroup::new(&self.nn);

    let lhs_arg = &group_nn.element(
      &(c.value().pow_mod(&lambda, &self.nn).unwrap())
    );
    let rhs_arg = &group_nn.element(
      &(pk.g.clone().pow_mod(&lambda, &self.nn).unwrap())
    );

    let m = self.L(lhs_arg) / self.L(rhs_arg);
    let group_n = AdditiveGroup::new(&pk.n);
    group_n.element(&m)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::building_block::additive_group::AdditiveGroup;

  #[test]
  fn test() {
    let order = Integer::from(29);
    let group = AdditiveGroup::new(&order);

    let _p = group.element(&Integer::from(5));
    let _q = group.element(&Integer::from(7));
  } 
}

