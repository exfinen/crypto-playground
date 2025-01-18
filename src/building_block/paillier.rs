#![allow(non_snake_case)]
#![allow(dead_code)]

use rand::Rng;
use rug::{Integer, Assign};
use rug::integer::IsPrime;
use crate::building_block::additive_group::{
  AdditiveGroup,
  Element,
};

pub struct Paillier {
  n: Integer,
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
    Paillier { n }
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
      let kn: Integer = (k.n * &n).into();
      let group_nn = AdditiveGroup::new(&nn);
      group_nn.element(&(kn + Integer::from(1)))
    };

    let pk = PublicKey { n: n.clone(), g: g.n };
    let sk = SecretKey { p, q };
    KeyPair { pk, sk }
  }

  // returns an element in Z_n^2
  pub fn encrypt(&self, pk: &PublicKey, m: &Element) -> Element {
    let nn: Integer = (&pk.n * &pk.n).into();
    let group_nn = AdditiveGroup::new(&nn);

    // select r randomly from Z_n^2
    let r = group_nn.get_random_element();

    // m is an element of Z_n
    assert_eq!(&m.order, &self.n);

    // g is in Z_n^2
    // c is in Z_n^2
    let c = group_nn.element(&(
      pk.g.clone().pow_mod(&m.n, &nn).unwrap()
      + r.n.pow_mod(&pk.n, &nn).unwrap()
    ));
    c
  }

  pub fn L(&self, u: &Integer) -> Integer {
    let u_minus_1: Integer = u - Integer::from(1);
    u_minus_1 / &self.n
  }

  fn lcm(a: &Integer, b: &Integer) -> Integer {
    let gcd = a.clone().gcd(b);
    let product: Integer = (a * b).into();
    let lcm = product / gcd;
    Integer::from(lcm)
  }

  pub fn decrypt(
    &self,
    c: &Element,
    sk: &SecretKey,
    pk: &PublicKey,
  ) -> Element {
    let p_minus_1: Integer = (&sk.p - &Integer::from(1)).into();
    let q_minus_1: Integer = (&sk.q - &Integer::from(1)).into();
    let lambda = Self::lcm(&p_minus_1, &q_minus_1);

    let nn: Integer = (&pk.n * &pk.n).into();
    let group_nn = AdditiveGroup::new(&nn);

    let lhs_arg = group_nn.element(
      &(c.n.clone().pow_mod(&lambda, &nn).unwrap())
    );
    let rhs_arg = group_nn.element(
      &(pk.g.clone().pow_mod(&lambda, &nn).unwrap())
    );

    let m = self.L(&lhs_arg.n) / self.L(&rhs_arg.n);
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

    let p = group.element(&Integer::from(5));
    let q = group.element(&Integer::from(7));
  } 
}

