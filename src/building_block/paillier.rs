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

  pub fn gen_key() -> (PublicKey, SecretKey) {
    let num_bits = 128;
    let p = Self::gen_random_prime(num_bits);
    let q = Self::gen_random_prime(num_bits);
    let n = Integer::from(&p * &q);

    let k = {
      let k = Self::gen_random_number();
      let group = AdditiveGroup::new(&n);
      group.element(&k)
    }; // k in Z_n

    // TODO implement Element.*
    let n_sq = Integer::from(&n * &n);
    let g = {
      let kn = k * &n;
      let g = 1 + kn % &n_sq; // g is in Z_n^2
      g
    };

    let pk = PublicKey { n: n.clone(), g };
    let sk = SecretKey { p, q };
    (pk, sk)
  }

  // returns an element in Z_n^2
  pub fn encrypt(pk: &PublicKey, m: &Element) -> Element {
    let n_sq = pk.n * pk.n;
    let group = AdditiveGroup::new(&n_sq);

    // select r randomly from Z_n^2
    let r = group.get_random_element();

    // m is an element of Z_n
    assert_eq!(m.order, &n);

    // g is in Z_n^2
    // c is in Z_n^2
    let c = (pk.g.pow(&m) + r.pow(&pk.n));
    c
  }

  pub fn L(u: &Integer, n: &Integer) -> Integer {
    (u - 1) / n
  }

  pub fn decrypt(c: &Element, sk: &SecretKey) -> Integer {
    let lambda = lcm(sk.p − 1, sk.q − 1);
    let n = sk.p * sk.q;
    let group = AdditiveGroup::new(n);
    let m = Self::L(c^lambda) / Self::L(g^lambda);
    m
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::building_block::additive_group::AdditiveGroup;

  #[test]
  fn test() {
    let order = Integer::from(29);
    let group = AdditiveGroup::new(order);

    let p = group.element(Integer::from(5));
    let q = group.element(Integer::from(7));
  } 
}

