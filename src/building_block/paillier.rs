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

  pub fn gen_random_prime(num_bits: u32) -> Integer {
    let mut rng = rug::rand::RandState::new();
    let mut n = Integer::from(Integer::random_bits(num_bits, &mut rng));

    let num_ite = 25;
    while n.is_probably_prime(num_ite) != IsPrime::Yes {
        n.assign(Integer::random_bits(num_bits, &mut rng));
    }
    n
  }

  pub fn new(num_bits: u32) -> Paillier {
    let p = Integer::from(233u8); // Self::gen_random_prime(num_bits);
    let q = Integer::from(211u8); //Self::gen_random_prime(num_bits);
    let n = Integer::from(&p * &q);
    println!("p: {:?}, q: {:?}, n: {:?}", p, q, n);

    let z_n = AdditiveGroup::new(&n);
    let k = z_n.get_random_element();

    // 2417000569
    let nn = (&n * &n).complete();
    println!("nn: {:?}", nn);
    let z_nn = AdditiveGroup::new(&nn);

    // let g = {
    //   let kn = (k.value_ref() * &n).complete();
    //   let one_plus_kn = (Integer::ONE + &kn).complete();
    //   (&one_plus_kn % &nn).complete()
    // };
    let g = Integer::from(524360);

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
    // m must be an element of Z_n
    assert_eq!(m.order_ref(), self.z_n.order_ref());

    // select r randomly from Z_n^2
    let r = self.z_nn.element(&Integer::from(10418));
    println!("r: {:?}", r.value());

    let nn = self.z_nn.order_ref();
    let gm = pk.g.clone().pow_mod(m.value_ref(), nn).unwrap();
    println!("g^m: {:?}", gm);

    // 857909725
    let rn = r.value().clone().pow_mod(&pk.n, nn).unwrap();
    println!("r^n: {:?}", rn);

    // 1233063404
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
    println!("lambda: {:?}", lambda);

    let nn = &self.nn;

    let lhs = self.z_nn.element(&(c.value().clone().pow_mod(&lambda, nn).unwrap()));
    let rhs = self.z_nn.element(&(pk.g.clone().pow_mod(&lambda, nn).unwrap()));

    // 19022
    let lhs = self.L(&lhs);
    println!("lhs: {:?}", lhs);

    let rhs = self.L(&rhs);
    println!("rhs: {:?}", rhs);

    let rhs_inv = rhs.invert(&self.n).unwrap();

    let m = lhs * rhs_inv;
    self.z_n.element(&m)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test() {
    let pal = Paillier::new(8);
    let m = pal.z_n.element(&Integer::from(23u8));
    println!("m: {:?}", m.value());

    let c = pal.encrypt(&pal.pk, &m);
    println!("c: {:?}", c.value());

    let m_rec = pal.decrypt(&c, &pal.sk, &pal.pk);
    println!("m (recovered): {:?}", m_rec.value());

    assert_eq!(m.value(), m_rec.value());
  } 
}

