#![allow(non_snake_case)]
#![allow(dead_code)]

use rug::{
  Complete,
  Integer,
  integer::IsPrime,
};
use crate::building_block::util::{
  gen_random_number,
  get_32_byte_rng,
};

pub struct PedersenCommitment {
  group_order: Integer,
  g: Integer,
  h: Integer,
}

impl PedersenCommitment {
  pub fn new(
    group_order: &Integer,
    g: &Integer, // generator
  ) -> Self {
    let num_ite = 25;
    if group_order.is_probably_prime(num_ite) != IsPrime::Yes {
      panic!("Group order must be a prime");
    }

    let h = {
      let num_bits = group_order.significant_bits();
      let mut rng = get_32_byte_rng();
      let alpha = gen_random_number(num_bits, &mut *rng);
      let n = (g * &alpha).complete();
      n % group_order
    };

    Self {
      group_order: group_order.clone(),
      g: g.clone(),
      h: h.clone(),
    }
  }

  pub fn commit(
    &self,
    m: &Integer,
    r: &Integer,
  ) -> Integer {
    (&self.g * m).complete() + (&self.h * r).complete()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_pedersen() {
    let group_order = Integer::from(11); 
    let g = Integer::from(2); 
    let r = Integer::from(3); 

    let pedersen = PedersenCommitment::new(
      &group_order,
      &g,
    );

    let m = Integer::from(5); 
    let commitment = pedersen.commit(&m, &r);
    println!("commitment: {:?}", commitment);
  } 
}

