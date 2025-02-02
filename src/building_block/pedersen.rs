#![allow(non_snake_case)]
#![allow(dead_code)]

use rand::Rng;
use rug::{Complete, Integer};

pub struct PedersenCommitment {
  group_order: Integer,
  g: Element,
  h: Element,
}

impl PedersenCommitment {
  pub fn new(
    group_order: &Integer,
    generator: &Integer,
  ) -> Self {
    let num_ite = 25;
    if group_order.is_probably_prime(num_ite) != IsPrime::Yes {
      panic!("Group order must be a prime");
    }

    let h = {
      let alpha = 
      let n = (generator * alpha).complete();
      n % group_order
    };
    Self {
      group_order: group_order.clone(),
      g: g.clone(),
      h: h.clone(),
    }
  }

  pub fn commit(&self, u: &Integer) -> (Element, Integer) {
    let mut rng = rand::thread_rng();
    let r = Integer::from(rng.gen_range(0..u64::MAX));

    let C = &self.g * u + &self.h * &r;
    (C, r)
  }

  pub fn verify(
    &self,
    C: &Element,
    u: &Integer,
    r: &Integer,
  ) -> bool {
     C == &self.g * u + &self.h * r
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test() {
    let eleven = Integer::from(11); 
    let two = Integer::from(2); 
    let three = Integer::from(3); 

    let group_11 = AdditiveGroup::new(&eleven);
    let g = group_11.element(&two); 
    let h = group_11.element(&three); 
    let _ = PedersenCommitment::new(
      &group_11,
      &g,
      &h,
    );
  } 
}

