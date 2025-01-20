#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::additive_group::{
  AdditiveGroup,
  Element,
};
use rand::Rng;
use rug::Integer;

pub struct PedersenCommitment {
  G: AdditiveGroup,  // cyclic group
  g: Element,  // generator of g
  h: Element,  // h = g^r for some random r
}

impl PedersenCommitment {
  pub fn new(
    G: &AdditiveGroup,
    g: &Element,
    h: &Element,
  ) -> Self {
    Self {
      G: G.clone(),
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

