#![allow(non_snake_case)]

use crate::group::{
  AdditiveGroup,
  Element,
};
use rug::Integer;

struct PedersenCommitment {
  G: AdditiveGroup,  // cyclic group
  g: Element,  // generator of g
  h: Element,  // h = g^r for some random r
}

impl PedersenCommitment {
    pub fn new(
      G: AdditiveGroup,
      g: Element,
      h: Element,
    ) -> Self {
        Self { G, g, h }
    }

    pub fn commit(&self, u: &Integer) -> (Element, Integer) {
      let mut rng = rand::thread_rng();
      let r = rng.gen_range(0..u64::MAX);

      let C = self.g * u + self.h * r
      (C, r)
    }

    pub fn verify(
      &self,
      C: &Element,
      u: &Integer,
      r: &Integer,
    ) -> bool {
       C == self.g * u + self.h * r
    }
}

#[cfg(test)]
mod tests {
  //use super::*;

  #[test]
  fn test() {
  } 
}

