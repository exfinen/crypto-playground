#![allow(dead_code)]

use rug::Integer;
use std::ops::{Add, Mul};

pub struct Element {
  pub order: Integer,
  pub n: Integer,
}

impl Add for Element {
  type Output = Self;

  fn add(self, other: Self) -> Self {
    assert_eq!(self.order, other.order, "Tried to add elements of different orders");
    let res = (self.n + other.n) % &self.order;
    Self::new(self.order.clone(), res)
  }
}

// Scalar multiplication
// impl Mul for Element {
//   type Output = Self;
// 
//   fn mul(self, n: &Integer) -> Self {
//     let mut n = rhs.clone();
//     let mut res = AffinePoint::zero();
//     let mut pt_pow_n = self.clone();
//     let one = &AffinePoint::curve_group().elem(&1u8);
// 
//     while !&n.is_zero() {
//       if !(&n & one).is_zero() {
//         res = &res + &pt_pow_n;
//       }
//       pt_pow_n = &pt_pow_n + &pt_pow_n;
//       n >>= &one.e;
//     }
//     res
//   }
// }

impl Element {
  pub fn new(order: Integer, n: Integer) -> Element {
    Element { order, n }
  }
}

pub struct AdditiveGroup {
  order: Integer,
}

impl AdditiveGroup {
  pub fn new(order: &Integer) -> AdditiveGroup {
    AdditiveGroup {
      order: order.clone(),
    }
  }

  pub fn element(&self, n: &Integer) -> Element {
    Element {
      order: self.order.clone(),
      n: n.clone(),
    }
  }

  // TODO implement this
  pub fn get_random_element(&self) -> Element {
    let n = Integer::from(5);
    Element {
      order: self.order.clone(),
      n
    }
  }
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test() {
    let group = AdditiveGroup::new(Integer::from(11));
    let a = group.element(Integer::from(5));
    let b = group.element(Integer::from(7));
    let c = a + b;
    assert_eq!(c.n, 1);
  } 
}

