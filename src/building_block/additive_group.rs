#![allow(dead_code)]

use rug::Integer;
use std::ops::{Add, Mul};

#[derive(Clone, Debug)]
pub struct Element {
  pub order: Integer,
  pub n: Integer,
}

impl PartialEq<Element> for Element {
  fn eq(&self, rhs: &Self) -> bool {
    self.n == rhs.n
  }
}

impl PartialEq<Element> for &Element {
  fn eq(&self, rhs: &Element) -> bool {
    self.n == rhs.n
  }
}

impl Add<Element> for Element {
  type Output = Self;

  fn add(self, rhs: Self) -> Self {
    assert_eq!(self.order, rhs.order, "Tried to add elements of different orders");
    let res = (self.n + rhs.n) % &self.order;
    Self::new(self.order.clone(), res)
  }
}

impl Add<&Element> for Element {
  type Output = Self;

  fn add(self, rhs: &Self) -> Self {
    assert_eq!(self.order, rhs.order, "Tried to add elements of different orders");
    let res: Integer = {
      let lhs: Integer = (&self.n + &rhs.n).into();
      lhs % self.order.clone()
    };
    Self::new(self.order.clone(), res)
  }
}

// Scalar multiplication
impl Mul<Element> for Element {
  type Output = Self;

  fn mul(self, rhs: Element) -> Self {
    let mut n = rhs.n.clone(); 
    let mut res = Integer::ZERO;
    let mut bit_amount = self.n.clone();

    while &n != &Integer::ZERO {
      // if the least significant bit is 1
      if (&n & Integer::from(1)) != Integer::ZERO {
        // add the amount for the current bit to res
        res += &bit_amount;
      }
      // update bit_amount to represent the next bit 
      bit_amount = bit_amount.clone() + bit_amount;
      n >>= 1;  // shift to the right to test the next bit
    }
    Element::new(self.order, res)
  }
}

impl Mul<&Integer> for Element {
  type Output = Self;

  fn mul(self, rhs: &Integer) -> Self {
    let mut n = rhs.clone(); 
    let mut res = Integer::ZERO;
    let mut bit_amount = self.n.clone();

    while &n != &Integer::ZERO {
      // if the least significant bit is 1
      if (&n & Integer::from(1)) != Integer::ZERO {
        // add the amount for the current bit to res
        res += &bit_amount;
      }
      // update bit_amount to represent the next bit 
      bit_amount = bit_amount.clone() + bit_amount;
      n >>= 1;  // shift to the right to test the next bit
    }
    Element::new(self.order, res)
  }
}

impl Mul<&Integer> for &Element {
  type Output = Element;

  fn mul(self, rhs: &Integer) -> Element {
    let mut n = rhs.clone(); 
    let mut res = Integer::ZERO;
    let mut bit_amount = self.n.clone();

    while &n != &Integer::ZERO {
      // if the least significant bit is 1
      if (&n & Integer::from(1)) != Integer::ZERO {
        // add the amount for the current bit to res
        res += &bit_amount;
      }
      // update bit_amount to represent the next bit 
      bit_amount = bit_amount.clone() + bit_amount;
      n >>= 1;  // shift to the right to test the next bit
    }
    Element::new(self.order.clone(), res)
  }
}

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
    let group = AdditiveGroup::new(&Integer::from(11));
    let a = group.element(&Integer::from(5));
    let b = group.element(&Integer::from(7));
    let c = a + b;
    assert_eq!(c.n, 1);
  } 
}

