#![allow(dead_code)]

use rug::{Complete, Integer};
use std::ops::{Add, Mul};

#[derive(Clone, Debug)]
pub struct Element {
  order: Integer,
  value: Integer,
}

impl PartialEq<Element> for Element {
  fn eq(&self, rhs: &Self) -> bool {
    self.value == rhs.value
  }
}

impl PartialEq<Element> for &Element {
  fn eq(&self, rhs: &Element) -> bool {
    self.value() == rhs.value()
  }
}

impl Add<Element> for Element {
  type Output = Self;

  fn add(self, rhs: Self) -> Self {
    self.assert_same_order(&rhs);
    let res = (self.value_ref() + rhs.value_ref()).complete();
    let res = res % &self.order;
    Self::new(self.order_ref(), &res)
  }
}

impl Add<&Element> for Element {
  type Output = Self;

  fn add(self, rhs: &Self) -> Self {
    self.assert_same_order(&rhs);
    let res = (self.value_ref() + rhs.value_ref()).complete();
    let res = res % &self.order;
    Self::new(self.order_ref(), &res)
  }
}

// Scalar multiplication
impl Mul<Element> for Element {
  type Output = Self;

  fn mul(self, rhs: Element) -> Self {
    let mut n = rhs.value(); 
    let mut res = Integer::ZERO;
    let mut bit_amount = self.value();

    while &n != &Integer::ZERO {
      // if the least significant bit is 1
      let lsb = (&n & Integer::ONE).complete();
      if &lsb == Integer::ONE {
        // add the amount for the current bit to res
        res += &bit_amount;
      }
      // update bit_amount to represent the next bit 
      bit_amount = (&bit_amount + &bit_amount).complete();
      n >>= 1;  // shift to the right to test the next bit
    }
    Element::new(&self.order, &res)
  }
}

impl Mul<&Integer> for Element {
  type Output = Self;

  fn mul(self, rhs: &Integer) -> Self {
    let mut n = rhs.clone(); 
    let mut res = Integer::ZERO;
    let mut bit_amount = self.value();

    while &n != &Integer::ZERO {
      // if the least significant bit is 1
      let lsb = (&n & Integer::ONE).complete();
      if lsb != Integer::ZERO {
        // add the amount for the current bit to res
        res += &bit_amount;
      }
      // update bit_amount to represent the next bit 
      bit_amount = (&bit_amount + &bit_amount).complete();
      n >>= 1;  // shift to the right to test the next bit
    }
    Element::new(&self.order, &res)
  }
}

impl Mul<&Integer> for &Element {
  type Output = Element;

  fn mul(self, rhs: &Integer) -> Element {
    let mut n = rhs.clone(); 
    let mut res = Integer::ZERO;
    let mut bit_amount = self.value();

    while &n != &Integer::ZERO {
      // if the least significant bit is 1
      let lsb = (&n & Integer::ONE).complete();
      if lsb != Integer::ZERO {
        // add the amount for the current bit to res
        res += &bit_amount;
      }
      // update bit_amount to represent the next bit 
      bit_amount = (&bit_amount + &bit_amount).complete();
      n >>= 1;  // shift to the right to test the next bit
    }
    Element::new(&self.order, &res)
  }
}

impl Element {
  pub fn new(order: &Integer, value: &Integer) -> Element {
    Element {
      order: order.clone(),
      value: value.clone(),
    }
  }

  pub fn value_ref(&self) -> &Integer {
    &self.value
  }

  pub fn value(&self) -> Integer {
    self.value.clone()
  }

  pub fn order_ref(&self) -> &Integer {
    &self.order
  }

  pub fn assert_same_order(&self, rhs: &Element) {
    assert_eq!(&self.order, &rhs.order, "Orders differ");
  }

  pub fn assert_order(&self, rhs: &Integer) {
    assert_eq!(&self.order, rhs, "The order and {:?} differ", rhs);
  }
}

#[derive(Clone, Debug)]
pub struct AdditiveGroup {
  order: Integer,
}

impl AdditiveGroup {
  pub fn new(order: &Integer) -> AdditiveGroup {
    AdditiveGroup {
      order: order.clone(),
    }
  }

  pub fn element(&self, value: &Integer) -> Element {
    Element {
      order: self.order.clone(),
      value: value.clone(),
    }
  }

  pub fn get_random_element(&self) -> Element {
    use rug::rand::RandState;
    let mut rand = RandState::new();
    let bits = self.order.significant_bits();
    let value = Integer::random_bits(bits, &mut rand).into();
    Element {
      order: self.order.clone(),
      value
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
    assert_eq!(c.value, 1);
  } 
}

