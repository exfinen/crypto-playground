use rug::Integer;
use std::ops::Add;

pub struct Element {
  order: Integer,
  n: Integer,
}

impl Add for Element {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert_eq!(self.order, other.order, "Tried to add elements of different orders");
        let res = (self.n + other.n) % &self.order;
        Self::new(self.order.clone(), res)
    }
}

impl Element {
  pub fn new(order: Integer, n: Integer) -> Element {
    Element {
      order,
      n
    }
  }
}

pub struct AdditiveGroup {
  order: Integer,
}

impl AdditiveGroup {
  pub fn new(order: Integer) -> AdditiveGroup {
    AdditiveGroup {
      order
    }
  }

  pub fn element(&self, n: Integer) -> Element {
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
    let group = AdditiveGroup::new(Integer::from(13));
    let a = group.element(Integer::from(5));
    let b = group.element(Integer::from(7));
    let c = a + b;
    assert_eq!(c.n, 2);
  } 
}

