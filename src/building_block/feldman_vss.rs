#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::secp256k1::{
  scalar::Scalar,
  point::Point,
};
use std::fmt;

pub struct FeldmanVss {
  coeffs: Vec<Scalar>, // polynomial coeffs from x^0 to x^degree
}

impl FeldmanVss {
  // - # of shares > threshold
  // - degree = threshold - 1
  pub fn new(secret: &Scalar, threshold: usize) -> Self {
    if threshold < 2 {
      panic!("Threshold must be at least 2");
    }

    // generate random polynomial
    let degree = threshold - 1;

    let mut coeffs = vec![secret.clone()];
    for _ in 1..=degree {
      let c = Scalar::rand();
      coeffs.push(c);
    }
    Self {
      coeffs,
    }
  }

  pub fn eval_P_at_i(&self, i: usize) -> Scalar {
    let mut x = Scalar::from(i);
    let mut res = self.coeffs[0];
    
    for coeff in &self.coeffs[1..] {
      res += *coeff * x;
      x *= x;
    }
    res
  }

  // returns g^coeff from x^0 to x^degree
  pub fn calc_coeff_hidings(&self) -> Vec<Point> {
    self.coeffs.iter()
      .map(|coeff| Point::from(*coeff))
      .collect::<Vec<_>>()
  }

  pub fn eval_P_at_i_with_coeff_hidings(
    i: usize,
    coeff_hidings: &Vec<Point>,
  ) -> Point {
    let mut x = Scalar::from(i);
    let mut res = coeff_hidings[0].clone(); 

    for coeff_hiding in &coeff_hidings[1..] {
      res += *coeff_hiding * x;
      x *= x;
    }
    res
  }
}

impl fmt::Debug for FeldmanVss {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let coeffs: Vec<(u64, usize)> =
      self.coeffs.iter().rev().map(|x| (*x).into()).zip(0..).collect();

    let mut s = String::new();
    for (coeff, i) in coeffs.iter() {
      if i > &0 {
        s += "+";
      }
      let power = coeffs.len() - 1 - i;
      let term = match power {
        0 => "".to_string(),
        1 => "x".to_string(),
        _ => format!("x^{:?}", power)
      };
      s += &format!("{}{}", *coeff, term);
    }
    write!(f, "FeldmanVss({})", s)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_new() {
    let secret = Scalar::from(7u32);
    let threshold = 2;
    let vss = FeldmanVss::new(&secret, threshold);
    assert_eq!(vss.coeffs.len(), 2);
    assert_eq!(vss.coeffs[0], secret);
    assert_eq!(vss.coeffs[1], Scalar::from(3u32));
  }

  #[test]
  fn test_eval_at_i() {
    let vss = FeldmanVss {
      // P = 3x + 5
      coeffs: vec![
        Scalar::from(5u32),
        Scalar::from(3u32),
      ],
    };
    assert_eq!(vss.eval_P_at_i(1), Scalar::from(8u32));
    assert_eq!(vss.eval_P_at_i(2), Scalar::from(11u32));
    assert_eq!(vss.eval_P_at_i(3), Scalar::from(14u32));
  }

  #[test]
  fn test_verify() {
    let secret = Scalar::rand();
    let num_shares = 100;
    let threshold = num_shares - 1;
    let vss = FeldmanVss::new(&secret, threshold);

    let coeff_hidings = vss.calc_coeff_hidings();

    // verify that all parties received a valid share
    for i in 1..=num_shares {
      let P = Point::from(vss.eval_P_at_i(i));
      let P_recovered =
        FeldmanVss::eval_P_at_i_with_coeff_hidings(i, &coeff_hidings);
      assert_eq!(P, P_recovered);
    }
  }
}
