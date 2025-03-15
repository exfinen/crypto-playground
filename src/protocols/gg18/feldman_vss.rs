#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::building_block::secp256k1::{
  scalar::Scalar,
  jacobian_point::JacobianPoint as Point,
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
    let i = Scalar::from(i);
    let mut x = i.clone();
    let mut res = self.coeffs[0];
    
    for coeff in &self.coeffs[1..] {
      res += coeff * x;
      x *= i;
    }
    res
  }

  // returns g^coeff from x^0 to x^degree
  pub fn calc_coeff_hidings(&self) -> Vec<Point> {
    self.coeffs.iter()
      .map(|coeff| Point::from(coeff))
      .collect::<Vec<_>>()
  }

  pub fn eval_P_at_i_with_coeff_hidings(
    i: usize,
    coeff_hidings: &Vec<Point>,
  ) -> Point {
    let mut x = Scalar::from(i);
    let i = Scalar::from(i);
    let mut res = coeff_hidings[0].clone(); 

    for coeff_hiding in &coeff_hidings[1..] {
      res += coeff_hiding * x;
      x *= i;
    }
    res
  }

  // k = threshold
  // lambda_i(x) = prod j=1->k, j!=i (x - x_j) / (x_i - x_j) 
  pub fn calc_lagrange_basis_polynomial(
    xs: &Vec<&Scalar>,
    i: usize,
    target: &Scalar, // interpolation target x
  ) -> Scalar {
    let mut prod = 1u8.into();

    for (curr_i, x_j) in xs.iter().enumerate() {
      if curr_i == i {
        continue;
      }
      let num = target + x_j.neg();
      let deno = xs[i] + x_j.neg();
      prod *= num * deno.inv();
    }
    prod
  }

  // f(x) = sum i=1->k y_i * lambda_i(x)
  pub fn recover_secret(
    &self,
    shares: Vec<(Scalar, Scalar)>,
  ) -> Result<Scalar,String> {
    if shares.len() < self.coeffs.len() {
      return Err(
        format!("{} or more shares are required", self.coeffs.len()));
    }
    let shares = &shares[..self.coeffs.len()];
    let mut secret = Scalar::zero();

    let xs = shares.iter().map(|(x, _)| x).collect::<Vec<_>>();
    let target = Scalar::zero();

    for (i, (_, y)) in shares.iter().enumerate() {
      let lambda = Self::calc_lagrange_basis_polynomial(
        &xs,
        i,
        &target,
      );
      secret += y * lambda
    }
    Ok(secret)
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
    let secret = Scalar::from(7u8);
    let threshold = 2;
    let vss = FeldmanVss::new(&secret, threshold);
    assert_eq!(vss.coeffs.len(), 2);
    assert_eq!(vss.coeffs[0], secret);
  }

  #[test]
  fn test_secret_recovery() {
    for threshold in 2..=100 {
      let secret = Scalar::rand();
      let vss = FeldmanVss::new(&secret, threshold);

      let shares: Vec<(Scalar, Scalar)> = (1..=(threshold + 1))
        .map(|i| (Scalar::from(i as u8), vss.eval_P_at_i(i)))
        .collect();
      let rec_secret = vss.recover_secret(shares).unwrap();
      assert_eq!(secret, rec_secret);
    }
  }

  #[test]
  fn test_eval_at_i() {
    let vss = FeldmanVss {
      // P = 3x + 5
      coeffs: vec![
        5u8.into(),
        3u8.into(),
      ],
    };
    assert_eq!(vss.eval_P_at_i(1), 8u8.into());
    assert_eq!(vss.eval_P_at_i(2), 11u8.into());
    assert_eq!(vss.eval_P_at_i(3), 14u8.into());
  }

  #[test]
  fn test_verify_shares() {
    let secret = Scalar::rand();
    let num_shares = 100;
    let threshold = num_shares - 1;
    let vss = FeldmanVss::new(&secret, threshold);

    let coeff_hidings = vss.calc_coeff_hidings();

    // verify that all parties received a valid share
    for i in 1..=num_shares {
      println!("Verifying share {}", i);
      let P = Point::from(vss.eval_P_at_i(i));
      let P_recovered =
        FeldmanVss::eval_P_at_i_with_coeff_hidings(i, &coeff_hidings);
      assert_eq!(P, P_recovered);
    }
  }
}
