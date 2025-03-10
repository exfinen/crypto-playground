#![allow(dead_code)]

use crate::building_block::{
  wire_label::WireLabel,
  util::gen_random_binary_val,
};

// A Wire consists of two WireLabels

#[derive(Debug)]
pub struct Wire {
  pub index: usize,
  labels: [WireLabel; 2],
}

impl Wire {
  pub fn new(k: usize, index: usize) -> Self {
    let p = gen_random_binary_val();  
    Wire {
      index,
      labels: [
        WireLabel::new(index, false, p, k),
        WireLabel::new(index, true, !p, k),
      ]
    }
  }

  pub fn get_label(&self, b: bool) -> &WireLabel {
    &self.labels[if b { 1 } else { 0 }]
  }
}

