#![allow(non_snake_case)]

use crate::building_block::{
  gate_model::GateModel,
  circuit::Circuit,
  gates::Gates,
  wires::Wires,
};

pub fn run() -> () {
  /*
   Circuit:
          6|
        (2:Or)
       4/     5\
    (0:And)  (1:Or)
    0/   1\  2/  3\

   */

  ///// P1

  // 1 construct circuit
  let gate_model = GateModel::or(
    Some(GateModel::and(None, None)),
    Some(GateModel::or(None, None)),
  );

  let K = 64;
  let mut gates = Gates::new();
  let mut wires = Wires::new(K);
  let circuit = Circuit::new(&gate_model, K, &mut gates, &mut wires);
  println!("{:?}", circuit);

  // // wire table generation
  // let depth = 2;
  // let K = 64;
  // let was = WireAssignment::new(depth);
  // 
  // let mut wires: Vec<Wire> = vec![];
  // 
  // let _labels = Wire::new(K);
  
  // garbled circuit generation

  // output decoding table generation
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test1() {
    run();
  }
}
