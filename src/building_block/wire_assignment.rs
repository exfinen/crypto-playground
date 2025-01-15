#![allow(dead_code)]

use crate::building_block::util::get_num_nodes;

#[derive(Debug)]
pub struct WireAssignment {
  pub gate_id: usize,
  pub out: usize,
  pub left: usize,
  pub right: usize,
}

impl WireAssignment {
  pub fn new(depth: usize) -> Vec<Self> {
    let num_nodes = get_num_nodes(depth);

    let mut was = vec![];

    let mut lower_wire_id = 0;
    let mut curr_depth = depth;
    let mut remaining_lower_wires = 1 << curr_depth;
    let mut upper_wire_id = remaining_lower_wires;

    for gate_id in 0..num_nodes {
      let wa = Self {
        gate_id,
        out: upper_wire_id,
        left: lower_wire_id,
        right: lower_wire_id + 1
      };
      was.push(wa);

      lower_wire_id += 2;
      remaining_lower_wires -= 2;
      upper_wire_id += 1;

      if remaining_lower_wires == 0 {
        curr_depth -= 1;
        if curr_depth == 0 {
          break;
        }
        remaining_lower_wires = 1 << curr_depth;
        upper_wire_id = lower_wire_id + remaining_lower_wires;
      }
    }
    was
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_depth_3() {
    //             | w14
    //         ____6____
    //    w12 /         \ w13
    //       4           5
    //  w8 /   \w9 w10 /   \ w11
    //    0     1     2     3
    //   / \   / \   / \   / \
    //  w0 w1 w2 w3 w4 w5 w6 w7
    //
    let depth = 3;
    let was = &WireAssignment::new(depth);
    println!("{:?}", was);

    fn f(
      was: &Vec<WireAssignment>,
      gate_id: usize,
      out: usize,
      left: usize,
      right: usize,
    ) {
      assert!(was[gate_id].out == out);
      assert!(was[gate_id].left == left);
      assert!(was[gate_id].right == right);
    }

    f(was, 0, 8, 0, 1);
    f(was, 1, 9, 2, 3);
    f(was, 2, 10, 4, 5);
    f(was, 3, 11, 6, 7);
    f(was, 4, 12, 8, 9);
    f(was, 5, 13, 10, 11);
    f(was, 6, 14, 12, 13);
  }
}

