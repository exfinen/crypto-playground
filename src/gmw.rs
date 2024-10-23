use crate::util::gen_random_binary_val;
use crate::wire_label::WireLabel;
use crate::gate_info::GateInfo;
use sha3::{Sha3_256, Digest};

fn gen_wire_labels<const K: usize>(
  num_wires: usize,
) -> Vec<[WireLabel<K>; 2]> {
  let mut ws = vec![];

  for _ in 0..num_wires {
    // p1 is the complementary binary value to p0
    let p0 = gen_random_binary_val();
    let p1 = !p0;

    ws.push([
      WireLabel::new(p0),
      WireLabel::new(p1),
    ]);
  }
  ws
}

fn construct_garbled_circuit<const K: usize>(
  a_id: usize,
  b_id: usize,
  c_id: usize,  // output
  i: usize,  // gate id
  wire_labels: &Vec<[WireLabel<K>; 2]>,
  op: impl Fn(bool, bool) -> bool,
) -> Vec<[Vec<bool>; 4]> {
  let es = vec![];

  for v_a in [false, true] {
    for v_b in [false, true] {
      let a_label = wire_labels[a_id][v_a as usize];
      let b_label = wire_labels[b_id][v_b as usize];

      let mut hasher = Sha3_256::new();
      hasher.update(a_label.k);
      hasher.update(b_label.k);
      hasher.update(i);
      let hash = hasher.finalize();

      let gate_value = op(v_a, v_b);
      let c_label = wire_labels[c_id][gate_value as usize];
      let value = hash ^ c_label.serialize(); 

      let p_a = a_label.p as usize;
      let p_b = b_label.p as usize;

      // es is sorted based on p_a and p_b
      let e: [Vec<bool>; 4];
      let index: usize = (p_a << 1) | p_b;
      e[index] = value;
      es.push(e);
    }
  }
  es
}

// number of wires of a balanced binary tree with num_inputs leaves
fn get_number_of_wires(num_inputs: usize) -> usize {
  (1 << (num_inputs.ilog2() + 1)) - 1
}

fn gen_gate_info(num_wires: usize) -> Vec<GateInfo> {
  let mut assignments = vec![];

  let mut id = 0;
  let mut left = 0;
  let mut curr_depth = num_wires.ilog2();
  let mut out = 1 << (curr_depth - 1);
  let mut out_beg = out;

  loop {
    let assignment = GateInfo::new(id, left, left + 1, out);
    assignments.push(assignment);

    id += 1;
    left += 2;
    out += 1;

    if left == out_beg {
      if curr_depth == 0 {
        break;
      }
      curr_depth -= 1;
      out = 1 << (curr_depth - 1);
      out_beg = out;
    }
  }
  assignments
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_gen_gate_info() {
    let gi = gen_gate_info(2);

    println!("{:?}", gi);
  }

  #[test]
  fn do_something() {
    let num_inputs = 4;

    let num_wires = get_number_of_wires(num_inputs);
    let wire_labels = gen_wire_labels::<4>(num_wires);

    for gi in gen_gate_info(num_wires) {
      construct_garbled_circuit(
        gi.left_wire,
        gi.right_wire,
        gi.out_wire,
        gi.id,
        &wire_labels,
        |a,b| a && b,
      );
    }
  }
}
