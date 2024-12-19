/*
use crate::gate::Gate;
use crate::util::{gen_random_binary_val, get_num_wires, get_num_wires};
use crate::wire_label::WireLabel;

use sha3::{Sha3_256, Digest};

pub fn gen_wire_labels<const K: usize>(
  num_wires: usize,
) -> Vec<[WireLabel<K>; 2]> {
  let mut ws = vec![];

  for id in 0..num_wires {
    // p1 is the complementary binary value to p0
    let p0 = gen_random_binary_val();
    let p1 = !p0;

    ws.push([
      WireLabel::new(id, p0),
      WireLabel::new(id, p1),
    ]);
  }
  ws
}

fn k_to_vector(k: &[bool]) -> Vec<u8> {
  let mut vec = vec![];
  for b in k {
    vec.push(if *b { 1 } else { 0 });
  }
  return vec;
}

fn xor_vecs(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
  let v1_len = v1.len();
  let v2_len = v2.len();

  let mut v1 = v1.clone();
  let mut v2 = v2.clone();

  // Pad the shorter vector with zeros at the front
  if v1_len < v2_len {
    let padding = vec![0; v2_len - v1_len];
    v1.splice(0..0, padding);
  } else if v1_len > v2_len {
    let padding = vec![0; v1_len - v2_len];
    v2.splice(0..0, padding);
  }

  v1.iter()
    .zip(v2.iter())
    .map(|(a, b)| a ^ b)
    .collect()
}

pub fn construct_garbled_table<const K: usize>(
  a_id: usize,  // left input
  b_id: usize,  // right input
  c_id: usize,  // output
  i: usize,  // gate id
  wire_labels: &Vec<[WireLabel<K>; 2]>, // K=security parameter. 
                                        // 2 comes from w_i^0 and w_i^1
                                        // where 0 and 1 stand for false and true
                                        // respectively
  op: impl Fn(bool, bool) -> bool,
) -> [Vec<u8>; 4] {
  let mut table: [Vec<u8>; 4] = [
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ];

  // for all combination of v_a and v_b
  for v_a in [false, true] {
    for v_b in [false, true] {
      // get labels w_a^v_a and w_b^v_b
      let a_label = &wire_labels[a_id][v_a as usize];
      let b_label = &wire_labels[b_id][v_b as usize];

      // compute the hash for op(v_a, b_b)
      let mut hasher = Sha3_256::new();
      hasher.update(k_to_vector(&a_label.k));
      hasher.update(k_to_vector(&b_label.k));
      hasher.update(i.to_be_bytes());
      let hash: Vec<u8> = hasher.finalize().to_vec();

      // compute e_{v_a, v_b}
      let gate_value = op(v_a, v_b);
      let c_label = &wire_labels[c_id][gate_value as usize];
      let c_k_vec = k_to_vector(&c_label.k); 
      let e = xor_vecs(&hash, &c_k_vec);

      // determine the index to store the e value
      let p_a = a_label.p as usize;
      let p_b = b_label.p as usize;
      let index: usize = (p_a << 1) | p_b;

      // store e to the table so taht es are sorted based on p_a and p_b
      table[index] = e;
    }
  }
  table
}

pub fn build_gates(depth: usize) -> Vec<Gate> {
  let num_nodes = get_num_nodes(depth);

  let mut assignments = vec![];

  let mut wire_id = 0;
  let mut curr_depth = depth;
  let mut input_wire_left = 1 << curr_depth;
  let mut out_wire_id = input_wire_left;

  for gate_id in 0..num_nodes {
    let assignment = Gate::new(
      gate_id,
      wire_id,
      wire_id + 1,
      out_wire_id,
    );
    assignments.push(assignment);

    wire_id += 2;
    input_wire_left -= 2;
    out_wire_id += 1;

    if input_wire_left == 0 {
      curr_depth -= 1;
      if curr_depth == 0 {
        break;
      }
      input_wire_left = 1 << curr_depth;
      out_wire_id = wire_id + input_wire_left;
    }
  }
  assignments
}

// e_v = H(k_i^v || "out" || j) xor v
fn calc_e_v<const K: usize>(k: &[bool; K], j: usize, v: bool) -> bool {
  let mut hasher = Sha3_256::new();

  hasher.update(k_to_vector(k));
  hasher.update("out");
  hasher.update(&j.to_be_bytes());

  let hash: Vec<u8> = hasher.finalize().to_vec();
  let lsb = hash[hash.len() - 1]; 
  let lhs = if lsb % 2 == 1 { true } else { false };

  lhs ^ v
}

// construct decoding table for each gate
pub fn construct_decoding_tables<const K: usize>(
  gates: &Vec<Gate>,
  wire_labels: &Vec<[WireLabel::<K>;2]>,
) -> Vec<[bool; 2]> {
  let mut dec_tables: Vec<[bool; 2]> = vec![];

  for j in 0..gates.len() {
    let gate = &gates[j];
    let out_wire_label = &wire_labels[gate.out_wire];
    // out_wire_label[0] is for v=0 (false)
    // out_wire_label[1] is for v=1 (true)

    let mut e = [false; 2];
    e[0] = calc_e_v(&out_wire_label[0].k, j, false);
    e[1] = calc_e_v(&out_wire_label[1].k, j, true);

    let mut sorted_e = [false; 2];

    // sort e by p value
    let e0_idx = out_wire_label[0].p as usize;
    let e1_idx = out_wire_label[1].p as usize;

    sorted_e[e0_idx] = e[0];
    sorted_e[e1_idx] = e[1];

    dec_tables.push(sorted_e);
  }
  dec_tables
}

pub fn run_protocol() -> () {
  // 1.
  // P1 plays the role of GC generator and runs the algorithm of Figure 3.1.
  // P1 then sends the obtained GC hat(C) (including the output decoding table) to P2
  //
  // 2.
  // P1 sends to P2 active wire labels for the wires of which P1 provides input.
  //
  // 3.
  // For each wire w_i on which P2 provides input, P1 and P2 execute an OT where P1
  // plays the role of the Sender, and P2 plays the role of Receiver:
  //
  // (a) P1's two input secrets are the two labels for the wire, and P2's choice-bit
  // input is its input on that wire
  //
  // (b) Upon completion of the OT, P2 receives active wire label on the wire.
  //
  // 4.
  // P2 evaluates received hat(C) gate-by-gate, starting with the active labels
  // on the input wires.
  //
  // (a) For gate G_i with garbled table T = (e_{0,0}, ..., e_{1,1}) and active input
  // labels w_a = (k_a, p_a), w_b = (k_b, p_b), P2 computes active output label
  // w_c = (k_c, p_c)
  //
  //        w_c = H(k_a || k_b || i) xor e_{p_a,p_b}
  //
  //  5.
  //  Obtaining output using decoding tables. Once all gates of hat(C) are evaluated,
  //  using "out" for the second key to decode the final output gates, P2 obtains
  //  the final output labels which are qeual to the plaintext output of the
  //  computatio. P2 sends the obtained output to P1, and they both output it.
  //
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_construct_decoding_table() {
    let depth = 2;
    let num_wires = get_num_wires(depth);
    let wire_labels = &gen_wire_labels::<10>(num_wires);
    let gws = &build_gates(depth);
    let dec_tables = construct_decoding_tables(gws, wire_labels);
    println!("{:?}", dec_tables);
  }

  // #[test]
  // fn do_something() {
  //   let num_inputs = 4;
  // 
  //   let num_wires = get_number_of_wires(num_inputs);
  //   let wire_labels = gen_wire_labels::<4>(num_wires);
  // 
  //   for gi in gen_gate_info(num_wires) {
  //     construct_garbled_table(
  //       gi.left_wire,
  //       gi.right_wire,
  //       gi.out_wire,
  //       gi.id,
  //       &wire_labels,
  //       |a,b| a && b,
  //     );
  //   }
  // }
}
*/
