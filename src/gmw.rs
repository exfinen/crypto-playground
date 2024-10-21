use crate::binary_wire_labels::BinaryWireLabels;
use rand::rngs::OsRng;
use crate::util::gen_random_binary_val;

fn gen_wire_labels<const K: usize>(
  num_wires: usize,
) -> Vec<BinaryWireLabels<K>> {
  let mut ws = vec![];

  for _ in 0..num_wires {
    // first randomly generate p_i^0
    let p0 = gen_random_binary_val(OsRng);

    // p1 is the complementary binary value to p0
    let p1 = !p0;

    let w = BinaryWireLabels::<K>::new(p0, p1);
    ws.push(w)
  }
  ws
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn do_something() {
    let ws = gen_wire_labels::<4>(2);

    println!("{:?}", ws[0]);
  }
}
