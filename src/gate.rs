#[derive(Debug)]
pub struct Gate {
  pub id: usize,
  pub left_wire: usize,
  pub right_wire: usize,
  pub out_wire: usize,
}

impl Gate {
  pub fn new(
    id: usize,
    left_wire: usize,
    right_wire: usize,
    out_wire: usize,
  ) -> Self {
    Gate {
      id,
      left_wire,
      right_wire,
      out_wire,
    }
  }
}

