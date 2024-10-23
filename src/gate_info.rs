#[derive(Debug)]
pub struct GateInfo {
  pub id: usize,
  pub left_wire: usize,
  pub right_wire: usize,
  pub out_wire: usize,
}

impl GateInfo {
  pub fn new(
    id: usize,
    left_wire: usize,
    right_wire: usize,
    out_wire: usize,
  ) -> Self {
    GateInfo {
      id,
      left_wire,
      right_wire,
      out_wire,
    }
  }
}

