#[derive(Debug, Clone)]
pub enum GateType {
  And,
  Or,
}

impl GateType {
  pub fn func(gate_type: &GateType) -> Box<dyn Fn(bool, bool) -> bool> {
    match gate_type {
      GateType::And => Box::new(|a, b| a && b),
      GateType::Or => Box::new(|a, b| a || b),
    }
  }
}

