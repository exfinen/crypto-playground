#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerId {
  A,
  B,
}

impl From<&SignerId> for u32 {
  fn from(signer_id: &SignerId) -> Self {
    match signer_id {
      SignerId::A => 0,
      SignerId::B => 1,
    }
  }
}

impl From<&SignerId> for usize {
  fn from(signer_id: &SignerId) -> Self {
    match signer_id {
      SignerId::A => 0,
      SignerId::B => 1,
    }
  }
}

impl SignerId {
  pub fn the_other(&self) -> Self {
    match self {
      SignerId::A => SignerId::B,
      SignerId::B => SignerId::A,
    }
  }
}

