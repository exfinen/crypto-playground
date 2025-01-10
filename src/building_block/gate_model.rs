#![allow(dead_code)]

pub enum GateModelBody {
  Values,
  Models(Box<GateModel>, Box<GateModel>),
}

pub enum GateModel {
  And(GateModelBody),
  Or(GateModelBody),
}

impl GateModel {
  pub fn int_and(
    left: Box<GateModel>,
    right: Box<GateModel>,
  ) -> Box<GateModel> {
    Box::new(
      GateModel::And(
        GateModelBody::Models(left, right)
      )
    )
  }

  pub fn leaf_and() -> Box<GateModel> {
    Box::new(
      GateModel::And(
        GateModelBody::Values
      )
    )
  }

  pub fn int_or(
    left: Box<GateModel>,
    right: Box<GateModel>,
  ) -> Box<GateModel> {
    Box::new(
      GateModel::Or(
        GateModelBody::Models(left, right)
      )
    )
  }

  pub fn leaf_or() -> Box<GateModel> {
    Box::new(
      GateModel::Or(
        GateModelBody::Values
      )
    )
  }
}

