use crate::building_block::gate_type::GateType;

type Children = (GateModel, GateModel);

pub struct GateModel {
  pub gate_type: GateType,
  pub left: Option<Box<GateModel>>,
  pub right: Option<Box<GateModel>>,
}

impl GateModel {
  pub fn and(left: Option<Box<GateModel>>, right: Option<Box<GateModel>>) -> Box<Self> {
    let model = GateModel {
      gate_type: GateType::And,
      left,
      right,
    };
    Box::new(model)
  }

  pub fn or(left: Option<Box<GateModel>>, right: Option<Box<GateModel>>) -> Box<Self> {
    let model = GateModel {
      gate_type: GateType::Or,
      left,
      right,
    };
    Box::new(model)
  }
}

