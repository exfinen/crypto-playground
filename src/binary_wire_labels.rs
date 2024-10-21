use crate::wire_label::WireLabel;

#[derive(Debug)]
pub struct BinaryWireLabels<const K: usize> {
  pub wire_labels: [WireLabel<K>; 2],
}

impl<const K: usize> BinaryWireLabels<K> {
  pub fn new(p0: bool, p1: bool) -> Self {
    let zero = WireLabel::new(p0);
    let one =  WireLabel::new(p1);
    BinaryWireLabels::<K> { wire_labels: [zero, one] }
  }
}

