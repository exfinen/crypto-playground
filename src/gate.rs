use crate::wire_label::WireLabel;

pub struct And<const K: usize> {
  a: WireLabel::<K>,
  b: WireLabel::<K>,
  out: WireLabel::<K>
}

impl<const K: usize> And<K> {
  pub fn new(
    a: WireLabel::<K>,
    b: WireLabel::<K>,
    out: WireLabel::<K>,
  ) -> Self {
    And { a, b, out }
  }
}

