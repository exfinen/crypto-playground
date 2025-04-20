use rug::Integer;

pub fn secp256k1_group_order() -> Integer {
  Integer::from_str_radix(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
  ).unwrap()
}

