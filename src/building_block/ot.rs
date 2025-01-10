use rsa::{
  Pkcs1v15Encrypt,
  RsaPrivateKey as PrivKey,
  RsaPublicKey as PubKey,
};
use crate::building_block::{
  wire::Wire,
  wire_label::WireLabel,
};

// public key-based semi-honest OT
pub struct OT();

pub struct OTKeys {
  pub sk: PrivKey,
  pub pk: PubKey,
  pub pk_prime: PubKey,
}

impl OT {
  pub fn gen_keys(bits: usize) -> OTKeys {
    let mut rng = rand::thread_rng();
    let sk = PrivKey::new(&mut rng, bits).expect("Failed to generate a private key");
    let pk = PubKey::from(&sk);
    let pk_prime = {
      let sk = PrivKey::new(&mut rng, bits).expect("Failed to generate a private key");
      PubKey::from(&sk)
    };
    OTKeys {
      sk,
      pk,
      pk_prime,
    }
  }

  pub fn encrypt_wire_labels(
    false_pub_key: &PubKey,
    true_pub_key: &PubKey,
    wire: &Wire,
  ) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();

    let false_wire_label = bincode::serialize(wire.get_label(false)).unwrap();
    let true_wire_label = bincode::serialize(wire.get_label(true)).unwrap();

    let enc_false_wire_label = 
      false_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &false_wire_label)
        .expect("Failed to encrypt false key");

    let enc_true_wire_label =
      true_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &true_wire_label)
        .expect("Failed to encrypt false key");

    (enc_false_wire_label, enc_true_wire_label)
  }

  pub fn decrypt(enc_wire_label: &[u8], priv_key: &PrivKey) -> Option<WireLabel> {
    match priv_key.decrypt(Pkcs1v15Encrypt, enc_wire_label) {
      Ok(wire_label) => Some(bincode::deserialize(&wire_label).unwrap()),
      Err(_) => None,
    }
  }
}

