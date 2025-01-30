use rug::Integer;
use crate::building_block::paillier::{
  GCalcMethod,
  Paillier,
};
use rand::Rng;
use rug::rand::RandState;

pub struct Alice {
}

pub struct Bob {
}

pub struct MtA {
  alice: Alice,
  bob: Bob,
}

impl MtA {
  fn gen_random_int() -> Integer {
    let mut rng = RandState::new();
    let seed = {
      use rand::thread_rng;
      let mut rng = thread_rng();
      Integer::from(rng.gen::<u128>())
    };
    rng.seed(&seed);
    Integer::from(rng.gen::<u128>())
  }

  pub fn new() -> MtA {
    // alice's secret
    let a = Integer::from(29); // in Z_n

    // bob's secret
    let b = Integer::from(13); // in Z_n

    // alice encrypts her secret
    let (pk, sk) = Paillier::new(16, GCalcMethod::Random);

    // ENC(a)
    let c_a = Paillier::encrypt(&a, &pk);

    // TODO implement this
    let _range_proof_a = 0;

    // alice sends c_a and range_proof_a to bob

    // bob calculates c_b
    let beta_prime = Self::gen_random_int() % &pk.n;

    // ENC(ab + beta')
    let c_b = {
      let c_a_times_b = Paillier::scalar_mul(&c_a, &b, &pk);
      Paillier::add(&c_a_times_b, &beta_prime, &pk)
    };
    let beta = beta_prime * -1;

    // bob sends c_b and range_proof of b and beta' to bob
    let _range_proof_b_beta_prime = 0;

    // alice decrypts c_b to get ab + beta'
    let alpha = Paillier::decrypt(&c_b, &sk, &pk);

    // now secret key is additively shared:
    // alpha + beta = ab + beta' + beta = ab = x

    MtA {
      alice: Alice {},
      bob: Bob {},
    }
  }
}

