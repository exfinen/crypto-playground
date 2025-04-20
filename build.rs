use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
  println!("cargo:rustc-env=MACOSX_DEPLOYMENT_TARGET=14.2");

  let cargo_target_dir: String =
    env::var("CARGO_TARGET_DIR")
      .unwrap_or_else(|_| "target".to_string());

  let secp256k1_path = Path::new(&cargo_target_dir).join("secp256k1-export");
  let secp256k1_dir = secp256k1_path.to_str().unwrap();

  if !secp256k1_path.exists() {
    let repo_url = "https://github.com/exfinen/secp256k1-export";
    Command::new("git")
      .args(["clone", "--depth", "1", repo_url, secp256k1_dir])
      .status()
      .expect("Failed to clone secp256k1-export repository");
  }

  let lib_dir = format!("{}/.libs/libsecp256k1.a", secp256k1_dir);
  let lib_path = Path::new(&lib_dir);
  if !lib_path.exists() {
    Command::new("sh")
      .arg("./autogen.sh")
      .current_dir(&secp256k1_dir)
      .status()
      .expect("Failed to run autogen.sh");

    Command::new("sh")
      .arg("./configure")
      .current_dir(&secp256k1_dir)
      .status()
      .expect("Failed to run configure");

    Command::new("make")
      .args(["-j", &num_cpus::get().to_string()])
      .current_dir(&secp256k1_dir)
      .status()
      .expect("Failed to build secp256k1-export");
  }

  println!("cargo:rustc-link-search=native={}/.libs", secp256k1_dir);
  println!("cargo:rustc-link-lib=static=secp256k1");
  println!("cargo:rustc-env=DYLD_LIBRARY_PATH={}/.libs", secp256k1_dir.to_string());
}

