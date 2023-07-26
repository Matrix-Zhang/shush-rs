use std::{
    env,
    path::{Path, PathBuf},
    process::{exit, Command},
};

static PLAIN_TEXT: &str = "super secret";

#[test]
fn main() {
    let output = Command::new("cargo")
        .arg("install")
        .arg("--path")
        .arg(".")
        .output()
        .expect("Failed to run cargo install");

    if !output.status.success() {
        println!(
            "Failed to install shush-rs, {}",
            String::from_utf8_lossy(&output.stderr)
        );
        exit(1);
    }
    test_encrypt_and_decrypt();
}

fn test_encrypt_and_decrypt() {
    let key = env::var("SHUSH_KEY").unwrap_or_default();
    if key.is_empty() {
        println!(
            "SHUSH_KEY was not found in environment. \
        Please set this to a usable KMS key and re-run the test with appropriate AWS credentials"
        );
        exit(2);
    }

    let alias = env::var("SHUSH_ALIAS").unwrap_or_default();
    if alias.is_empty() {
        println!(
            "SHUSH_ALIAS was not found in environment. \
        Please set this to the alias of the key you specified as SHUSH_KEY and re-run the test"
        );
        exit(3);
    }

    let shush_path = Path::new(&env::var("CARGO_HOME").expect(
        "CARGO_HOME was not found in environment. \
        Please set this environment with the cargo bin path",
    ))
    .join("bin")
    .join("shush-rs")
    .to_path_buf();

    if !shush_path.exists() {
        println!("Could not find shush-rs executable");
        exit(4);
    }

    for key in [key, alias.clone(), format!("alias/{}", alias)] {
        let cipher_text = encrypt(&shush_path, &key);
        let decrypt_text = decrypt(&shush_path, &cipher_text);
        assert_eq!(decrypt_text, PLAIN_TEXT);
        verify_exec(&shush_path, &cipher_text);
        verify_key(&shush_path, &cipher_text);
    }
}

fn encrypt(shush_path: &PathBuf, key: &str) -> String {
    let output = Command::new(shush_path.to_path_buf())
        .arg("encrypt")
        .arg("--key")
        .arg(key)
        .arg(PLAIN_TEXT)
        .output()
        .expect("Failed to run shush-rs encrypt command");

    if !output.status.success() {
        println!(
            "shush-rs encrypt error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        exit(5);
    }

    String::from_utf8_lossy(&output.stdout).to_string()
}

fn decrypt(shush_path: &PathBuf, cipher_text: &str) -> String {
    let output = Command::new(shush_path.to_path_buf())
        .arg("decrypt")
        .arg(cipher_text)
        .output()
        .expect("Failed to run shush-rs decrypt command");

    if !output.status.success() {
        println!(
            "shush-rs decrypt error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        exit(6);
    }

    String::from_utf8_lossy(&output.stdout).to_string()
}

fn verify_exec(shush_path: &PathBuf, cipher_text: &str) {
    let output = Command::new(shush_path)
        .env("KMS_ENCRYPTED_SHUSH_SECRET", cipher_text)
        .arg("exec")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("env | grep SHUSH_SECRET")
        .output()
        .expect("Failed to run shush-rs exec command");

    if !output.status.success() {
        println!(
            "shush-rs exec error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        exit(7);
    }

    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("SHUSH_SECRET={PLAIN_TEXT}")
    );
}

fn verify_key(shush_path: &PathBuf, cipher_text: &str) {
    let output = Command::new(shush_path)
        .arg("decrypt")
        .arg("--print-key")
        .arg(cipher_text)
        .output()
        .expect("Failed to run shush-rs command");

    if !output.status.success() {
        println!(
            "shush-rs --print-key error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        exit(8);
    }

    assert!(String::from_utf8_lossy(&output.stdout).ends_with(&env::var("SHUSH_KEY").unwrap()));
}
