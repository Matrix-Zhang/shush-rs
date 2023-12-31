use std::env;

use anyhow::{anyhow, Result};
use clap::{Args, Parser};
use clap_stdin::MaybeStdin;
use tokio::process::Command;

mod kms;

use crate::kms::*;

#[derive(Parser)]
#[command(name = "shush-rs")]
#[command(bin_name = "shush-rs")]
enum ShushCli {
    Encrypt(EncryptArgs),
    Exec(ExecArgs),
    Decrypt(DecryptArgs),
}

#[derive(Args)]
#[command(about, author, long_about = None, version)]
struct EncryptArgs {
    #[arg(long, short)]
    key: Key,
    #[arg(default_value_t = false, long, short)]
    trim: bool,
    #[arg(default_value_t = false, long = "no_padding")]
    no_padding: bool,
    plain_text: MaybeStdin<String>,
}

#[derive(Args)]
#[command(about, author, long_about = None, version)]
struct ExecArgs {
    #[arg(default_value_t = false, long = "no_padding")]
    no_padding: bool,
    #[arg(default_value_t = String::from("KMS_ENCRYPTED_"), long)]
    prefix: String,
    command: String,
    args: Vec<String>,
}

#[derive(Args)]
#[command(about, author, long_about = None, version)]
struct DecryptArgs {
    #[arg(default_value_t = false, long = "no_padding")]
    no_padding: bool,
    #[arg(long = "print-key", short)]
    print_key: bool,
    cipher_text: MaybeStdin<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let shush_cli = ShushCli::parse();
    let kms = Kms::new().await;
    match shush_cli {
        ShushCli::Encrypt(encrypt) => {
            let plain_text = if encrypt.trim {
                encrypt.plain_text.trim()
            } else {
                &encrypt.plain_text
            };
            let cipher_text = kms
                .encrypt(encrypt.key, plain_text, encrypt.no_padding)
                .await?;
            print!("{cipher_text}");
        }
        ShushCli::Exec(exec) => {
            for (key, value) in env::vars() {
                if key.starts_with(&exec.prefix) && !value.is_empty() {
                    env::remove_var(&key);
                    let decrypt_output = kms
                        .decrypt(&value, exec.no_padding)
                        .await
                        .map_err(|err| anyhow!("Could not decrypt key {key}, {err}"))?;
                    env::set_var(
                        key.trim_start_matches(&exec.prefix),
                        decrypt_output.plain_text,
                    );
                }
            }

            Command::new(exec.command)
                .args(exec.args)
                .spawn()?
                .wait()
                .await?;
        }
        ShushCli::Decrypt(decrypt) => {
            let decrypt_res = kms
                .decrypt(&decrypt.cipher_text, decrypt.no_padding)
                .await?;
            if decrypt.print_key {
                print!("{}", decrypt_res.key_id);
            } else {
                print!("{}", decrypt_res.plain_text);
            }
        }
    }
    Ok(())
}
