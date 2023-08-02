use std::str::FromStr;

use anyhow::{anyhow, Result};
use aws_sdk_kms::{primitives::Blob, Client};
use base64::{
    engine::general_purpose::{STANDARD as base64_std, STANDARD_NO_PAD as base64_no_padding},
    Engine,
};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Key {
    Id(Uuid),
    Arn(String),
    Alias(String),
}

impl From<String> for Key {
    fn from(value: String) -> Self {
        if value.starts_with("arn:aws:kms") {
            Key::Arn(value)
        } else if let Ok(uuid) = Uuid::from_str(&value) {
            Key::Id(uuid)
        } else if value.starts_with("alias/") {
            Key::Alias(value)
        } else {
            Key::Alias(format!("alias/{value}"))
        }
    }
}

impl From<&str> for Key {
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}

impl From<Key> for String {
    fn from(key: Key) -> Self {
        match key {
            Key::Arn(arn) => arn,
            Key::Alias(alias) => alias,
            Key::Id(uuid) => uuid.to_string(),
        }
    }
}

pub(crate) struct DecryptOutput {
    pub(crate) key_id: String,
    pub(crate) plain_text: String,
}

pub(crate) struct Kms {
    client: Client,
}

impl Kms {
    pub(crate) async fn new() -> Kms {
        Kms {
            client: Client::new(&aws_config::load_from_env().await),
        }
    }

    pub(crate) async fn encrypt(&self, key: Key, plaintext: &str, no_padding: bool) -> Result<String> {
        self.client
            .encrypt()
            .key_id(key)
            .plaintext(Blob::new(plaintext.as_bytes()))
            .send()
            .await
            .map_err(Into::into)
            .and_then(|response| {
                response
                    .ciphertext_blob()
                    .ok_or_else(|| anyhow!("Could not get encrypted cipher text"))
                    .map(|blob| {
                        if no_padding {
                            base64_no_padding.encode(blob)
                        } else {
                            base64_std.encode(blob)
                        }
                    })
            })
    }

    pub(crate) async fn decrypt(&self, cipher_text: &str, no_padding: bool) -> Result<DecryptOutput> {
        self.client
            .decrypt()
            .ciphertext_blob(Blob::new(if no_padding {
                base64_no_padding.decode(cipher_text.as_bytes())?
            } else {
                base64_std.decode(cipher_text.as_bytes())?
            }))
            .send()
            .await
            .map_err(Into::into)
            .and_then(|response| {
                response
                    .plaintext()
                    .ok_or_else(|| anyhow!("Could not to get decrypted plain text"))
                    .map(|blob| DecryptOutput {
                        key_id: response
                            .key_id()
                            .map(ToString::to_string)
                            .unwrap_or_default(),
                        plain_text: String::from_utf8_lossy(blob.as_ref()).to_string(),
                    })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_from_uuid_should_success() {
        let uuid = Uuid::new_v4();
        let key = Key::from(uuid.to_string());
        assert_eq!(Key::Id(uuid), key);
    }

    #[test]
    fn key_from_arn_should_success() {
        let arn = format!(
            "arn:aws:kms:ap-southeast-1:874322187757:key/{}",
            Uuid::new_v4(),
        );
        let key = Key::from(arn.clone());
        assert_eq!(Key::Arn(arn), key);
    }

    #[test]
    fn key_from_alias_should_be_alias() {
        let key = Key::from("alias/key");
        assert_eq!(Key::Alias(String::from("alias/key")), key);
    }

    #[test]
    fn key_from_others_should_be_alias() {
        let key = Key::from("key");
        assert_eq!(Key::Alias(String::from("alias/key")), key);
    }
}
