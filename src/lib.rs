use std::io;

use serde::{self, Deserialize, Serialize};
use stoken::{self, chrono::Utc};

use self::config::{Config, TotpOptions};

pub mod config;
pub mod totp;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TokenAlgorithm {
    #[serde(rename = "sha1")]
    TotpSha1,
    #[serde(rename = "stoken")]
    SToken,
}

impl Copy for TokenAlgorithm {}

fn stoken(config: &Config, name: &str) -> Option<String> {
    let value = config.lookup(name)?;
    let token = stoken::export::import(value.secret.clone())?;
    Some(stoken::generate(token, Utc::now()))
}

pub fn token(config: Config, name: &str) -> Option<String> {
    match config.lookup(name).and_then(|n| { n.algorithm }).unwrap_or(TokenAlgorithm::TotpSha1) {
        TokenAlgorithm::TotpSha1 => totp::standard_totp(config, name),
        TokenAlgorithm::SToken => stoken(&config, name)
    }
}

pub fn add_totp_secret(config: Config, config_dir: std::path::PathBuf, name: String, secret: String) -> io::Result<()> {
    base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret)
        .expect("Invalid base32 OTP secret");

    add_secret(config, config_dir, name, secret, TokenAlgorithm::TotpSha1)
}

pub fn add_secret(
    mut config: Config,
    config_dir: std::path::PathBuf,
    name: String,
    secret: String,
    algorithm: TokenAlgorithm) -> io::Result<()> {
    config.totp.insert(name, TotpOptions { secret, algorithm: Some(algorithm) });
    let string = toml::to_string(&config).expect("unable to write config to TOML");

    config::ensure_config_dir(&config_dir)?;

    std::fs::write(config_dir.join("config.toml"), string)
}

pub fn list_secrets(config: Config, prefix: Option<String>) -> io::Result<Vec<String>> {
    use std::iter::FromIterator;
    Ok(Vec::from_iter(config.totp.keys().cloned()
        .filter(|_n| prefix.is_none())))
}

pub fn delete_secret(mut config: Config, config_dir: std::path::PathBuf, name: String) -> io::Result<()> {
    config.totp.remove(&name);
    let string = toml::to_string(&config).expect("unable to write config to TOML");
    config::ensure_config_dir(&config_dir)?;
    std::fs::write(config_dir.join("config.toml"), string)
}
