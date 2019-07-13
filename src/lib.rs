use serde::{self, Deserialize, Serialize};
use stoken::{self, chrono::Utc};

use config::{Config, TotpOptions};

pub mod config;
mod secrets;
pub mod totp;

use std::iter::FromIterator;
use std::path::Path;
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    result::Result,
};

#[derive(Debug)]
pub struct TotpError<'a>(&'a str);

impl<'a> Display for TotpError<'a> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl<'a> Error for TotpError<'a> {}

impl<'a> TotpError<'a> {
    pub fn of(msg: &'a str) -> Self {
        return TotpError(msg);
    }
}

#[derive(Debug)]
pub struct TotpConfigError(String);

impl Display for TotpConfigError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl Error for TotpConfigError {}

pub type TotpResult<T> = Result<T, Box<dyn Error>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TokenAlgorithm {
    #[serde(rename = "sha1")]
    TotpSha1,
    #[serde(rename = "stoken")]
    SToken,
}

impl Copy for TokenAlgorithm {}

fn stoken(config: &Config, name: &str) -> TotpResult<String> {
    let value = config.lookup(name)?;
    let token = stoken::export::import(secrets::get_secret(name, value)?.to_string())
        .ok_or(TotpError("Unable to import secret as an RSA stoken secret"))?;
    Ok(stoken::generate(token, Utc::now()))
}

pub fn token(config: Config, name: &str) -> TotpResult<String> {
    match config.lookup(name)?.algorithm() {
        TokenAlgorithm::TotpSha1 => totp::standard_totp(config, name),
        TokenAlgorithm::SToken => stoken(&config, name),
    }
}

pub fn add_totp_secret<P: AsRef<Path>>(
    config: Config,
    config_dir: P,
    name: &str,
    secret: String,
) -> TotpResult<()> {
    base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret)
        .expect("Invalid base32 OTP secret");

    add_secret(&config, config_dir, name, secret, TokenAlgorithm::TotpSha1).map(|_| ())
}

pub fn add_stoken<P: AsRef<Path>>(
    config: &Config,
    config_dir: P,
    name: &str,
    rsa_token_file: P,
    pin: &str,
) -> TotpResult<()> {
    let token = stoken::read_file(rsa_token_file);
    let token = stoken::RSAToken::from_xml(token, pin);
    let exported_token = stoken::export::export(token).expect("Unable to export RSA Token");
    add_secret(
        &config,
        config_dir,
        name,
        exported_token,
        TokenAlgorithm::SToken,
    )?;

    Ok(())
}

pub fn add_secret<P: AsRef<Path>>(
    config: &Config,
    config_dir: P,
    name: &str,
    secret: String,
    algorithm: TokenAlgorithm,
) -> TotpResult<Config> {
    secrets::store_secret(&name, &secret)?;
    let mut config: Config = config.clone();
    config.totp.insert(
        name.to_string(),
        TotpOptions::new_keychain_stored_secret(algorithm),
    );
    let string = toml::to_string(&config)?;

    config::ensure_config_dir(&config_dir)?;

    std::fs::write(config_dir.as_ref().join("config.toml"), string)?;
    Ok(config)
}

pub fn list_secrets(config: Config, _prefix: Option<String>) -> TotpResult<Vec<String>> {
    Ok(Vec::from_iter(config.totp.keys().cloned()))
}

pub fn delete_secret<P: AsRef<Path>>(
    mut config: Config,
    config_dir: P,
    name: String,
) -> TotpResult<()> {
    config.totp.remove(&name);
    let string = toml::to_string(&config).expect("unable to write config to TOML");
    config::ensure_config_dir(&config_dir)?;
    std::fs::write(config_dir.as_ref().join("config.toml"), string)?;
    Ok(())
}

pub fn migrate_secrets_to_keychain<P: AsRef<Path>>(
    mut config: Config,
    config_dir: P,
) -> TotpResult<()> {
    for (name, value) in config.clone().totp.iter() {
        println!("Migrating {}", name);
        let secret = secrets::get_secret(name, value)?;
        println!("Got secret {}", secret);
        config = add_secret(
            &config,
            config_dir.as_ref(),
            name,
            secret,
            value.algorithm(),
        )?;
    }

    Ok(())
}
