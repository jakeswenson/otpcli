//! OTP — a one time password code generator library
use config::Config;

pub mod config;
mod secrets;
pub mod totp;

#[cfg(feature = "rsa_stoken")]
use crate::config::TotpOptions;
#[cfg(feature = "rsa_stoken")]
use stoken::{self, chrono::Utc};

use crate::totp::TokenAlgorithm;
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
        TotpError(msg)
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

#[cfg(feature = "rsa_stoken")]
fn stoken(name: &str, options: &TotpOptions) -> TotpResult<String> {
    let token = stoken::export::import(secrets::get_secret(name, options)?.to_string())
        .ok_or(TotpError("Unable to import secret as an RSA stoken secret"))?;
    Ok(stoken::generate(token, Utc::now()))
}

pub fn token(name: &str, config: Config) -> TotpResult<String> {
    let options = config.lookup(name)?;

    match config.lookup(name)?.algorithm() {
        TokenAlgorithm::TotpSha1 => totp::standard_totp(name, options),
        #[cfg(feature = "rsa_stoken")]
        TokenAlgorithm::SToken => stoken(name, options),
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

#[cfg(feature = "ras_stoken")]
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
    let totp_options = secrets::store_secret(&name, &secret, algorithm)?;
    let mut config: Config = config.clone();
    config.insert(name.to_string(), totp_options);
    let string = toml::to_string(&config)?;

    config::ensure_config_dir(&config_dir)?;

    std::fs::write(config_dir.as_ref().join("config.toml"), string)?;
    Ok(config)
}

pub fn list_secrets(config: Config, _prefix: Option<String>) -> TotpResult<Vec<String>> {
    Ok(Vec::from_iter(config.codes().keys().cloned()))
}

pub fn delete_secret<P: AsRef<Path>>(
    mut config: Config,
    config_dir: P,
    name: String,
) -> TotpResult<()> {
    config.remove(&name);
    let string = toml::to_string(&config).expect("unable to write config to TOML");
    config::ensure_config_dir(&config_dir)?;
    std::fs::write(config_dir.as_ref().join("config.toml"), string)?;
    Ok(())
}

#[cfg(feature = "keychain")]
pub fn migrate_secrets_to_keychain<P: AsRef<Path>>(
    config: Config,
    config_dir: P,
) -> TotpResult<Config> {
    let mut new_codes = config.clone();
    for (name, value) in config.codes().iter() {
        println!("Migrating {}", name);
        let secret = secrets::get_secret(name, value)?;
        new_codes = add_secret(
            &new_codes,
            config_dir.as_ref(),
            name,
            secret,
            value.algorithm(),
        )?;
    }

    Ok(new_codes)
}
