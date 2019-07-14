use crate::config::{SecretLocation, TotpOptions};
use crate::{TokenAlgorithm, TotpError, TotpResult};
#[cfg(feature = "keychain")]
use keyring::Keyring;

pub fn get_secret(_name: &str, totp_config: &TotpOptions) -> TotpResult<String> {
    let secret = totp_config.secret();
    match totp_config.storage().unwrap_or(&SecretLocation::Config) {
        SecretLocation::Config => Ok(secret
            .cloned()
            .ok_or(TotpError("Config secret but no secret"))?),
        #[cfg(feature = "keychain")]
        SecretLocation::KeyChain => {
            let keyring = Keyring::new("urn:otpcli", _name);
            Ok(keyring.get_password()?)
        }
    }
}

#[cfg(feature = "keychain")]
fn store(name: &str, secret: &str, algorithm: TokenAlgorithm) -> TotpResult<TotpOptions> {
    let keyring = Keyring::new("urn:otpcli", name);
    keyring.set_password(secret)?;
    Ok(TotpOptions::new_keychain_stored_secret(algorithm))
}

#[cfg(not(feature = "keychain"))]
fn store(_name: &str, secret: &str, algorithm: TokenAlgorithm) -> TotpResult<TotpOptions> {
    Ok(TotpOptions::new_config_stored_secret(
        secret.to_string(),
        algorithm,
    ))
}

pub fn store_secret(
    name: &str,
    secret: &str,
    algorithm: TokenAlgorithm,
) -> TotpResult<TotpOptions> {
    store(name, secret, algorithm)
}
