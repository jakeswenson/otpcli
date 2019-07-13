use crate::config::{SecretLocation, TotpOptions};
use crate::{TotpError, TotpResult};
use keyring::Keyring;

pub fn get_secret(name: &str, totp_config: &TotpOptions) -> TotpResult<String> {
    let secret = totp_config.secret();
    match totp_config.storage().unwrap_or(&SecretLocation::Config) {
        SecretLocation::Config => Ok(secret
            .cloned()
            .ok_or(TotpError("Config secret but no secret"))?),
        SecretLocation::KeyChain => {
            let keyring = Keyring::new("urn:otpcli", name);
            Ok(keyring.get_password()?)
        }
    }
}

pub fn store_secret(name: &str, secret: &str) -> TotpResult<()> {
    let keyring = Keyring::new("urn:otpcli", name);

    keyring.set_password(secret)?;

    Ok(())
}
