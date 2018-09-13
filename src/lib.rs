extern crate base32;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate ring;
extern crate byteorder;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    totp: std::collections::HashMap<String, TotpOptions>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TotpOptions {
    secret: String,
}

fn make_config_dir(config_dir: &std::path::PathBuf) -> std::io::Result<()> {
    println!("creating config dir: {:?}", config_dir);
    std::fs::create_dir_all(config_dir)
}

pub fn add_secret(mut config: Config, config_dir: std::path::PathBuf, name: String, secret: String) -> Result<(), std::io::Error> {

    match std::fs::metadata(&config_dir) {
        Err(_)  => make_config_dir(&config_dir)?,
        Ok(ref md) if !md.is_dir() => make_config_dir(&config_dir)?,
        Ok(_) => ()
    }

    base32::decode(base32::Alphabet::RFC4648 { padding: false }, &secret)
        .expect("Invalid base32 OTP secret");

    config.totp.insert(name, TotpOptions { secret });
    let string = toml::to_string(&config).unwrap();
    std::fs::write(config_dir.join("config.toml"), string)
}

pub fn load_config(config_dir: &std::path::PathBuf) -> Result<Config, std::io::Error> {
    let config_path = config_dir.join("config.toml");

    let meta_data = match std::fs::metadata(&config_path) {
        Ok(md) => md,
        Err(_e) => return Ok(Config { totp: std::collections::HashMap::new() })
    };

    let config: Config = match meta_data.is_file() {
        true => {
            let config = std::fs::read_to_string(config_path)?;

            toml::from_str(&config).unwrap()
        }
        false => Config { totp: std::collections::HashMap::new() }
    };
    Ok(config)
}

use std::time::{Duration, SystemTime};

pub fn generate_totp(config: Config, name: String) -> String {
    let totp_settings = config.totp.get(&name)
        .expect(&format!("a TOTP config named `{}` was not found, did you add a secret with that name?", name));

    let time = SystemTime::now();
    let seconds: Duration = time.duration_since(SystemTime::UNIX_EPOCH)
        .expect("Can't get time since EPOCH?");

    let secret = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &totp_settings.secret);
    let secret = secret.expect("Invalid base32 secret");

    totp(&secret, seconds, Duration::from_secs(30), 6)
}

pub fn totp(secret: &[u8], time: Duration, time_window: Duration, length: usize) -> String {
    use ring::hmac::{sign, SigningKey};
    use byteorder::{ByteOrder, BigEndian};

    let mut buf: [u8; 8] = [0; 8];
    BigEndian::write_u64(&mut buf, time.as_secs() / time_window.as_secs());

    let signing_key = SigningKey::new(&ring::digest::SHA1, secret);

    let signature = sign(&signing_key, &buf);

    let value: &[u8] = signature.as_ref();

    let digits_power: [u32; 9] = [
        1u32, // 0
        10u32, // 1
        100u32, // 2
        1000u32, // 3
        10000u32, // 4
        100000u32, // 5
        1000000u32, // 6
        10000000u32, // 7
        100000000u32, // 8
    ];

    let modulus: u32 = digits_power[length];

    let code: u32 = truncate(value) % modulus;

    // zero pad using format fills
    // https://doc.rust-lang.org/std/fmt/#fillalignment
    // https://doc.rust-lang.org/std/fmt/#width
    format!("{:0>width$}", code, width = length)
}

fn truncate(signature: &[u8]) -> u32 {
    let offset: usize = (signature[signature.len() - 1] & 0xF).into();
    let bytes = &signature[offset..offset + std::mem::size_of::<u32>()];

    let high = bytes[0] as u32;
    let high_num = (high & 0x7F) << 24;

    let mid = bytes[1] as u32;
    let mid_num = mid << 16;

    let lower = bytes[2] as u32;
    let lower_num = lower << 8;

    let bottom = bytes[3] as u32;

    let result = high_num | mid_num | lower_num | bottom;

    result
}

#[cfg(test)]
#[test]
fn verify() {
    let standard_time_window = Duration::from_secs(30);

    // test vectors from the RFC
    // https://tools.ietf.org/html/rfc6238#appendix-B
    let code = totp(b"12345678901234567890", Duration::from_secs(59), standard_time_window, 8);
    assert_eq!(code, "94287082");

    let code = totp(b"12345678901234567890", Duration::from_secs(1111111109), standard_time_window, 8);
    assert_eq!(code, "07081804");

    let code = totp(b"12345678901234567890", Duration::from_secs(1234567890), standard_time_window, 8);
    assert_eq!(code, "89005924");
}