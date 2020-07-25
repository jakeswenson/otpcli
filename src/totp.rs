use std::time::{Duration, SystemTime};

use crypto::digest::Digest;
pub use crypto::sha1::Sha1;

use super::config::Config;
use super::secrets;
use crate::{TotpError, TotpResult};

static ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

pub fn standard_totp(config: Config, name: &str) -> TotpResult<String> {
    let totp_settings = config
        .totp
        .get(name)
        .ok_or(TotpError("Can't find the specified config"))?;
    let secret = secrets::get_secret(name, &totp_settings)?;

    generate_code(secret)
}

pub fn generate_code(secret: String) -> TotpResult<String> {
    let now = SystemTime::now();
    let seconds: Duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Can't get time since UNIX_EPOCH?");

    let secret = base32::decode(ALPHABET, &secret)
        .ok_or(TotpError("Failed to decode secret from base32"))?;

    totp(&secret, seconds, Duration::from_secs(30), 6, Sha1::new())
}

const DIGITS_MODULUS: [u32; 9] = [
    1u32,           // 0
    10u32,          // 1
    100u32,         // 2
    1000u32,        // 3
    10_000u32,      // 4
    100_000u32,     // 5
    1_000_000u32,   // 6
    10_000_000u32,  // 7
    100_000_000u32, // 8
];

pub fn totp<D: Digest>(
    secret: &[u8],
    time_since_epoch: Duration,
    time_window: Duration,
    length: usize,
    algo: D,
) -> TotpResult<String> {
    use byteorder::{BigEndian, ByteOrder};
    use crypto::{hmac::Hmac, mac::Mac};

    let mut buf: [u8; 8] = [0; 8];
    BigEndian::write_u64(&mut buf, time_since_epoch.as_secs() / time_window.as_secs());

    let mut hmac1 = Hmac::new(algo, secret);
    hmac1.input(&buf);
    let mac_result = hmac1.result();
    let signature = mac_result.code();

    let modulus: u32 = DIGITS_MODULUS[length];

    let code: u32 = truncate(signature) % modulus;

    // zero pad using format fills
    // https://doc.rust-lang.org/std/fmt/#fillalignment
    // https://doc.rust-lang.org/std/fmt/#width
    Ok(format!("{:0>width$}", code, width = length))
}

fn truncate(signature: &[u8]) -> u32 {
    let offset: usize = (signature[signature.len() - 1] & 0xF).into();
    let bytes = &signature[offset..offset + std::mem::size_of::<u32>()];

    let high = u32::from(bytes[0]);
    let high_num = (high & 0x7F) << 24;

    let mid = u32::from(bytes[1]);
    let mid_num = mid << 16;

    let lower = u32::from(bytes[2]);
    let lower_num = lower << 8;

    let bottom = u32::from(bytes[3]);

    high_num | mid_num | lower_num | bottom
}

#[cfg(test)]
#[test]
fn verify() -> TotpResult<()> {
    let standard_time_window = Duration::from_secs(30);

    // test vectors from the RFC
    // https://tools.ietf.org/html/rfc6238#appendix-B
    let code = totp(
        b"12345678901234567890",
        Duration::from_secs(59),
        standard_time_window,
        8,
        Sha1::new(),
    )?;
    assert_eq!(code, "94287082");

    let code = totp(
        b"12345678901234567890",
        Duration::from_secs(1_111_111_109),
        standard_time_window,
        8,
        Sha1::new(),
    )?;
    assert_eq!(code, "07081804");

    let code = totp(
        b"12345678901234567890",
        Duration::from_secs(1_234_567_890),
        standard_time_window,
        8,
        Sha1::new(),
    )?;
    assert_eq!(code, "89005924");

    Ok(())
}
