use std::time::{Duration, SystemTime};

pub use crypto;
pub use crypto::digest::Digest;
pub use crypto::sha1::Sha1;

use crate::config::TotpOptions;
use crate::{TotpError, TotpResult};

use super::secrets;

static ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

/// RFC6238 recommended time step duration
/// See: https://tools.ietf.org/html/rfc6238#section-5.2
pub const RFC6238_RECOMMENDED_TIMESTEP: Duration = Duration::from_secs(30);

/// Runs a standard TOTP for the provided config, looking up secrets using []()
///
/// # Examples
/// ```rust
/// use otp::config::TotpOptions;
/// use otp::TokenAlgorithm;
/// use otp::totp::standard_totp;
/// let options = TotpOptions::new_config_stored_secret(
///   "A SECRET".to_string(),
///   TokenAlgorithm::TotpSha1);
///
/// let  code = standard_totp("test", &options).expect("Failed to generate a TOTP code");
///
/// assert_eq!(code.len(), 6);
///
/// const BASE_10: u32 = 10;
/// assert!(code.chars().all(|c| c.is_digit(BASE_10)))
///
/// ```
pub fn standard_totp(name: &str, options: &TotpOptions) -> TotpResult<String> {
    let secret = secrets::get_secret(name, &options)?;

    generate_sha1_code(secret)
}

/// Generate a SHA1 TOTP code
///
/// # Examples
/// ```rust
/// use otp::totp::generate_sha1_code;
/// let  code = generate_sha1_code("A BASE 32 SECRET".to_string()).expect("Failed to generate a TOTP code");
///
/// assert_eq!(code.len(), 6);
///
/// const BASE_10: u32 = 10;
/// assert!(code.chars().all(|c| c.is_digit(BASE_10)))
///
/// ```
pub fn generate_sha1_code(secret: String) -> TotpResult<String> {
    let now = SystemTime::now();
    let seconds: Duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Can't get time since UNIX_EPOCH?");

    let clean_secret = secret.replace(" ", "").to_uppercase();
    let secret = base32::decode(ALPHABET, &clean_secret)
        .ok_or(TotpError("Failed to decode secret from base32"))?;

    let algo_sha1 = Sha1::new();
    totp(&secret, seconds, RFC6238_RECOMMENDED_TIMESTEP, 6, algo_sha1)
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

/// Generate a RFC6238 TOTP code using the supplied secret, time, time step size, output length, and algorithm
///
/// # Examples
/// ```rust
/// // This SHA1 example is from the RFC: https://tools.ietf.org/html/rfc6238#appendix-B
/// use std::time::Duration;
/// use otp::totp::{Sha1, RFC6238_RECOMMENDED_TIMESTEP, totp};
/// let secret = b"12345678901234567890";
/// let time_since_epoch = Duration::from_secs(59);
/// let output_length = 8;
/// let algo = Sha1::new();
///
/// let totp_code = totp(secret, time_since_epoch, RFC6238_RECOMMENDED_TIMESTEP, 8, algo)
///   .expect("Failed to generate TOTP code");
///
/// assert_eq!(totp_code, "94287082");
/// ```
pub fn totp<D>(
    secret: &[u8],
    time_since_epoch: Duration,
    time_step: Duration,
    length: usize,
    algo: D,
) -> TotpResult<String>
where
    D: Digest,
{
    use byteorder::{BigEndian, ByteOrder};
    use crypto::{hmac::Hmac, mac::Mac};

    let mut buf: [u8; 8] = [0; 8];
    BigEndian::write_u64(&mut buf, time_since_epoch.as_secs() / time_step.as_secs());

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
mod tests {
    use super::*;

    // Example code from
    // https://tools.ietf.org/html/rfc6238#appendix-A
    fn rfc6238_test<D: Digest>(
        time_since_epoch: Duration,
        digest: D,
        expected_code: &str,
    ) -> TotpResult<()> {
        const RFC_SECRET_SEED: &[u8] = b"12345678901234567890";

        // Need to seed with the proper number of bytes (sha1 = 20 bytes, sha256 = 32, sha512 = 64)
        let secret: Vec<u8> = std::iter::repeat(RFC_SECRET_SEED)
            .flatten()
            .take(digest.output_bytes())
            .cloned()
            .collect();

        let code = totp(
            &secret,
            time_since_epoch,
            RFC6238_RECOMMENDED_TIMESTEP,
            8,
            digest,
        )?;

        assert_eq!(code, expected_code);

        Ok(())
    }

    #[cfg(test)]
    #[test]
    fn rfc6238_sha1_tests() -> TotpResult<()> {
        // test vectors from the RFC
        // https://tools.ietf.org/html/rfc6238#appendix-B

        fn algo() -> impl Digest {
            Sha1::new()
        }

        rfc6238_test(Duration::from_secs(59), algo(), "94287082")?;
        rfc6238_test(Duration::from_secs(1_111_111_109), algo(), "07081804")?;
        rfc6238_test(Duration::from_secs(1_111_111_111), algo(), "14050471")?;
        rfc6238_test(Duration::from_secs(1_234_567_890), algo(), "89005924")?;
        rfc6238_test(Duration::from_secs(2_000_000_000), algo(), "69279037")?;
        rfc6238_test(Duration::from_secs(20_000_000_000), algo(), "65353130")?;

        Ok(())
    }

    #[cfg(test)]
    #[test]
    fn rfc6238_sha256_tests() -> TotpResult<()> {
        // test vectors from the RFC
        // https://tools.ietf.org/html/rfc6238#appendix-B

        fn algo() -> impl Digest {
            crypto::sha2::Sha256::new()
        }

        rfc6238_test(Duration::from_secs(59), algo(), "46119246")?;
        rfc6238_test(Duration::from_secs(1_111_111_109), algo(), "68084774")?;
        rfc6238_test(Duration::from_secs(1_111_111_111), algo(), "67062674")?;
        rfc6238_test(Duration::from_secs(1_234_567_890), algo(), "91819424")?;
        rfc6238_test(Duration::from_secs(2_000_000_000), algo(), "90698825")?;
        rfc6238_test(Duration::from_secs(20_000_000_000), algo(), "77737706")?;

        Ok(())
    }

    #[cfg(test)]
    #[test]
    fn rfc6238_sha512_tests() -> TotpResult<()> {
        // test vectors from the RFC
        // https://tools.ietf.org/html/rfc6238#appendix-B

        fn algo() -> impl Digest {
            crypto::sha2::Sha512::new()
        }

        rfc6238_test(Duration::from_secs(59), algo(), "90693936")?;
        rfc6238_test(Duration::from_secs(1_111_111_109), algo(), "25091201")?;
        rfc6238_test(Duration::from_secs(1_111_111_111), algo(), "99943326")?;
        rfc6238_test(Duration::from_secs(1_234_567_890), algo(), "93441116")?;
        rfc6238_test(Duration::from_secs(2_000_000_000), algo(), "38618901")?;
        rfc6238_test(Duration::from_secs(20_000_000_000), algo(), "47863826")?;

        Ok(())
    }
}
