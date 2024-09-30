mod criteria;
mod errors;
mod util;

pub use criteria::*;
pub use errors::*;
use util::*;

use rand::seq::SliceRandom;
use rand::{rngs::OsRng, Rng};

/// Creates a password.
///
/// # Parameters
///
/// - `password_length`: Length of the password.
/// - `criteria`: Password criteria.
/// - `extra_charset`: Extra character set.
///
/// # Returns
///
/// `Ok(String)` with the generated password on success; `Err(Error)` on
/// failure.
pub fn create_password(
    password_length: usize,
    criteria: &PasswordCriteria,
    extra_charset: Option<&[u8]>,
) -> Result<String, Error> {
    let base_charset = create_charset(criteria, extra_charset)?;
    let mut rng = OsRng;
    let mut password_chars = extra_charset.unwrap_or(&[]).to_owned();
    let remaining_length = password_length.saturating_sub(password_chars.len());

    password_chars.extend((0..remaining_length).map(|_| {
        let idx = rng.gen_range(0..base_charset.len());
        base_charset[idx]
    }));

    password_chars.shuffle(&mut rng);

    let password = String::from_utf8(password_chars).map_err(|_| Error::Default)?;

    Ok(password)
}

/// Calculates password entropy.
///
/// # Parameters
///
/// - `password_length`: Length of the password.
/// - `criteria`: Password criteria.
/// - `extra_charset`: Extra character set.
///
/// # Returns
///
/// `Some(f64)` for valid inputs; `None` otherwise.
pub fn calculate_entropy(
    password_length: usize,
    criteria: &PasswordCriteria,
    extra_charset: Option<&[u8]>,
) -> Result<f64, Error> {
    let base_charset = create_charset(criteria, extra_charset)?;
    let base_charset_size = base_charset.len();

    if let Some(extra_charset) = extra_charset {
        let extra_char_multiplicities = calculate_char_multiplicities(extra_charset);
        let extra_charset_size = extra_char_multiplicities.iter().sum::<usize>();

        if password_length < extra_charset_size {
            return Err(Error::Default);
        }

        Ok(
            log2_binomial_coefficient(password_length as u64, extra_charset_size as u64)
                + (log2_factorial(extra_charset_size.try_into().unwrap())
                    - extra_char_multiplicities
                        .iter()
                        .map(|&num| log2_factorial(num as u64))
                        .sum::<f64>())
                + (password_length as u64 - extra_charset_size as u64) as f64
                    * (base_charset_size as f64).log(2.0),
        )
    } else {
        Ok((password_length as u64) as f64 * (base_charset_size as f64).log(2.0))
    }
}

/// The minimum entropy threshold for a secure password.
pub const ENTROPY_THRESHOLD: f64 = 72.0;

/// Suggests the minimum length for a secure password.
///
/// # Parameters
///
/// - `criteria`: Password criteria.
/// - `extra_charset`: Extra character set.
///
/// # Returns
///
/// `Some(usize)` with the suggested length; `None` if inputs are
/// invalid.
pub fn suggest_password_length(
    criteria: &PasswordCriteria,
    extra_charset: Option<&[u8]>,
) -> Option<usize> {
    for i in 1..1000 {
        if let Ok(entropy) = calculate_entropy(i, criteria, extra_charset) {
            if entropy >= ENTROPY_THRESHOLD {
                return Some(i);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_password_length() {
        let charset = b"abcdefg";
        let password = create_password(10, &PasswordCriteria::BaseCharset(charset), None)
            .ok()
            .unwrap();
        assert_eq!(password.len(), 10);
    }

    #[test]
    fn test_create_password_with_extra_charset() {
        let length = 10;
        let extra_charset = b"!@#$%";
        let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let password = create_password(
            length,
            &PasswordCriteria::BaseCharset(charset),
            Some(extra_charset),
        )
        .ok()
        .unwrap();

        assert!(extra_charset
            .iter()
            .all(|c| password.contains(char::from(*c))));
    }

    #[test]
    fn test_calculate_entropy() {
        assert_eq!(
            calculate_entropy(10, &PasswordCriteria::Alphanumeric, None).unwrap(),
            (62 as f64).powf(10.0).log(2.0)
        );

        assert_eq!(
            calculate_entropy(5, &PasswordCriteria::Alphanumeric, Some(b"01234")).unwrap(),
            log2_factorial(5)
        );

        assert_eq!(
            calculate_entropy(5, &PasswordCriteria::Alphanumeric, Some(b"00000")).unwrap(),
            0.0
        );

        assert_eq!(
            calculate_entropy(
                20,
                &PasswordCriteria::Alphanumeric,
                Some(b"000001111222334")
            )
            .unwrap(),
            log2_binomial_coefficient(20, 15) + log2_factorial(15)
                - log2_factorial(5)
                - log2_factorial(4)
                - log2_factorial(3)
                - log2_factorial(2)
                - log2_factorial(1)
                + (62 as f64).powf(5.0).log(2.0)
        );

        assert_eq!(
            calculate_entropy(10, &PasswordCriteria::Alphanumeric, Some(b"01234")).unwrap(),
            log2_binomial_coefficient(10, 5) + log2_factorial(5) + (62 as f64).powf(5.0).log2()
        );
    }

    #[test]
    fn test_suggest_password_length() {
        assert_eq!(
            suggest_password_length(&PasswordCriteria::Alphanumeric, None),
            Some(13)
        );

        assert!(suggest_password_length(&PasswordCriteria::BaseCharset(b"a"), None).is_none());
    }
}
