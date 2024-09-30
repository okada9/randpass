mod criteria;
mod errors;
mod util;

pub use criteria::*;
pub use errors::*;
use util::*;

use rand::seq::SliceRandom;
use rand::{rngs::OsRng, Rng};
use regex::Regex;
use std::collections::HashSet;

/// Creates a character set.
///
/// # Parameters
///
/// - `criteria`: Password criteria.
/// - `extra_charset`: Extra character set.
///
/// # Returns
///
/// `Ok(Vec<u8>)` with the created character set on success;
/// `Err(Error)` on failure.
pub fn create_charset(
    criteria: &PasswordCriteria,
    extra_charset: Option<&[u8]>,
) -> Result<Vec<u8>, errors::Error> {
    let mut charset: HashSet<u8> = match criteria {
        PasswordCriteria::Alphanumeric => Ok::<HashSet<u8>, Error>(
            (b'0'..=b'9')
                .chain(b'A'..=b'Z')
                .chain(b'a'..=b'z')
                .collect(),
        ),
        PasswordCriteria::UppercaseAndDigitsOnly => Ok((b'0'..=b'9').chain(b'A'..=b'Z').collect()),
        PasswordCriteria::LowercaseAndDigitsOnly => Ok((b'0'..=b'9').chain(b'a'..=b'z').collect()),
        PasswordCriteria::DigitsOnly => Ok((b'0'..=b'9').collect()),
        PasswordCriteria::AllPrintableChars => Ok((b' '..=b'~').collect()),
        PasswordCriteria::BaseCharset(chars) => Ok(HashSet::from_iter(chars.iter().cloned())),
        PasswordCriteria::RegexPattern(p) => Ok(create_charset_from_regex(p)?
            .into_iter()
            .collect::<HashSet<u8>>()),
    }?;

    if let Some(extra_charset) = extra_charset {
        charset.extend(extra_charset);
    }

    if charset.is_empty() {
        return Err(Error::NoValidChars);
    }

    let mut charset: Vec<u8> = charset.into_iter().collect();

    charset.sort();

    Ok(charset)
}

fn create_charset_from_regex(pattern: &str) -> Result<Vec<u8>, Error> {
    let regex = Regex::new(pattern).map_err(|_| Error::InvalidRegex)?;
    let charset = (b' '..=b'~')
        .filter(|c| regex.is_match(&(*c as char).to_string()))
        .collect::<Vec<u8>>();

    if charset.is_empty() {
        return Err(Error::RegexMatchesNoChars);
    }

    Ok(charset)
}

/// Creates a password.
///
/// # Parameters
///
/// - `password_length`: Length of the password.
/// - `base_charset`: Base character set.
/// - `criteria`: Password criteria.
/// - `extra_charset`: Extra character set.
///
/// # Returns
///
/// `Ok(String)` with the generated password on success; `Err(Error)` on
/// failure.
pub fn create_password(
    password_length: usize,
    base_charset: &[u8],
    criteria: &PasswordCriteria,
    extra_charset: Option<&[u8]>,
) -> Result<String, Error> {
    let mut rng = OsRng;
    let mut password_chars = extra_charset.unwrap_or(&[]).to_owned();

    if criteria == &PasswordCriteria::AllPrintableChars {
        let special_chars: Vec<u8> = (b' '..=b'~')
            .filter(|c: &u8| !c.is_ascii_alphanumeric())
            .collect();

        if let Some(&special_char) = special_chars.choose(&mut rng) {
            password_chars.push(special_char);
        }
    }

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
/// - `base_charset`: Base character set.
/// - `extra_charset`: Extra character set.
///
/// # Returns
///
/// `Some(f64)` for valid inputs; `None` otherwise.
pub fn calculate_entropy(
    password_length: usize,
    base_charset: &[u8],
    extra_charset: Option<&[u8]>,
) -> Option<f64> {
    let base_charset_size = base_charset.len();

    if let Some(extra_charset) = extra_charset {
        let extra_char_multiplicities = calculate_char_multiplicities(extra_charset);
        let extra_charset_size = extra_char_multiplicities.iter().sum::<usize>();

        if password_length < extra_charset_size {
            return None;
        }

        Some(
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
        Some((password_length as u64) as f64 * (base_charset_size as f64).log(2.0))
    }
}

/// The minimum entropy threshold for a secure password.
pub const ENTROPY_THRESHOLD: f64 = 72.0;

/// Suggests the minimum length for a secure password.
///
/// # Parameters
///
/// - `base_charset`: Base character set.
/// - `extra_charset`: Extra character set.
///
/// # Returns
///
/// `Some(usize)` with the suggested length; `None` if inputs are
/// invalid.
pub fn suggest_password_length(base_charset: &[u8], extra_charset: Option<&[u8]>) -> Option<usize> {
    for i in 1..1000 {
        if let Some(entropy) = calculate_entropy(i, base_charset, extra_charset) {
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
    fn test_create_charset_with_default_config() {
        let charset = create_charset(&PasswordCriteria::Alphanumeric, None).unwrap();
        assert_eq!(
            charset,
            (b'0'..=b'9')
                .chain(b'A'..=b'Z')
                .chain(b'a'..=b'z')
                .collect::<Vec<u8>>()
        );
    }

    #[test]
    fn test_create_charset_with_uppercase_letters_and_digits_only() {
        let charset = create_charset(&PasswordCriteria::UppercaseAndDigitsOnly, None).unwrap();
        assert_eq!(
            charset,
            (b'0'..=b'9').chain(b'A'..=b'Z').collect::<Vec<u8>>()
        );
    }

    #[test]
    fn test_create_charset_with_lowercase_letters_and_digits_only() {
        let charset = create_charset(&PasswordCriteria::LowercaseAndDigitsOnly, None).unwrap();
        assert_eq!(
            charset,
            (b'0'..=b'9').chain(b'a'..=b'z').collect::<Vec<u8>>()
        );
    }

    #[test]
    fn test_create_charset_with_digits_only() {
        let charset = create_charset(&PasswordCriteria::DigitsOnly, None).unwrap();
        assert_eq!(charset, (b'0'..=b'9').collect::<Vec<u8>>());
    }

    #[test]
    fn test_create_charset_with_all_printable_chars() {
        let charset = create_charset(&PasswordCriteria::AllPrintableChars, None).unwrap();
        assert_eq!(charset, (b' '..=b'~').collect::<Vec<u8>>());
    }

    #[test]
    fn test_create_charset_without_duplication() {
        let charset =
            create_charset(&PasswordCriteria::RegexPattern(&"[0-9]"), Some(b"00000")).unwrap();
        assert_eq!(charset, (b'0'..=b'9').collect::<Vec<u8>>());
    }

    #[test]
    fn test_create_password_length() {
        let charset = b"abcdefg";
        let password = create_password(10, charset, &PasswordCriteria::Alphanumeric, None)
            .ok()
            .unwrap();
        assert_eq!(password.len(), 10);
    }

    #[test]
    fn test_create_password_with_special_chars() {
        let length = 10;
        let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let special_chars: Vec<u8> = (b' '..=b'~')
            .filter(|c: &u8| !c.is_ascii_alphanumeric())
            .collect();
        let password = create_password(length, charset, &PasswordCriteria::AllPrintableChars, None)
            .ok()
            .unwrap();

        assert!(special_chars
            .iter()
            .any(|c| password.contains(char::from(*c))));
    }

    #[test]
    fn test_create_password_with_extra_charset() {
        let length = 10;
        let extra_charset = b"!@#$%";
        let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let password = create_password(
            length,
            charset,
            &PasswordCriteria::Alphanumeric,
            Some(extra_charset),
        )
        .ok()
        .unwrap();

        assert!(extra_charset
            .iter()
            .all(|c| password.contains(char::from(*c))));
    }

    #[test]
    fn test_create_charset_from_regex() {
        let charset = create_charset_from_regex("[a-z]").unwrap();
        assert_eq!(charset, (b'a'..=b'z').collect::<Vec<u8>>());
    }

    #[test]
    fn test_create_charset_from_invalid_regex() {
        let result = create_charset_from_regex("[a-z");
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_entropy() {
        let base_charset = create_charset(&PasswordCriteria::Alphanumeric, None).unwrap();

        assert_eq!(
            calculate_entropy(10, &base_charset, None),
            Some((62 as f64).powf(10.0).log(2.0))
        );

        assert_eq!(
            calculate_entropy(5, &base_charset, Some(b"01234")),
            Some(log2_factorial(5))
        );

        assert_eq!(
            calculate_entropy(5, &base_charset, Some(b"00000")),
            Some(0.0)
        );

        assert_eq!(
            calculate_entropy(20, &base_charset, Some(b"000001111222334")),
            Some(
                log2_binomial_coefficient(20, 15) + log2_factorial(15)
                    - log2_factorial(5)
                    - log2_factorial(4)
                    - log2_factorial(3)
                    - log2_factorial(2)
                    - log2_factorial(1)
                    + (62 as f64).powf(5.0).log(2.0)
            )
        );

        assert_eq!(
            calculate_entropy(10, &base_charset, Some(b"01234")),
            Some(
                log2_binomial_coefficient(10, 5) + log2_factorial(5) + (62 as f64).powf(5.0).log2()
            )
        );
    }

    #[test]
    fn test_suggest_password_length() {
        let base_charset = create_charset(&PasswordCriteria::Alphanumeric, None).unwrap();
        let small_base_chatset =
            create_charset(&PasswordCriteria::BaseCharset(b"a"), None).unwrap();

        assert_eq!(suggest_password_length(&base_charset, None), Some(13));

        assert!(suggest_password_length(&small_base_chatset, None).is_none());
    }
}
