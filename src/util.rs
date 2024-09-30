use crossterm::terminal::size;
use regex::Regex;
use std::collections::HashMap;
use std::io;
use std::io::IsTerminal;
use std::{borrow::Cow, collections::HashSet};
use textwrap::wrap;

use crate::{Error, PasswordCriteria};

#[allow(dead_code)]
pub(crate) fn create_charset(
    criteria: &PasswordCriteria,
    extra_charset: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
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

#[allow(dead_code)]
pub(crate) fn parse_escape_sequences(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    '0' => {
                        result.push('\0');
                        chars.next();
                    }
                    'a' => {
                        result.push('\u{0007}');
                        chars.next();
                    }
                    'b' => {
                        result.push('\u{0008}');
                        chars.next();
                    }
                    't' => {
                        result.push('\t');
                        chars.next();
                    }
                    'n' => {
                        result.push('\n');
                        chars.next();
                    }
                    'v' => {
                        result.push('\u{000b}');
                        chars.next();
                    }
                    'f' => {
                        result.push('\u{000c}');
                        chars.next();
                    }
                    'r' => {
                        result.push('\r');
                        chars.next();
                    }
                    'e' => {
                        result.push('\u{001b}');
                        chars.next();
                    }
                    '\\' => {
                        result.push('\\');
                        chars.next();
                    }
                    '\'' => {
                        result.push('\'');
                        chars.next();
                    }
                    '\"' => {
                        result.push('\"');
                        chars.next();
                    }
                    'u' => {
                        chars.next();
                        let mut hex = String::new();
                        for _ in 0..4 {
                            if let Some(&next_char) = chars.peek() {
                                if next_char.is_ascii_hexdigit() {
                                    hex.push(next_char);
                                    chars.next();
                                } else {
                                    break;
                                }
                            }
                        }
                        if let Ok(codepoint) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(codepoint) {
                                result.push(ch);
                            }
                        }
                    }
                    _ => {
                        result.push(c);
                    }
                }
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[allow(dead_code)]
pub(crate) fn log2_factorial(n: u64) -> f64 {
    (1..=n).map(|x| x as f64).map(|x| x.log(2.0)).sum()
}

#[allow(dead_code)]
pub(crate) fn log2_binomial_coefficient(n: u64, k: u64) -> f64 {
    if n >= k {
        return log2_factorial(n) - log2_factorial(k) - log2_factorial(n - k);
    }
    panic!();
}

const DEFAULT_WRAP_WIDTH: u16 = 80;

fn wrap_text(text: &str) -> Vec<Cow<'_, str>> {
    wrap(text, size().unwrap_or((DEFAULT_WRAP_WIDTH, 0)).0 as usize)
}

const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[1;31m";
const GREEN: &str = "\x1b[1;32m";
const YELLOW: &str = "\x1b[1;33m";
const CYAN: &str = "\x1b[1;36m";
const RESET: &str = "\x1b[0m";

#[allow(dead_code)]
pub(crate) fn print_info(text: &str) {
    if io::stderr().is_terminal() {
        eprintln!(
            "{}",
            wrap_text(&format!(
                "{}info:{} {}{}{}",
                CYAN, RESET, BOLD, &text, RESET
            ))
            .join("\n"),
        );
    } else {
        eprintln!("{}", wrap_text(&format!("info: {}", &text)).join("\n"));
    }
}

#[allow(dead_code)]
pub(crate) fn print_hint(text: &str) {
    if io::stderr().is_terminal() {
        eprintln!(
            "{}",
            wrap_text(&format!(
                "{}hint:{} {}{}{}",
                GREEN, RESET, BOLD, &text, RESET
            ))
            .join("\n"),
        );
    } else {
        eprintln!("{}", wrap_text(&format!("hint: {}", &text)).join("\n"));
    }
}

#[allow(dead_code)]
pub(crate) fn print_warning(text: &str) {
    if io::stderr().is_terminal() {
        eprintln!(
            "{}",
            wrap_text(&format!(
                "{}warning:{} {}{}{}",
                YELLOW, RESET, BOLD, &text, RESET
            ))
            .join("\n"),
        );
    } else {
        eprintln!("{}", wrap_text(&format!("warning: {}", &text)).join("\n"));
    }
}

#[allow(dead_code)]
pub(crate) fn print_error(text: &str) {
    if io::stderr().is_terminal() {
        eprintln!(
            "{}",
            wrap_text(&format!(
                "{}error:{} {}{}{}",
                RED, RESET, BOLD, &text, RESET
            ))
            .join("\n"),
        );
    } else {
        eprintln!("{}", wrap_text(&format!("error: {}", &text)).join("\n"));
    }
}

#[allow(dead_code)]
pub(crate) fn calculate_char_multiplicities(charset: &[u8]) -> Vec<usize> {
    let mut multiplicity_map: HashMap<u8, usize> = HashMap::new();

    for c in charset {
        *multiplicity_map.entry(*c).or_insert(0) += 1;
    }

    let mut multiplicities: Vec<usize> = multiplicity_map.values().cloned().collect();

    multiplicities.sort();

    multiplicities
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_approx_eq {
        ($a:expr, $b:expr) => {{
            assert!(
                ($a - $b).abs() < 1.0e-6,
                concat!(
                    "assertion `left == right` failed\n",
                    " left: {:?}\n",
                    "right: {:?}"
                ),
                $a,
                $b,
            );
        }};
    }

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
    fn test_parse_escape_sequences() {
        assert_eq!(
            parse_escape_sequences("Hello\\0World"),
            "Hello\u{0000}World"
        );

        assert_eq!(
            parse_escape_sequences("Hello\\aWorld"),
            "Hello\u{0007}World"
        );

        assert_eq!(
            parse_escape_sequences("Hello\\bWorld"),
            "Hello\u{0008}World"
        );

        assert_eq!(
            parse_escape_sequences("Hello\\tWorld"),
            "Hello\u{0009}World"
        );

        assert_eq!(
            parse_escape_sequences("Hello\\nWorld"),
            "Hello\u{000a}World"
        );

        assert_eq!(
            parse_escape_sequences("Hello\\vWorld"),
            "Hello\u{000b}World"
        );

        assert_eq!(
            parse_escape_sequences("Hello\\fWorld"),
            "Hello\u{000c}World"
        );

        assert_eq!(
            parse_escape_sequences("Hello\\rWorld"),
            "Hello\u{000d}World"
        );

        assert_eq!(
            parse_escape_sequences("Hello\\eWorld"),
            "Hello\u{001b}World"
        );

        assert_eq!(parse_escape_sequences("Hello\\\\World"), "Hello\\World");

        assert_eq!(parse_escape_sequences("Hello\\'World"), "Hello'World");

        assert_eq!(parse_escape_sequences("Hello\\\"World"), "Hello\"World");

        for codepoint in 0x0..=0xf {
            if let Some(expected_char) = char::from_u32(codepoint) {
                assert_eq!(
                    parse_escape_sequences(&format!("Hello\\u{:01x}World", codepoint)),
                    format!("Hello{}World", expected_char)
                );
            }
        }

        for codepoint in 0x00..=0xff {
            if let Some(expected_char) = char::from_u32(codepoint) {
                assert_eq!(
                    parse_escape_sequences(&format!("Hello\\u{:02x}World", codepoint)),
                    format!("Hello{}World", expected_char)
                );
            }
        }

        for codepoint in 0x000..=0xfff {
            if let Some(expected_char) = char::from_u32(codepoint) {
                assert_eq!(
                    parse_escape_sequences(&format!("Hello\\u{:03x}World", codepoint)),
                    format!("Hello{}World", expected_char)
                );
            }
        }

        for codepoint in 0x0000..=0xffff {
            if let Some(expected_char) = char::from_u32(codepoint) {
                assert_eq!(
                    parse_escape_sequences(&format!("Hello\\u{:04x}World", codepoint)),
                    format!("Hello{}World", expected_char)
                );
            }
        }
    }

    #[test]
    fn test_log2_factorial() {
        assert_approx_eq!(log2_factorial(0), (1.0 as f64).log(2.0));

        assert_approx_eq!(log2_factorial(5), (120.0 as f64).log(2.0));

        assert_approx_eq!(log2_factorial(10), (3628800.0 as f64).log(2.0));
    }

    #[test]
    fn test_log2_binomial_coefficient() {
        assert_approx_eq!(
            log2_binomial_coefficient(0, 0),
            log2_factorial(0) - log2_factorial(0) - log2_factorial(0)
        );

        assert_approx_eq!(
            log2_binomial_coefficient(5, 0),
            log2_factorial(5) - log2_factorial(0) - log2_factorial(5)
        );

        assert_approx_eq!(
            log2_binomial_coefficient(10, 5),
            log2_factorial(10) - log2_factorial(5) - log2_factorial(5)
        );

        assert_approx_eq!(
            log2_binomial_coefficient(10, 10),
            log2_factorial(10) - log2_factorial(10) - log2_factorial(0)
        );
    }

    #[test]
    fn test_calculate_char_multiplicities() {
        assert_eq!(
            calculate_char_multiplicities(&"hello".as_bytes().to_vec()),
            vec![1, 1, 1, 2]
        );
    }
}
