mod util;

use util::*;

use clap::Parser;
use randpass::{
    calculate_entropy, create_charset, create_password, suggest_password_length, Error,
    PasswordCriteria, ENTROPY_THRESHOLD,
};
use std::process;

/// Password Generator
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Length of the password
    #[arg(short = 'l', long = "length", default_value_t = 20)]
    password_length: usize,

    /// Use uppercase letters and digits only
    #[arg(
        short = 'u',
        long = "uppercase",
        conflicts_with = "use_lowercase_and_digits_only",
        conflicts_with = "use_digits_only",
        conflicts_with = "use_all_printable_chars",
        conflicts_with = "base_charset",
        conflicts_with = "regex_pattern"
    )]
    use_uppercase_and_digits_only: bool,

    /// Use lowercase letters and digits only
    #[arg(
        short = 'L',
        long = "lowercase",
        conflicts_with = "use_digits_only",
        conflicts_with = "use_all_printable_chars",
        conflicts_with = "base_charset",
        conflicts_with = "regex_pattern"
    )]
    use_lowercase_and_digits_only: bool,

    /// Use digits only
    #[arg(
        short = 'd',
        long = "digits",
        conflicts_with = "use_all_printable_chars",
        conflicts_with = "base_charset",
        conflicts_with = "regex_pattern"
    )]
    use_digits_only: bool,

    /// Use all letters, digits, and symbols
    #[arg(
        short = 's',
        long = "symbols",
        conflicts_with = "base_charset",
        conflicts_with = "regex_pattern"
    )]
    use_all_printable_chars: bool,

    /// Custom base character set to use
    #[arg(short, long = "base", conflicts_with = "regex_pattern")]
    base_charset: Option<String>,

    /// Regex pattern for allowed characters
    #[arg(short, long = "regex", default_value = "[A-Za-z0-9]")]
    regex_pattern: Option<String>,

    /// Extra characters to include
    #[arg(short, long = "extra")]
    extra_charset: Option<String>,

    /// Number of passwords to generate
    #[arg(short = 'n', long = "number", default_value_t = 1)]
    password_quantity: usize,

    /// Customize the output format of the password
    #[arg(short, long = "format")]
    format_string: Option<String>,

    /// Do not print the trailing newline character
    #[arg(short = 'N', long)]
    no_newline: bool,

    /// Use a custom delimiter
    #[arg(short = 'D', long)]
    delimiter: Option<String>,

    /// Do not warn about weak passwords
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,

    /// Always output the strength of the password
    #[arg(short, long)]
    verbose: bool,

    /// Terminate if the password is weak
    #[arg(short = 'F', long)]
    fail: bool,
}

fn report_entropy(
    base_charset: &[u8],
    extra_charset: &[u8],
    password_length: usize,
    verbose: bool,
    quiet: bool,
    fail: bool,
) -> Result<(), Error> {
    let base_charset_size = base_charset.len();
    let extra_char_multiplicities = calculate_char_multiplicities(extra_charset);
    let entropy = calculate_entropy(
        password_length,
        base_charset_size,
        Some(&extra_char_multiplicities),
    )
    .unwrap();

    if entropy >= ENTROPY_THRESHOLD && verbose {
        print_info(&format!("your password has {:.2} bits of entropy", entropy));
    }

    if entropy < ENTROPY_THRESHOLD && !quiet {
        if fail {
            return Err(Error::PasswordEntropyInsufficient(entropy));
        } else {
            print_warning(&format!(
                "your password has only {:.2} bits of entropy",
                entropy
            ));
        }

        if let Some(suggested_length) =
            suggest_password_length(base_charset_size, Some(&extra_char_multiplicities))
        {
            print_hint(&format!(
                "set '--length' to '{}' or longer (use '--quiet' to hide this message)",
                suggested_length
            ));
        }
    }

    Ok(())
}

fn get_newline(delimiter: Option<&str>, last_line: bool, no_newline: bool) -> String {
    match delimiter {
        Some(delimiter) => {
            if last_line {
                "".to_string()
            } else {
                parse_escape_sequences(delimiter)
            }
        }
        None => {
            if last_line && no_newline {
                "".to_string()
            } else {
                "\n".to_string()
            }
        }
    }
}

fn run() -> Result<(), Error> {
    let args = Args::parse();
    let base_charset = match args.base_charset {
        Some(b) => b.as_bytes().to_vec(),
        None => vec![],
    };
    let extra_charset = match args.extra_charset {
        Some(e) => e.as_bytes().to_vec(),
        None => vec![],
    };
    let regex_pattern = args.regex_pattern.unwrap();

    if extra_charset.len() > args.password_length {
        return Err(Error::TooManyExtraChars);
    }

    let criteria = if args.use_uppercase_and_digits_only {
        PasswordCriteria::UppercaseAndDigitsOnly
    } else if args.use_lowercase_and_digits_only {
        PasswordCriteria::LowercaseAndDigitsOnly
    } else if args.use_digits_only {
        PasswordCriteria::DigitsOnly
    } else if args.use_all_printable_chars {
        PasswordCriteria::AllPrintableChars
    } else if !base_charset.is_empty() {
        PasswordCriteria::BaseCharset(&base_charset)
    } else if !regex_pattern.is_empty() {
        PasswordCriteria::RegexPattern(&regex_pattern)
    } else {
        PasswordCriteria::Alphanumeric
    };

    let base_charset = match create_charset(&criteria, Some(&extra_charset)) {
        Ok(base_charset) => base_charset,
        Err(e) => return Err(e),
    };

    if !args.quiet || args.fail {
        report_entropy(
            &base_charset,
            &extra_charset,
            args.password_length,
            args.verbose,
            args.quiet,
            args.fail,
        )?;
    }

    for i in 0..args.password_quantity {
        let newline = get_newline(
            args.delimiter.as_deref(),
            i == args.password_quantity - 1,
            args.no_newline,
        );
        let password = match create_password(
            args.password_length,
            &base_charset,
            &criteria,
            Some(&extra_charset),
        ) {
            Ok(p) => p,
            Err(_) => panic!(),
        };

        match args.format_string {
            Some(ref format_string) => {
                print!("{}{}", format_string.replace("{}", &password), newline)
            }
            None => print!("{}{}", password, newline),
        };
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        print_error(&e.to_string());
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_newline() {
        assert_eq!(get_newline(Some("\\0"), true, true), "");

        assert_eq!(get_newline(Some("\\0"), false, true), "\0");

        assert_eq!(get_newline(Some("\\0"), true, false), "");

        assert_eq!(get_newline(Some("\\0"), false, false), "\0");

        assert_eq!(get_newline(None, true, true), "");

        assert_eq!(get_newline(None, false, true), "\n");

        assert_eq!(get_newline(None, true, false), "\n");

        assert_eq!(get_newline(None, false, false), "\n");
    }
}
