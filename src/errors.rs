use std::fmt;

/// Represents errors that can occur during password generation.
#[derive(Debug)]
pub enum Error {
    /// A generic error variant.
    Default,

    /// The provided regex pattern is invalid.
    InvalidRegex,

    /// No characters match the given criteria.
    NoValidChars,

    /// Indicates insufficient password entropy, with the calculated
    /// entropy value.
    PasswordEntropyInsufficient(f64),

    /// The regex pattern matches no characters.
    RegexMatchesNoChars,

    /// The number of extra characters is greater than the requested
    /// password length.
    TooManyExtraChars,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Default => write!(f, "error"),
            Error::InvalidRegex => write!(f, "invalid regex pattern"),
            Error::NoValidChars => write!(f, "no valid characters left in the charset"),
            Error::PasswordEntropyInsufficient(entropy) => {
                write!(f, "your password has only {:.2} bits of entropy", entropy)
            }
            Error::RegexMatchesNoChars => {
                write!(f, "no valid characters found for the provided regex")
            }
            Error::TooManyExtraChars => write!(f, "too many extra characters"),
        }
    }
}
