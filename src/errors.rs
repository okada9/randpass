use std::fmt;

#[derive(Debug)]
pub enum Error {
    Default,
    InvalidRegex,
    NoValidChars,
    PasswordEntropyInsufficient(f64),
    RegexMatchesNoChars,
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
