/// Defines criteria for password generation.
#[derive(Clone, PartialEq)]
pub enum PasswordCriteria<'a> {
    /// Allows letters and digits.
    Alphanumeric,

    /// Allows only uppercase letters and digits.
    UppercaseAndDigitsOnly,

    /// Allows only lowercase letters and digits.
    LowercaseAndDigitsOnly,

    /// Allows only digits.
    DigitsOnly,

    /// Allows all printable ASCII characters.
    AllPrintableChars,

    /// Uses a custom base character set provided as a byte slice.
    BaseCharset(&'a [u8]),

    /// Uses a regex pattern.
    RegexPattern(&'a str),
}
