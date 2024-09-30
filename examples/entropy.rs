use randpass::{calculate_entropy, PasswordCriteria};

fn main() {
    let password_length = 20;
    let criteria = PasswordCriteria::Alphanumeric;
    let extra_charset = None;
    let entropy = calculate_entropy(password_length, &criteria, extra_charset).unwrap();

    println!("{}", entropy);
}
