use randpass::{calculate_entropy, create_charset, PasswordCriteria};

fn main() {
    let password_length = 20;
    let criteria = PasswordCriteria::Alphanumeric;
    let base_charset = create_charset(&criteria, None).unwrap();
    let entropy = calculate_entropy(password_length, base_charset.len(), None).unwrap();

    println!("{}", entropy);
}
