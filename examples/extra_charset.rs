use randpass::{create_charset, create_password, PasswordCriteria};

fn main() {
    let password_length = 20;
    let criteria = PasswordCriteria::Alphanumeric;
    let extra_charset = b"!@#$%";
    let base_charset = create_charset(&criteria, Some(extra_charset)).unwrap();
    let password = create_password(
        password_length,
        &base_charset,
        &criteria,
        Some(extra_charset),
    )
    .unwrap();

    println!("{}", password);
}
