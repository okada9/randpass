use randpass::{create_password, PasswordCriteria};

fn main() {
    let password_length = 20;
    let criteria = PasswordCriteria::Alphanumeric;
    let extra_charset = b"!@#$%";
    let password = create_password(password_length, &criteria, Some(extra_charset)).unwrap();

    println!("{}", password);
}
