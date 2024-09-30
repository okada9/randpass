use randpass::{create_password, PasswordCriteria};

fn main() {
    let password_length = 20;
    let criteria = PasswordCriteria::Alphanumeric;
    let extra_charset = None;
    let password = create_password(password_length, &criteria, extra_charset).unwrap();

    println!("{}", password);
}
