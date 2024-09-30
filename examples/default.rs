use randpass::{create_charset, create_password, PasswordCriteria};

fn main() {
    let password_length = 20;
    let criteria = PasswordCriteria::Alphanumeric;
    let base_charset = create_charset(&criteria, None).unwrap();
    let password = create_password(password_length, &base_charset, None).unwrap();

    println!("{}", password);
}
