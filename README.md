# `randpass`

`randpass` is a secure password generator written in [Rust], featuring a
customizable character set, entropy calculation, and more.

## Usage

```bash
randpass [OPTIONS]
```

### Options

| Option                               | Description                                                   |
| ------------------------------------ | ------------------------------------------------------------- |
| `-l`, `--length <PASSWORD_LENGTH>`   | Length of the password [default: `20`]                        |
| `-u`, `--uppercase`                  | Use uppercase letters and digits only                         |
| `-L`, `--lowercase`                  | Use lowercase letters and digits only                         |
| `-d`, `--digits`                     | Use digits only                                               |
| `-s`, `--symbols`                    | Use all letters, digits, and symbols                          |
| `-b`, `--base <BASE_CHARSET>`        | Custom base character set to use                              |
| `-r`, `--regex <REGEX_PATTERN>`      | Regex pattern for allowed characters [default: `[A-Za-z0-9]`] |
| `-e`, `--extra <EXTRA_CHARSET>`      | Extra characters to include                                   |
| `-n`, `--number <PASSWORD_QUANTITY>` | Number of passwords to generate [default: `1`]                |
| `-f`, `--format <FORMAT_STRING>`     | Customize the output format of the password                   |
| `-N`, `--no-newline`                 | Do not print the trailing newline character                   |
| `-D`, `--delimiter <DELIMITER>`      | Use a custom delimiter                                        |
| `-q`, `--quiet`                      | Do not warn about weak passwords                              |
| `-v`, `--verbose`                    | Always output the strength of the password                    |
| `-F`, `--fail`                       | Terminate if the password is weak                             |

## Examples

### `-l`, `--length <PASSWORD_LENGTH>`

Create a password of a specific length:

```bash
randpass -l 15
```

### `-u`, `--uppercase`

Create a password that consists only of uppercase letters and digits:

```bash
randpass -u
```

### `-L`, `--lowercase`

Create a password that consists only of lowercase letters and digits:

```bash
randpass -L
```

### `-d`, `--digits`

Create a password that consists only of digits:

```bash
randpass -d
```

### `-s`, `--symbols`

Create a password that consists of all letters, digits, and symbols:

```bash
randpass -s
```

### `-b`, `--base <BASE_CHARSET>`

Create a password using a custom base character set:

```bash
randpass -b 'abc123!@#'
```

The above command produces `1acb@a3b132c#aa3a3@1`. The default character
set includes all alphanumeric characters (A–Z, a–z, and 0–9).

### `-r`, `--regex <REGEX_PATTERN>`

Create a password with characters that match a specific regex pattern:

```bash
randpass -r '[A-Z0-9]'
```

The above command produces `7F3X2EQKMS6R7H1O07AY`.

### `-e`, `--extra <EXTRA_CHARSET>`

Create a password that contains one or more instances of specific
characters:

```bash
randpass -e '!@#$%'
```

The above command produces `O$DqiC@$E#rR#y!I1A%D`. Every letter in the
extra character set will occur at least once.

### `-n`, `--number <PASSWORD_QUANTITY>`

Create multiple passwords at once:

```bash
randpass -n 10
```

### `-f`, `--format <FORMAT_STRING>`

Customize the output format of the password. Use `{}` as a placeholder
for the password:

```bash
randpass -f 'Your password is: {}'
```

Any other text will be included as-is.

[Rust]: https://www.rust-lang.org/
