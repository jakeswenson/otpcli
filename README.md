# OTP Cli
[![Crates.io](https://img.shields.io/crates/v/otpcli.svg?style=for-the-badge)](https://crates.io/crates/otpcli)
[![Build Status](https://img.shields.io/github/workflow/status/jakeswenson/otpcli/Build?style=flat-square)]()

A one time password library and CLI tool for generating time-based one time passwords.
Also supports RSA Secure tokens (using the rust stoken library)

## Installing
You can install with `cargo`

```bash
cargo install otpcli
```

## Features
- **[DEFAULT]** `copy`: build with copy to [clipboard](https://crates.io/crates/clipboard) support. Adds a `--copy` option 
- **[DEFAULT]** `keychain`: build with secure secret storage support using [`keyring`](https://crates.io/crates/keyring)

The `copy` feature uses [clipboard](https://crates.io/crates/clipboard) 
and that requires a X11 on linux to access the clipboard

## CLI

```bash
A simple one-time-password CLI, with support for TOTP and STOKEN.

USAGE:
    otpcli [FLAGS] [name] [SUBCOMMAND]

FLAGS:
        --copy       Copies the generated token to the clipboard
    -n, --newline    Adds a newline printed at the end out output
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose

ARGS:
    <name>    The name of the totp token to generate

SUBCOMMANDS:
    add                    Add/Update a new TOTP secret
    delete                 Add/Update a new TOTP secret
    generate               Generate a token
    help                   Prints this message or the help of the given subcommand(s)
    import                 Import an RSAToken into otpcli
    list                   Add/Update a new TOTP secret
    migrate-to-keychain    Migrate secrets stored in the config to be stored in the keychain
```


