use std::error::Error;
use std::io::prelude::*;

use structopt::StructOpt;

use cli::{Command, Options};
use otp::{self, config::{self, Config}};

mod cli;

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Options::from_args();

    let config_dir = config::default_config_dir();
    let config = config::load_config(&config_dir)?;

    match opts.cmd {
        Some(Command::AddSecret { name, secret }) => {
            otp::add_totp_secret(config, config_dir, name, secret.replace(" ", ""))?;
            Ok(())
        }
        Some(Command::ImportStoken { name, path, pin }) => {
            let token = stoken::read_file(path);
            let token = stoken::RSAToken::from_xml(token, &pin);
            let exported_token = stoken::export::export(token).expect("Unable to export RSA Token");
            otp::add_secret(config, config_dir, name, exported_token, otp::TokenAlgorithm::SToken)?;
            Ok(())
        }
        Some(Command::ListSecrets { prefix }) => {
            let secrets = otp::list_secrets(config, prefix)?;
            for sec in secrets {
                println!("- {}", sec);
            }
            Ok(())
        }
        Some(Command::DeleteSecret { name }) => {
            otp::delete_secret(config, config_dir, name)?;
            Ok(())
        }
        None => generate_token(opts, config)
    }
}

fn generate_token(opts: Options, config: Config) -> Result<(), Box<dyn Error>> {
    let name: Option<String> = opts.name;
    if name.is_none() {
        println!("TOTP name not provided");
        Options::clap().print_help()?;
        return Ok(());
    }

    let name = name.unwrap();

    let code = match otp::token(config, &name) {
        Some(token) => token,
        None => {
            println!("a TOTP config named `{}` was not found, did you add a secret with that name?", name);
            Options::clap().print_help()?;
            return Ok(());
        }
    };

    if opts.end_with_newline {
        println!("{}", code);
    } else {
        print!("{}", code);
        std::io::stdout().flush()?;
    }
    Ok(())
}
