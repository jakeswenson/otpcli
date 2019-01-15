use structopt::StructOpt;

use otp::{self, config};

mod cli;

fn main() -> Result<(), std::io::Error> {
    let opts = cli::Options::from_args();

    let config_dir = config::default_config_dir();
    let config = config::load_config(&config_dir)?;

    match opts.cmd {
        Some(cli::Command::AddSecret { name, secret }) => {
            otp::add_totp_secret(config, config_dir, name, secret.replace(" ", ""))
        }
        Some(cli::Command::ImportStoken { name, path, pin }) => {
            let token = stoken::read_file(path);
            let token = stoken::RSAToken::from_xml(token, &pin);
            let exported_token = stoken::export::export(token).expect("Unable to export RSA Token");
            otp::add_secret(config, config_dir, name, exported_token, otp::TokenAlgorithm::SToken)
        }
        Some(cli::Command::ListSecrets { prefix }) => {
            let secrets = otp::list_secrets(config, prefix)?;
            for sec in secrets {
                println!("- {}", sec);
            }
            Ok(())
        }
        Some(cli::Command::DeleteSecret { name }) => {
            otp::delete_secret(config, config_dir, name)?;
            Ok(())
        }
        None => {
            let name: Option<String> = opts.name;
            if name.is_none() {
                println!("TOTP name not provided");
                cli::Options::clap().print_help().ok();
                return Ok(());
            }

            let name = name.unwrap();

            let code = match otp::token(config, &name) {
                Some(token) => token,
                None => {
                    println!("a TOTP config named `{}` was not found, did you add a secret with that name?", name);
                    cli::Options::clap().print_help().ok();
                    return Ok(());
                }
            };

            if opts.end_with_newline {
                println!("{}", code);
            } else {
                print!("{}", code);
                use std::io::prelude::*;
                std::io::stdout().flush()?;
            }
            Ok(())
        }
    }
}
