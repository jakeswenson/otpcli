use std::error::Error;
use std::io::prelude::*;

#[cfg(feature = "copy")]
use clipboard::{ClipboardContext, ClipboardProvider};
use structopt::StructOpt;

use cli::{Command, Options};
use otp::{
    self,
    config::{self, Config},
    TotpResult,
};

mod cli;

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Options = Options::from_args();

    let config_dir = config::default_config_dir();
    let config = config::load_config(&config_dir)?;

    match opts.command()? {
        Command::GenerateToken { name } => generate_token(opts, config, name),
        Command::ListSecrets { prefix } => {
            let secrets = otp::list_secrets(config, prefix)?;
            for sec in secrets {
                println!("- {}", sec);
            }
            Ok(())
        }
        Command::AddSecret { name, secret } => {
            otp::add_totp_secret(config, config_dir, &name, secret.replace(" ", ""))?;
            Ok(())
        }
        Command::ImportStoken { name, path, pin } => {
            otp::add_stoken(&config, config_dir, &name, path, &pin)?;
            Ok(())
        }
        Command::DeleteSecret { name } => {
            otp::delete_secret(config, config_dir, name)?;
            Ok(())
        }
        #[cfg(feature = "keychain")]
        Command::UseKeychain => {
            otp::migrate_secrets_to_keychain(config, config_dir)?;
            Ok(())
        }
    }
}

#[cfg(feature = "copy")]
fn copy_to_clipboard(code: &str) -> TotpResult<()> {
    let mut clipboard: ClipboardContext = ClipboardProvider::new()?;
    clipboard.set_contents(code.to_string())?;
    Ok(())
}

#[cfg(not(feature = "copy"))]
fn copy_to_clipboard(_code: &str) -> TotpResult<()> {
    Ok(())
}

fn generate_token(opts: Options, config: Config, name: String) -> TotpResult<()> {
    let code = match otp::token(config, &name) {
        Ok(token) => token,
        Err(e) => {
            println!("Error: {}", e);
            println!(
                "a TOTP config named '{}' was not found, did you add a secret with that name?",
                name
            );
            Options::clap().print_help()?;
            return Ok(());
        }
    };

    if cfg!(feature = "copy") {
        copy_to_clipboard(&code)?;
    }

    if opts.end_with_newline {
        println!("{}", code);
    } else {
        print!("{}", code);
        std::io::stdout().flush()?;
    }

    Ok(())
}
