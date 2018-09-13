extern crate base32;
#[macro_use]
extern crate structopt;

use std::io::prelude::*;
use structopt::StructOpt;

extern crate otpcli;

mod cli;

fn main() -> Result<(), std::io::Error> {
    let opts = cli::Options::from_args();

    let home_dir = std::env::home_dir().expect("Can't load users home directory");
    let config_dir = home_dir.join(".config").join("otpcli");

    let config = otpcli::load_config(&config_dir)?;

    match opts.cmd {
        Some(cli::Command::AddSecret { name, secret }) => {
            otpcli::add_secret(config, config_dir, name, secret)
        }
        None => {
            let name: Option<String> = opts.name;
            if name.is_none() {
                println!("TOTP name not provided");
                cli::Options::clap().print_help().ok();
                return Ok(());
            }

            let code = otpcli::generate_totp(config, name.unwrap());

            if opts.end_with_newline {
                println!("{}", code);
                Ok(())
            } else {
                print!("{}", code);
                std::io::stdout().flush()
            }
        }
    }
}
