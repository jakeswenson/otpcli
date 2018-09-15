extern crate otpcli;
#[macro_use]
extern crate structopt;

use std::io::prelude::*;
use structopt::StructOpt;

mod cli;

fn main() -> Result<(), std::io::Error> {
    let opts = cli::Options::from_args();

    let config_dir = otpcli::default_config_dir();
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

            let name = name.unwrap();

            let code = otpcli::standard_totp(config, &name)
                .expect(&format!("a TOTP config named `{}` was not found, did you add a secret with that name?", name));

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
