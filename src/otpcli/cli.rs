#[cfg(feature = "ras_stoken")]
use std::path::PathBuf;

use otp::{TotpError, TotpResult};
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
pub struct Options {
    #[structopt(subcommand)]
    pub cmd: Option<Command>,

    /// The name of the totp token to generate
    #[structopt(name = "name")]
    pub name: Option<String>,

    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbosity: u8,

    /// Adds a newline printed at the end out output
    #[structopt(short = "n", long = "newline")]
    pub end_with_newline: bool,

    /// Copies the generated token to the clipboard
    #[cfg(feature = "copy")]
    #[structopt(long = "copy")]
    pub copy_to_clipboard: bool,
}

impl Options {
    #[cfg(feature = "copy")]
    pub fn copy_to_clipboard(&self) -> bool {
        self.copy_to_clipboard
    }
}

#[derive(StructOpt, Clone)]
pub enum Command {
    /// Add/Update a new TOTP secret
    #[structopt(name = "add")]
    #[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
    AddSecret { name: String, secret: String },
    /// Import an RSAToken into otpcli
    #[cfg(feature = "ras_stoken")]
    #[structopt(name = "import")]
    #[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
    ImportStoken {
        name: String,
        #[structopt(parse(from_os_str))]
        path: PathBuf,
        pin: String,
    },
    /// Add/Update a new TOTP secret
    #[structopt(name = "list")]
    #[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
    ListSecrets { prefix: Option<String> },
    /// Add/Update a new TOTP secret
    #[structopt(name = "delete")]
    #[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
    DeleteSecret { name: String },
    /// Migrate secrets stored in the config to be stored in the keychain
    #[cfg(feature = "keychain")]
    #[structopt(name = "migrate-to-keychain")]
    #[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
    UseKeychain,
    /// Generate a token
    #[structopt(name = "generate")]
    #[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
    GenerateToken { name: String },
}

impl Options {
    pub fn command(&self) -> TotpResult<Command> {
        if self.name.is_none() && self.cmd.is_none() {
            println!("Missing either a Command or TOTP token name to generate");
            Options::clap().print_help()?;
            return Err(Box::new(TotpError::of(
                "No command or TOTP token name provided",
            )));
        }

        Ok(self.cmd.clone().unwrap_or_else(|| Command::GenerateToken {
            name: self.name.clone().unwrap(),
        }))
    }
}
