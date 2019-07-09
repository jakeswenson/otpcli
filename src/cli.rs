use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
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
}

#[derive(StructOpt)]
pub enum Command {
    /// Add/Update a new TOTP secret
    #[structopt(name = "add")]
    #[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    AddSecret { name: String, secret: String },
    /// Import an RSAToken into otpcli
    #[structopt(name = "import")]
    #[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    ImportStoken {
        name: String,
        #[structopt(parse(from_os_str))]
        path: PathBuf,
        pin: String,
    },
    /// Add/Update a new TOTP secret
    #[structopt(name = "list")]
    #[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    ListSecrets { prefix: Option<String> },
    /// Add/Update a new TOTP secret
    #[structopt(name = "delete")]
    #[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    DeleteSecret { name: String },
}
