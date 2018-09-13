extern crate structopt;

#[derive(StructOpt)]
#[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
pub struct Options {
    #[structopt(subcommand)]
    pub cmd: Option<Command>,

    #[structopt(name = "name")]
    /// The name of the totp token to generate
    pub name: Option<String>,

    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbosity: u8,

    #[structopt(short = "n", long = "newline")]
    /// Adds a newline should be printed at the end
    pub end_with_newline: bool,
}

#[derive(StructOpt)]
pub enum Command {
    #[structopt(name = "add")]
    /// Add/Update a new TOTP secret
    #[structopt(raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    AddSecret {
        name: String,
        secret: String,
    },
}