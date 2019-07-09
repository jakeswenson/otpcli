use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use serde::{self, Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub totp: std::collections::HashMap<String, TotpOptions>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TotpOptions {
    pub secret: String,
    pub algorithm: Option<super::TokenAlgorithm>,
}

impl Config {
    pub fn lookup(&self, name: &str) -> Option<&TotpOptions> {
        self.totp.get(name)
    }
}

pub fn load_config(config_dir: &std::path::PathBuf) -> io::Result<Config> {
    let config_path = config_dir.join("config.toml");

    let meta_data = match std::fs::metadata(&config_path) {
        Ok(md) => md,
        Err(_e) => return Ok(Config { totp: HashMap::new() })
    };

    let config: Config = if meta_data.is_file() {
            let config = std::fs::read_to_string(config_path)?;
            toml::from_str(&config).expect("Unable to read config as TOML")
        }
        else { Config { totp: std::collections::HashMap::new() } };

    Ok(config)
}

fn make_config_dir(config_dir: &PathBuf) -> io::Result<()> {
    println!("creating config dir: {:?}", config_dir);
    std::fs::create_dir_all(config_dir)
}

pub fn default_config_dir() -> std::path::PathBuf {
    let home_dir = dirs::home_dir().expect("Can't load users home directory");
    home_dir.join(".config").join("otpcli")
}

pub fn ensure_config_dir(config_dir: &PathBuf) -> io::Result<()> {
    match std::fs::metadata(config_dir) {
        Err(_) => make_config_dir(config_dir),
        Ok(ref md) if !md.is_dir() => make_config_dir(config_dir),
        Ok(_) => Ok(())
    }
}
