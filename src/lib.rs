mod cli;
mod commands;
mod gateway;
mod models;
mod runtime;

use clap::Parser;

pub fn run() -> i32 {
    let cli = cli::Cli::parse();
    match commands::execute(cli.command) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("error: {err}");
            2
        }
    }
}
