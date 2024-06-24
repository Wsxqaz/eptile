#![allow(unused)]

mod config;
mod client;
mod server;
mod commands;

use clap::{Arg, ArgAction, Command};

fn main() {
    let matches = Command::new("eptile")
        .version("0.1.0")
        .author("wsxqaz")
        .about("reptile parrot")
        .subcommand(
            Command::new("client")
                .about("run the listener and send magic packet")
        )
        .subcommand(
            Command::new("server")
                .about("run the server and listen the magic packet")
        )
        .get_matches();

    match matches.subcommand() {
        Some(("client", _)) => {
            let config = config::Config::new();
            let client = client::Client::new(config);
            client.run();
        }
        Some(("server", _)) => {
            let config = config::Config::new();
            let server = server::Server::new(config);
            server.run();
        }
        _ => {
            println!("No subcommand was used");
        }
    }
}
