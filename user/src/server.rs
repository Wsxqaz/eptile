use crate::config::Config;
use crate::commands::Command;
use std::sync::mpsc;


mod tcp;
mod udp;
mod icmp;

pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(config: Config) -> Server {
        Server { config }
    }

    pub fn run(&self) {
        println!("Server is running on port {}", self.config.r_port);
    }
}
