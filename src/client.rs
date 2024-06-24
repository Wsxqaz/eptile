use crate::config::Config;
use crate::commands::Command;

mod tcp;
mod udp;
mod icmp;

pub struct Client {
    config: Config,
}

impl Client {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn send(&self, command: Command) {}

    pub fn run(&self) {
        println!("Running client with config: {:?}", self.config);
    }
}
