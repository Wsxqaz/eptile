#[derive(Debug, Default)]
pub struct Config {
    pub l_host: String,
    pub l_port: u16,
    pub r_host: String,
    pub r_port: u16,
    pub src_host: String,
    pub src_port: u16,
    pub protocol: String,
    pub password: String,
    pub token: String,
}

impl Config {
    pub fn new() -> Config { Default::default() }
}
