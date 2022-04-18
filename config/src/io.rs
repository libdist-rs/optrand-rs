use std::fs::File;
use std::io::prelude::*;
use crate::{Node, Reconfig};

impl Node {
    pub fn from_json(filename: String) -> Node {
        let f = File::open(filename).unwrap();
        let c: Node = serde_json::from_reader(f).unwrap();
        c.init()
    }

    pub fn from_toml(filename: String) -> Node {
        let mut buf = String::new();
        let mut f = File::open(filename).unwrap();
        f.read_to_string(&mut buf).unwrap();
        let c: Node = toml::from_str(&buf).unwrap();
        return c.init();
    }

    pub fn from_yaml(filename: String) -> Node {
        let f = File::open(filename).unwrap();
        let c: Node = serde_yaml::from_reader(f).unwrap();
        return c.init();
    }

    pub fn from_bin(filename: String) -> Node {
        let mut buf = Vec::new();
        let mut f = File::open(filename).unwrap();
        f.read_to_end(&mut buf).unwrap();
        let bytes: &[u8] = &buf;
        let c: Node = bincode::deserialize(bytes).unwrap();
        return c.init();
    }

    pub fn update_config(&mut self, ips: Vec<String>)
    {
        let mut idx = 0;
        for ip in ips {
            // For self ip, put 0.0.0.0 with the same port
            if idx == self.id {
                let port: u16 = ip
                    .split(":")
                    .last()
                    .expect("invalid ip found; unable to split at :")
                    .parse()
                    .expect("failed to parse the port after :");
                self.net_map.insert(idx, format!("0.0.0.0:{}", port));
                idx += 1;
                continue;
            }
            // Put others ips in the config
            self.net_map.insert(idx, ip);
            idx += 1;
        }
        log::debug!("Talking to servers: {:?}", self.net_map);
    }

    pub fn write_file(&self, out: OutputType, basename: &str) {
        match out {
            OutputType::JSON => {
                let filename = format!("{}/nodes-{}.json", basename, self.id);
                write_json(filename, self);
            }
            OutputType::Binary => {
                let filename = format!("{}/nodes-{}.dat", basename, self.id);
                write_bin(filename, self);
            }
            OutputType::TOML => {
                let filename = format!("{}/nodes-{}.toml", basename, self.id);
                write_toml(filename, self);
            }
            OutputType::Yaml => {
                let filename = format!("{}/nodes-{}.yml", basename, self.id);
                write_yaml(filename, self);
            }
        }

    }
}

use util::io::*;

#[derive(Debug, Clone, Copy)]
pub enum OutputType {
    JSON,
    TOML,
    Binary,
    Yaml,
}

impl Reconfig {
    pub fn from_json(filename: String) -> Self {
        let f = File::open(filename).unwrap();
        let c: Self = serde_json::from_reader(f).unwrap();
        c.init()
    }

    pub fn from_toml(filename: String) -> Self {
        let mut buf = String::new();
        let mut f = File::open(filename).unwrap();
        f.read_to_string(&mut buf).unwrap();
        let c: Self = toml::from_str(&buf).unwrap();
        return c.init();
    }

    pub fn from_yaml(filename: String) -> Self {
        let f = File::open(filename).unwrap();
        let c: Self = serde_yaml::from_reader(f).unwrap();
        return c.init();
    }

    pub fn from_bin(filename: String) -> Self {
        let mut buf = Vec::new();
        let mut f = File::open(filename).unwrap();
        f.read_to_end(&mut buf).unwrap();
        let bytes: &[u8] = &buf;
        let c: Self = bincode::deserialize(bytes).unwrap();
        return c.init();
    }

    pub fn update_config(&mut self, ips: Vec<String>)
    {
        let mut idx = 0;
        for ip in ips {
            // For self ip, put 0.0.0.0 with the same port
            if idx == self.id {
                let port: u16 = ip
                    .split(":")
                    .last()
                    .expect("invalid ip found; unable to split at :")
                    .parse()
                    .expect("failed to parse the port after :");
                self.net_map.insert(idx, format!("0.0.0.0:{}", port));
                idx += 1;
                continue;
            }
            // Put others ips in the config
            self.net_map.insert(idx, ip);
            idx += 1;
        }
        log::debug!("Talking to servers: {:?}", self.net_map);
    }

    pub fn write_file(&self, out: OutputType, basename: &str) {
        match out {
            OutputType::JSON => {
                let filename = format!("{}/nodes-{}.json", basename, self.id);
                write_json(filename, self);
            }
            OutputType::Binary => {
                let filename = format!("{}/nodes-{}.dat", basename, self.id);
                write_bin(filename, self);
            }
            OutputType::TOML => {
                let filename = format!("{}/nodes-{}.toml", basename, self.id);
                write_toml(filename, self);
            }
            OutputType::Yaml => {
                let filename = format!("{}/nodes-{}.yml", basename, self.id);
                write_yaml(filename, self);
            }
        }

    }
}
