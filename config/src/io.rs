use std::fs::File;
use std::io::prelude::*;
use crate::Node;

impl Node {
    pub fn from_json(filename: String) -> Node {
        let f = File::open(filename).unwrap();
        let c: Node = serde_json::from_reader(f).unwrap();
        return c.init();
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
}