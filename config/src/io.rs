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
}