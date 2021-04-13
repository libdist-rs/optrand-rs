use config::Node;
use util::io::*;

#[derive(Debug, Clone, Copy)]
pub enum OutputType {
    JSON,
    TOML,
    Binary,
    Yaml,
}


pub fn write_file_for_node(out: OutputType, basename: &str, id:usize, config: &Node) {
        match out {
            OutputType::JSON => {
                let filename = format!("{}/nodes-{}.json", basename, id);
                write_json(filename, config);
            }
            OutputType::Binary => {
                let filename = format!("{}/nodes-{}.dat", basename, id);
                write_bin(filename, config);
            }
            OutputType::TOML => {
                let filename = format!("{}/nodes-{}.toml", basename, id);
                write_toml(filename, config);
            }
            OutputType::Yaml => {
                let filename = format!("{}/nodes-{}.yml", basename, id);
                write_yaml(filename, config);
            }
        }
}