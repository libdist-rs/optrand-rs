use clap::{load_yaml, App};
use config::Node;

pub fn load_config() -> Node {
    let yaml = load_yaml!("cli.yml");
    let m = App::from_yaml(yaml).get_matches();

    let conf_str = m
        .value_of("config")
        .expect("unable to convert config file into a string");
    let conf_file = std::path::Path::new(conf_str);
    let str = String::from(conf_str);
    let mut config = match conf_file
        .extension()
        .expect("Unable to get file extension")
        .to_str()
        .expect("Failed to convert the extension into ascii string")
    {
        "json" => Node::from_json(str),
        "dat" => Node::from_bin(str),
        "toml" => Node::from_toml(str),
        "yaml" => Node::from_yaml(str),
        _ => panic!("Invalid config file extension"),
    };
    config.validate().expect("The decoded config is not valid");

    if let Some(d) = m.value_of("delta") {
        config.delta = d.parse().unwrap();
    }
    if let Some(f) = m.value_of("ip") {
        config.update_config(util::io::file_to_ips(f.to_string()));
    }

    simple_logger::SimpleLogger::new().init().unwrap();
    let x = m.occurrences_of("debug");
    match x {
        0 => log::set_max_level(log::LevelFilter::Off),
        1 => log::set_max_level(log::LevelFilter::Error),
        2 => log::set_max_level(log::LevelFilter::Warn),
        3 => log::set_max_level(log::LevelFilter::Info),
        4 => log::set_max_level(log::LevelFilter::Debug),
        5 | _ => log::set_max_level(log::LevelFilter::Trace),
    }
    unsafe {
        config_lc::SLEEP_TIME = 10 + 4 * config.num_nodes as u64;
    }

    log::debug!("{:?}", config.net_map);
    config
}