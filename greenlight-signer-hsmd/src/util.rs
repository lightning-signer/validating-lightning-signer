use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use std::{env, fs};

pub fn read_allowlist() -> Vec<String> {
    let allowlist_path_res = env::var("ALLOWLIST");
    if let Ok(allowlist_path) = allowlist_path_res {
        let file =
            File::open(&allowlist_path).expect(format!("open {} failed", &allowlist_path).as_str());
        BufReader::new(file).lines().map(|l| l.expect("line")).collect()
    } else {
        Vec::new()
    }
}

pub fn read_integration_test_seed() -> Option<[u8; 32]> {
    let result = fs::read("hsm_secret");
    if let Ok(data) = result {
        Some(data.as_slice().try_into().expect("hsm_secret wrong length"))
    } else {
        None
    }
}

pub fn setup_logging(who: &str, level: &str) {
    use fern::colors::{Color, ColoredLevelConfig};
    let colors = ColoredLevelConfig::new().info(Color::Green).error(Color::Red).warn(Color::Yellow);
    let who = who.to_string();
    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                who,
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::from_str(level).expect("level"))
        .level_for("h2", log::LevelFilter::Info)
        .level_for("sled", log::LevelFilter::Info)
        .chain(std::io::stdout())
        // .chain(fern::log_file("/tmp/output.log")?)
        .apply()
        .expect("log config");
}
