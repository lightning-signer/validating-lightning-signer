use log::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
#[cfg(feature = "main")]
use std::path::Path;
use std::path::PathBuf;
use std::{env, fs};

/// Compare environment variable to a value
pub fn compare_env_var(name: &str, value: &str) -> bool {
    match env::var(name) {
        Ok(val) => val == value,
        Err(_) => false,
    }
}

pub fn line_filter(line: &str) -> Option<String> {
    let whitespace_removed = line.trim();
    if whitespace_removed.is_empty() {
        return None;
    }
    let comment_removed = whitespace_removed.split('#').next()?.trim();
    if comment_removed.is_empty() {
        return None;
    }
    Some(comment_removed.to_string())
}

pub fn read_allowlist() -> Vec<String> {
    if let Ok(allowlist_path) = env::var("REMOTE_SIGNER_ALLOWLIST") {
        return read_allowlist_path(&allowlist_path);
    }
    Vec::new()
}

pub fn read_allowlist_path(path: &str) -> Vec<String> {
    let file = File::open(path).expect(format!("open {} failed", path).as_str());
    let allowlist: Vec<String> =
        BufReader::new(file).lines().filter_map(|l| line_filter(&l.expect("line"))).collect();

    allowlist
}

/// Determine if we should auto approve payments
pub fn should_auto_approve() -> bool {
    if compare_env_var("VLS_PERMISSIVE", "1") {
        warn!("VLS_PERMISSIVE: ALL INVOICES, KEYSENDS, AND PAYMENTS AUTOMATICALLY APPROVED");
        return true;
    }

    if compare_env_var("VLS_AUTOAPPROVE", "1") {
        warn!("VLS_AUTOAPPROVE: ALL INVOICES, KEYSENDS, AND PAYMENTS AUTOMATICALLY APPROVED");
        return true;
    }

    info!("VLS_ENFORCING: ALL INVOICES, KEYSENDS, AND PAYMENTS REQUIRE APPROVAL");
    false
}

/// Abort on panic.
/// Use this instead of `panic = abort` in Cargo.toml, which doesn't show
/// nice backtraces.
pub fn abort_on_panic() {
    let old = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        old(info);
        std::process::abort();
    }));
}

#[cfg(feature = "main")]
pub fn setup_logging<P: AsRef<Path>>(datadir: P, who: &str, level_arg: &str) {
    use fern::colors::{Color, ColoredLevelConfig};
    use std::str::FromStr;

    // Should we support seperate console and file log levels?
    let level = env::var("RUST_LOG").unwrap_or(level_arg.to_string());

    // file
    let who_clone = who.to_string();
    let logfile = datadir.as_ref().join(format!("{}.log", who));
    let file_config = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                tstamp(),
                who_clone,
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::from_str(&level).expect("level"))
        .level_for("h2", log::LevelFilter::Info)
        .chain(fern::log_file(logfile).expect("file log config"));

    // console
    let who_clone = who.to_string();
    let colors = ColoredLevelConfig::new().info(Color::Green).error(Color::Red).warn(Color::Yellow);
    let console_config = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}/{} {}] {}",
                tstamp(),
                who_clone,
                record.target(),
                colors.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::from_str(&level).expect("level"))
        .level_for("h2", log::LevelFilter::Info)
        .chain(std::io::stdout());

    fern::Dispatch::new().chain(console_config).chain(file_config).apply().expect("log config");
}

// Would prefer to use now_local but https://rustsec.org/advisories/RUSTSEC-2020-0071
// Also, https://time-rs.github.io/api/time/struct.OffsetDateTime.html#method.now_local
#[cfg(feature = "main")]
pub fn tstamp() -> String {
    use time::{macros::format_description, OffsetDateTime};

    OffsetDateTime::now_utc()
        .format(format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
        ))
        .expect("formatted tstamp")
}

pub fn read_integration_test_seed<P: AsRef<Path>>(datadir: P) -> Option<[u8; 32]> {
    let path = PathBuf::from(datadir.as_ref()).join("hsm_secret");
    tracing::warn!("reading integration hsm_secret from {:?}", path);
    let result = fs::read(path);
    if let Ok(data) = result {
        Some(
            data.as_slice().try_into().unwrap_or_else(|_| {
                panic!("Expected hsm_secret to be 32 bytes, got {}", data.len())
            }),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn line_filter_test() {
        assert_eq!(line_filter("#"), None);
        assert_eq!(
            line_filter("tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z # comment"),
            Some("tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string())
        );
        assert_eq!(line_filter("   "), None);
        assert_eq!(line_filter("   #   "), None);
        assert_eq!(
            line_filter("   tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z   "),
            Some("tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string())
        );
    }

    #[test]
    fn read_allowlist_test() {
        let test_file_content = "\
        # Sample Allowlist
        tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z
        tb1qexampleaddress1234567890123456789012345678

        # Another comment line after blank line
    ";
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        write!(temp_file, "{}", test_file_content).unwrap();
        let allowlist = read_allowlist_path(temp_file.path().to_str().unwrap());
        assert_eq!(
            allowlist,
            vec![
                "tb1qhetd7l0rv6kca6wvmt25ax5ej05eaat9q29z7z".to_string(),
                "tb1qexampleaddress1234567890123456789012345678".to_string(),
            ]
        );
        temp_file.close().unwrap();
    }
}
