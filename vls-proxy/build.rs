use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn update_version() {
    let git_desc = match Command::new("git")
        .args(&["describe", "--tags", "--long", "--always", "--match=v*.*", "--dirty"])
        .output()
    {
        Ok(output) =>
            if output.status.success() {
                String::from_utf8(output.stdout)
                    .unwrap_or("git-desc-badstr".to_string())
                    .trim_end()
                    .to_string()
            } else {
                "git-desc-error".to_string()
            },
        Err(_) => "git-desc-failed".to_string(),
    };
    let version_source = format!("pub const GIT_DESC: &'static str = \"{}\";\n", git_desc);
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let version_path = Path::new(&out_dir).join("version.rs");
    let old_version_source =
        String::from_utf8(fs::read(&version_path).unwrap_or(vec![])).unwrap_or("".to_string());
    if version_source != old_version_source {
        fs::write(&version_path, version_source).unwrap();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    update_version();
    tonic_build::configure()
        .build_server(true)
        .out_dir("src/grpc")
        .compile(&["src/grpc/hsmd.proto"], &["src/grpc"])?;
    Ok(())
}
