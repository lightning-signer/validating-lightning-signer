use std::io::Write;
use std::{net::TcpListener, process::Command, time::Duration};
use tempfile::{NamedTempFile, TempDir};

use tokio::time::sleep;

fn get_free_tcp_port() -> u16 {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let free_port = socket.local_addr().unwrap().port();
    free_port
}

#[tokio::test]
async fn rpc_server_test() {
    Command::new("cargo")
        .args(["build", "--bin", "vlsd2"])
        .current_dir("..")
        .status()
        .expect("vlsd2 build failed");

    let tempdir = TempDir::new().expect("temp dir for vlsd");
    let tmp_path = tempdir.path().to_str().unwrap();
    let port = get_free_tcp_port();
    let mut vlsd2_process = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "vlsd2",
            "--",
            "--connect=http://localhost:7701",
            &format!("--datadir={}", tmp_path),
            "--rpc-user=vls",
            "--rpc-pass=bitcoin",
            &format!("--rpc-server-port={}", port),
        ])
        .current_dir("..")
        .spawn()
        .expect("vlsd2 didn't start");

    // required to ensure vls is started and running
    sleep(Duration::from_secs(10)).await;
    let vls_cli_result = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "vls-cli",
            "--",
            "--rpc-user=vls",
            "--rpc-password=bitcoin",
            &format!("--rpc-uri=http://127.0.0.1:{}", port),
            "info",
        ])
        .current_dir("..")
        .output()
        .expect("vls-cli info failed");

    vlsd2_process.kill().expect("vlsd2 couldn't be killed properly");
    let stdout_vls_cli =
        std::str::from_utf8(&vls_cli_result.stdout).expect("error while parsing result");
    assert!(stdout_vls_cli.contains("channels"));
    assert!(stdout_vls_cli.contains("height"));
    assert!(stdout_vls_cli.contains("version"));
}

#[tokio::test]
async fn rpc_server_test_with_cookie() {
    Command::new("cargo")
        .args(["build", "--bin", "vlsd2"])
        .current_dir("..")
        .status()
        .expect("vlsd2 build failed");

    // Create the rpc cookie file
    let cookie_file = NamedTempFile::new().unwrap();
    cookie_file.as_file().write_all(b"user:password").unwrap();
    let cookie_path = cookie_file.path().to_str().unwrap();

    let tempdir = TempDir::new().expect("temp dir for vlsd");
    let tmp_path = tempdir.path().to_str().unwrap();
    let port = get_free_tcp_port();
    // Start the vlsd2 process with the rpc-cookie
    let mut vlsd2_process = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "vlsd2",
            "--",
            "--connect=http://localhost:7701",
            &format!("--datadir={}", tmp_path),
            &format!("--rpc-server-port={}", port),
            "--rpc-cookie",
            cookie_path,
        ])
        .current_dir("..")
        .spawn()
        .expect("vlsd2 didn't start");

    // required to ensure vls is started and running
    sleep(Duration::from_secs(10)).await;
    let vls_cli_result = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "vls-cli",
            "--",
            &format!("--rpc-uri=http://127.0.0.1:{}", port),
            "--rpc-cookie",
            cookie_path,
            "info",
        ])
        .current_dir("..")
        .output()
        .expect("vls-cli info failed");

    vlsd2_process.kill().expect("vlsd2 couldn't be killed properly");
    let stdout_vls_cli =
        std::str::from_utf8(&vls_cli_result.stdout).expect("error while parsing result");
    assert!(stdout_vls_cli.contains("channels"));
    assert!(stdout_vls_cli.contains("height"));
    assert!(stdout_vls_cli.contains("version"));
}
