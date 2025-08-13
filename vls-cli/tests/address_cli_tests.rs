use std::{net::TcpListener, process::Command, time::Duration};
use tempfile::TempDir;

use tokio::{fs, io::AsyncWriteExt, time::sleep};

fn get_free_tcp_port() -> u16 {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let free_port = socket.local_addr().unwrap().port();
    free_port
}

async fn start_test_vlsd(port: u16, tempdir: &TempDir) -> std::process::Child {
    let datadir = tempdir.path().join("vlsd");
    fs::create_dir(&datadir).await.unwrap();
    let node_network_dir = tempdir.path().join("regtest");
    fs::create_dir(&node_network_dir).await.unwrap();
    let mut secret_file = fs::File::create(node_network_dir.join("hsm_secret")).await.unwrap();
    secret_file.write_all(&[42; 32]).await.unwrap();
    Command::new("cargo")
        .args(["build", "--bin", "vlsd"])
        .current_dir("..")
        .status()
        .expect("vlsd build failed");

    let vlsd_process = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "vlsd",
            "--",
            "--connect=http://localhost:7701",
            &format!("--datadir={}", datadir.to_str().unwrap()),
            "--network=regtest",
            "--integration-test",
            "--rpc-user=vls",
            "--rpc-pass=bitcoin",
            &format!("--rpc-server-port={}", port),
        ])
        .current_dir("..")
        .spawn()
        .expect("vlsd didn't start");

    // Wait for vlsd to start up
    sleep(Duration::from_secs(10)).await;
    vlsd_process
}

fn run_vls_cli_command(port: u16, args: &[&str]) -> std::process::Output {
    let rpc_uri = format!("--rpc-uri=http://127.0.0.1:{}", port);
    let mut full_args =
        vec!["run", "--bin", "vls-cli", "--", "--rpc-user=vls", "--rpc-password=bitcoin", &rpc_uri];
    full_args.extend(args);

    Command::new("cargo")
        .args(full_args)
        .current_dir("..")
        .output()
        .expect("vls-cli command failed")
}

#[tokio::test]
async fn test_addresses_list_basic() {
    let tempdir = TempDir::new().expect("temp dir for vlsd");
    let port = get_free_tcp_port();
    let mut vlsd_process = start_test_vlsd(port, &tempdir).await;

    let result = run_vls_cli_command(port, &["addresses", "list"]);

    vlsd_process.kill().expect("vlsd couldn't be killed properly");
    assert!(result.status.success());

    let stdout = std::str::from_utf8(&result.stdout).expect("stdout should be in utf8 encoding");
    assert!(
        stdout.to_ascii_lowercase().contains("address")
            && stdout.to_ascii_lowercase().contains("path"),
    );
}

#[tokio::test]
async fn test_addresses_list_with_types() {
    let tempdir = TempDir::new().expect("temp dir for vlsd");
    let port = get_free_tcp_port();
    let mut vlsd_process = start_test_vlsd(port, &tempdir).await;

    let result = run_vls_cli_command(
        port,
        &["addresses", "list", "--address-type", "taproot", "--start", "6"],
    );

    vlsd_process.kill().expect("vlsd couldn't be killed properly");

    assert!(result.status.success(),);
    let stdout = std::str::from_utf8(&result.stdout).expect("error parsing stdout");
    assert!(stdout.contains("bcrt1p0wf4ew625p284scun2w7czuszph66nmnfldu47eneg7p30663pdswmd4c7"));
    assert!(stdout.contains("\"path\": \"6\""));
    assert!(!stdout.contains("\"path\": \"3\""));
    assert!(stdout.to_ascii_lowercase().contains("taproot"));
}

#[tokio::test]
async fn test_addresses_verify_basic() {
    let tempdir = TempDir::new().expect("temp dir for vlsd");
    let port = get_free_tcp_port();
    let mut vlsd_process = start_test_vlsd(port, &tempdir).await;

    let result = run_vls_cli_command(
        port,
        &[
            "addresses",
            "verify",
            "--address",
            "bcrt1p0wf4ew625p284scun2w7czuszph66nmnfldu47eneg7p30663pdswmd4c7",
        ],
    );

    vlsd_process.kill().expect("vlsd couldn't be killed properly");

    let stdout = std::str::from_utf8(&result.stdout).expect("error parsing stdout");
    assert!(stdout.contains("\"path\": \"6\""));
    assert!(stdout.contains("\"valid\": true"))
}

#[tokio::test]
async fn test_addresses_verify_invalid_address() {
    let tempdir = TempDir::new().expect("temp dir for vlsd");
    let port = get_free_tcp_port();
    let mut vlsd_process = start_test_vlsd(port, &tempdir).await;

    let result = run_vls_cli_command(
        port,
        &["addresses", "verify", "--address", "invalid_address_format", "--limit", "1"],
    );

    let stderr = std::str::from_utf8(&result.stderr).expect("error parsing stdout");
    assert!(stderr.contains("invalid address"));

    let result_incorrect_network = run_vls_cli_command(
        port,
        &[
            "addresses",
            "verify",
            "--address",
            "bc1pq0vlsqw5rdyq3c5tvecjsfqm0kuvsaff4dvg5p66cxa3z7z8zyssp4s29k",
            "--limit",
            "1",
        ],
    );

    let stderr_network =
        std::str::from_utf8(&result_incorrect_network.stderr).expect("error parsing stdout");
    assert!(stderr_network.contains("address on wrong network:"));

    vlsd_process.kill().expect("vlsd couldn't be killed properly");
}
