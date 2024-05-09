use std::{process::Command, time::Duration};

use tokio::time::sleep;

#[tokio::test]
async fn rpc_server_test() {
    Command::new("cargo")
        .args(["build", "--bin", "vlsd2"])
        .current_dir("..")
        .status()
        .expect("vlsd2 build failed");

    let mut vlsd2_process = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "vlsd2",
            "--",
            "--connect=http://localhost:7701",
            "--rpc-user=vls",
            "--rpc-pass=bitcoin",
        ])
        .current_dir("..")
        .spawn()
        .expect("vlsd2 didn't start");

    // required to ensure vls is started and running
    sleep(Duration::from_secs(10)).await;
    let vls_cli_result = Command::new("cargo")
        .args(["run", "--bin", "vls-cli", "--", "--rpc-user=vls", "--rpc-password=bitcoin", "info"])
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
