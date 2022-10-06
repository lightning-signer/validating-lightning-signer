use std::process::Command;

fn main() {
    let git_desc = match Command::new("git")
        .args(&["describe", "--tags", "--long", "--always", "--match=v*.*", "--dirty"])
        .output()
    {
        Ok(output) =>
            if output.status.success() {
                String::from_utf8(output.stdout).unwrap_or("git-desc-badstr".to_string())
            } else {
                "git-desc-error".to_string()
            },
        Err(_) => "git-desc-failed".to_string(),
    };
    println!("cargo:rustc-env=GIT_DESC={}", git_desc);
}
