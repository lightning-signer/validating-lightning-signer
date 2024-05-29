use anyhow::Result;
use std::path::PathBuf;

/// Get the rpc username and password from the provided arguments.
pub fn get_rpc_credentials(
    rpc_username: Option<String>,
    rpc_password: Option<String>,
    rpc_cookie: Option<PathBuf>,
) -> Result<(String, String)> {
    match (rpc_username, rpc_password, rpc_cookie) {
        (Some(user), Some(password), None) => Ok((user, password)),
        (_, _, Some(cookie)) => {
            let contents = match std::fs::read_to_string(cookie) {
                Ok(contents) => contents,
                Err(e) => {
                    eprintln!("Error reading rpc cookie file: {}", e);
                    std::process::exit(1);
                }
            };
            let mut split = contents.splitn(2, ":");
            let user = split
                .next()
                .ok_or(anyhow::anyhow!("rpc_cookie file must contain a username and password"))?;
            let password = split
                .next()
                .ok_or(anyhow::anyhow!("rpc_cookie file must contain a username and password"))?;

            Ok((user.to_string(), password.to_string()))
        }
        _ => {
            anyhow::bail!("rpc_username and rpc_password must be set, or rpc_cookie must be set");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_rpc_username_password() {
        let rpc_username = Some("user".to_string());
        let rpc_password = Some("password".to_string());
        let rpc_cookie = None;
        assert_eq!(
            get_rpc_credentials(rpc_username, rpc_password, rpc_cookie).unwrap(),
            ("user".to_string(), "password".to_string())
        );

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "user:password").unwrap();
        let rpc_cookie = Some(temp_file.path().to_path_buf());
        let rpc_username = None;
        let rpc_password = None;
        assert_eq!(
            get_rpc_credentials(rpc_username, rpc_password, rpc_cookie).unwrap(),
            ("user".to_string(), "password".to_string())
        );

        let rpc_username = Some("user".to_string());
        let rpc_password = None;
        let rpc_cookie = None;
        assert!(get_rpc_credentials(rpc_username, rpc_password, rpc_cookie).is_err());

        let rpc_username = None;
        let rpc_password = Some("password".to_string());
        let rpc_cookie = None;
        assert!(get_rpc_credentials(rpc_username, rpc_password, rpc_cookie).is_err());

        let rpc_username = None;
        let rpc_password = None;
        let rpc_cookie = None;
        assert!(get_rpc_credentials(rpc_username, rpc_password, rpc_cookie).is_err());
    }
}
