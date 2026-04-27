#[derive(Debug, Clone, Default)]
pub struct SshLaunchRequest {
    pub target: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub launcher: Option<String>,
    pub password: Option<String>,
    pub private_key_pem: Option<String>,
    pub passphrase: Option<String>,
}
