use anyhow::{anyhow, Result};
use url::Url;

use crate::types::{LaunchRequest, LaunchTargetKind};

pub fn parse_launch_uri(raw: &str) -> Result<LaunchRequest> {
    let url = Url::parse(raw)?;
    if url.scheme() != "eguard-ztna" {
        return Err(anyhow!("unsupported_scheme"));
    }
    let action = url.host_str().unwrap_or_default();
    if action != "launch" {
        return Err(anyhow!("unsupported_action"));
    }
    let mut app_id = String::new();
    let mut name = String::new();
    let mut host = String::new();
    let mut raw_type = String::new();
    let mut username = None;
    let mut path = None;
    let mut absolute_url = None;
    let mut port = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "app_id" => app_id = value.into_owned(),
            "name" => name = value.into_owned(),
            "host" => host = value.into_owned(),
            "type" => raw_type = value.into_owned(),
            "username" => username = Some(value.into_owned()),
            "path" => path = Some(value.into_owned()),
            "url" => absolute_url = Some(value.into_owned()),
            "port" => port = value.parse::<u16>().ok(),
            _ => {}
        }
    }
    let kind =
        LaunchTargetKind::parse(&raw_type).ok_or_else(|| anyhow!("unsupported_launch_type"))?;
    if absolute_url.is_none() && host.trim().is_empty() {
        return Err(anyhow!("launch_host_required"));
    }
    Ok(LaunchRequest {
        app_id,
        name,
        kind,
        host,
        port,
        username,
        path,
        url: absolute_url,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_launch_uri;
    use crate::LaunchTargetKind;

    #[test]
    fn parses_launch_uri() {
        let req = parse_launch_uri("eguard-ztna://launch?type=ssh&host=10.0.0.10&port=22&username=admin&app_id=app-1&name=SSH").expect("parse uri");
        assert_eq!(req.kind, LaunchTargetKind::Ssh);
        assert_eq!(req.host, "10.0.0.10");
        assert_eq!(req.port, Some(22));
        assert_eq!(req.username.as_deref(), Some("admin"));
    }
}
