//! Matrix server discovery. Only validated authorities are used in HTTPS URLs.
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ResolvedServer {
    pub host: String,
    pub port: u16,
}

pub fn is_valid_server_name(value: &str) -> bool {
    let Ok(server) = <&ruma::ServerName>::try_from(value) else {
        return false;
    };
    let host = server.host();
    // HTTP URL parsers interpret integer, hexadecimal, octal and shortened IPv4
    // names as IP literals. Reject those aliases so ACLs and the connector use
    // the same server identity and IP classification.
    let Ok(url) = reqwest::Url::parse(&format!("https://{value}")) else {
        return false;
    };
    let normalized_host = url
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let original_host = host.trim_start_matches('[').trim_end_matches(']');
    if normalized_host.parse::<std::net::IpAddr>().is_ok()
        && original_host.parse::<std::net::IpAddr>().is_err()
    {
        return false;
    }
    !host.is_empty()
        && value.len() <= 255
        && server.port() != Some(0)
        && (host.starts_with('[')
            || host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            }))
}

fn parse_server(server_name: &str) -> Result<ResolvedServer, String> {
    if !is_valid_server_name(server_name) {
        return Err("Invalid Matrix server name".into());
    }
    let server = <&ruma::ServerName>::try_from(server_name).map_err(|e| e.to_string())?;
    // URL parsers also accept shortened/octal/integer IPv4 spellings. Validate
    // their normalized host, since an IP literal bypasses the DNS resolver.
    let url = reqwest::Url::parse(&format!("https://{server_name}")).map_err(|e| e.to_string())?;
    let host = url
        .host_str()
        .ok_or("Missing federation host")?
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| !is_public_ip(ip))
    {
        return Err("Federation destination must be a public address".into());
    }
    Ok(ResolvedServer {
        host: server.host().to_owned(),
        port: server.port().unwrap_or(8448),
    })
}

pub async fn resolve_server_name(server_name: &str) -> Result<ResolvedServer, String> {
    let direct = parse_server(server_name)?;
    let server = <&ruma::ServerName>::try_from(server_name).map_err(|e| e.to_string())?;
    if server.port().is_some() || server.is_ip_literal() {
        return Ok(direct);
    }
    Ok(try_well_known(server_name).await.unwrap_or(direct))
}

/// No redirects: discovery must not silently change the HTTPS trust authority.
pub fn http_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(std::sync::Arc::new(PublicDns))
        .build()
        .map_err(|e| e.to_string())
}

/// Resolve once, validate the actual addresses, and hand the pinned answers to the
/// HTTP connector. Checking a hostname separately would permit DNS rebinding.
struct PublicDns;
impl reqwest::dns::Resolve for PublicDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Non-public federation address",
                )
                .into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0 && c == 0)
                && !(a == 198 && (b == 18 || b == 19))
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ip(mapped.into());
            }
            let segments = ip.segments();
            // Permit global unicast only; exclude documentation and protocol
            // transition ranges which can tunnel to private IPv4 destinations.
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] < 0x0200 || segments[1] == 0x0db8))
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}

async fn try_well_known(server_name: &str) -> Option<ResolvedServer> {
    let client = http_client(Duration::from_secs(5)).ok()?;
    let resp = client
        .get(format!("https://{server_name}/.well-known/matrix/server"))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json = bounded_json(resp).await.ok()?;
    parse_server(json.get("m.server")?.as_str()?).ok()
}

pub async fn bounded_json(mut response: reqwest::Response) -> Result<serde_json::Value, String> {
    const MAX_BYTES: usize = 1024 * 1024;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BYTES as u64)
    {
        return Err("Remote JSON response too large".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > MAX_BYTES {
            return Err("Remote JSON response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_addresses_exclude_private_and_transition_networks() {
        for address in [
            "127.0.0.1",
            "10.1.1.1",
            "172.16.2.3",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "2002:7f00:1::",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_ip(address.parse().unwrap()), "{address}");
        }
    }
    #[test]
    fn url_normalization_cannot_bypass_address_checks() {
        for server in [
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f000001",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(parse_server(server).is_err(), "{server}");
        }
    }
    #[test]
    fn alternate_public_ip_spellings_are_not_server_names() {
        for server in [
            "0x08080808",
            "134744072",
            "010.010.010.010",
            "8.8.2056",
            "0x08080808:8448",
        ] {
            assert!(!is_valid_server_name(server), "{server}");
        }
        for server in [
            "8.8.8.8",
            "8.8.8.8:8448",
            "dns.google",
            "node123.example",
            "[2606:4700:4700::1111]",
        ] {
            assert!(is_valid_server_name(server), "{server}");
        }
    }

    #[test]
    fn authorities_are_not_urls() {
        for value in [
            "",
            ":8448",
            "evil@localhost",
            "example.org/path",
            "example.org?x",
            "a\\b",
            "a:0",
            "a:65536",
            "::1",
            "-a.org",
            "a..org",
            "a#fragment",
        ] {
            assert!(!is_valid_server_name(value), "{value}");
        }
        for value in [
            "example.org",
            "example.org:443",
            "127.0.0.1:8448",
            "[::1]",
            "[2001:db8::1]:443",
        ] {
            assert!(is_valid_server_name(value), "{value}");
        }
    }
}
