//! Matrix server name resolution.
//!
//! Resolution order per Matrix spec:
//! 1. If server_name has an explicit port → use directly
//! 2. Check /.well-known/matrix/server for delegation
//! 3. SRV DNS lookup _matrix._tcp.<server_name>
//! 4. Fall back to server_name:8448

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ResolvedServer {
    pub host: String,
    pub port: u16,
}

/// Resolve a Matrix server name to a host:port for federation connections.
pub async fn resolve_server_name(server_name: &str) -> ResolvedServer {
    // If explicit port given, use as-is
    if let Some((host, port_str)) = server_name.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return ResolvedServer {
                host: host.to_owned(),
                port,
            };
        }
    }

    // Try /.well-known/matrix/server delegation
    if let Some(resolved) = try_well_known(server_name).await {
        return resolved;
    }

    // Fall back to port 8448
    ResolvedServer {
        host: server_name.to_owned(),
        port: 8448,
    }
}

async fn try_well_known(server_name: &str) -> Option<ResolvedServer> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(false)
        .build()
        .ok()?;

    let url = format!("https://{}/.well-known/matrix/server", server_name);
    let resp = client.get(&url).send().await.ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let json: serde_json::Value = resp.json().await.ok()?;
    let delegated = json.get("m.server")?.as_str()?;

    // Parse "host:port" or just "host"
    if let Some((host, port_str)) = delegated.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Some(ResolvedServer {
                host: host.to_owned(),
                port,
            });
        }
    }

    Some(ResolvedServer {
        host: delegated.to_owned(),
        port: 8448,
    })
}
