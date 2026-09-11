//! On-demand diagnostics; public probes never run in the background daemon.
use anyhow::Result;
use opengate_protocol::LocalCommand;
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

async fn reachability(address: &str) -> Value {
    let start = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(address),
    )
    .await;
    let (reachable, error) = match result {
        Ok(Ok(_)) => (true, None),
        Ok(Err(error)) => (false, Some(error.to_string())),
        Err(_) => (false, Some("probe timed out".to_owned())),
    };
    json!({"target":address,"tcp_reachable":reachable,"elapsed_ms":start.elapsed().as_millis(),"error":error})
}

pub async fn run(dir: &Path, device: Option<String>) -> Result<Value> {
    let authentication = if let Some(device) = device {
        let start = Instant::now();
        let result = crate::client::rpc(dir, LocalCommand::Connect { device }).await;
        match result {
            Ok(reply) => {
                json!({"authenticated":true,"control_roundtrip_ms":start.elapsed().as_millis(),"remote":reply.data})
            }
            Err(error) => {
                json!({"authenticated":false,"control_roundtrip_ms":start.elapsed().as_millis(),"error":format!("{error:#}")})
            }
        }
    } else {
        Value::Null
    };
    // Public Cloudflare resolver addresses, documented at
    // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/
    // Establish TCP only: no DNS names, local metadata or pairing data are sent.
    let (ipv4, ipv6, status) = tokio::join!(
        reachability("1.1.1.1:853"),
        reachability("[2606:4700:4700::1111]:853"),
        crate::client::rpc(dir, LocalCommand::Status),
    );
    let status = status?.data;
    let paths: Vec<&str> = status["network"]["connections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["path"].as_str())
        .collect();
    let explanation = if paths.contains(&"RELAYED") {
        "A configured relay carries at least one encrypted peer connection. Direct traversal may still succeed later."
    } else if paths.is_empty() {
        "No peer path is established. Connect a saved device to measure its authentication and reachability; restrictive NAT may require a configured relay."
    } else {
        "An established direct peer path is available. Its observed path and transport are shown for each connection."
    };
    let connections = status["network"]["connections"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let ping_successes: u64 = connections
        .iter()
        .filter_map(|connection| connection["ping_successes"].as_u64())
        .sum();
    let ping_failures: u64 = connections
        .iter()
        .filter_map(|connection| connection["ping_failures"].as_u64())
        .sum();
    let ping_samples = ping_successes.saturating_add(ping_failures);
    let packet_loss = if ping_samples == 0 {
        json!({
            "percent": Value::Null,
            "reason": "no libp2p ping samples are available yet",
            "method": "libp2p_ping_samples"
        })
    } else {
        json!({
            "percent": (ping_failures as f64 * 100.0) / ping_samples as f64,
            "samples": ping_samples,
            "method": "libp2p_ping_samples",
            "note": "This is observed ping failure rate, not a raw packet-capture measurement."
        })
    };
    Ok(json!({
        "local_version":env!("CARGO_PKG_VERSION"), "local_protocol":opengate_protocol::VERSION,
        "authentication":authentication, "internet_probes":{"ipv4":ipv4,"ipv6":ipv6,
            "scope":"TCP reachability to the stated public resolver only; a failed probe does not prove all Internet access is unavailable."},
        "packet_loss":packet_loss,
        "path_explanation":explanation,"status":status
    }))
}
