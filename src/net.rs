use std::net::IpAddr;

use crate::{DirectionFilter, FlowFilter, LogEntry};

pub fn is_local_src_ip(src_ip: Option<&str>) -> bool {
    is_local_ip(src_ip)
}

pub fn is_wan_src_ip(src_ip: Option<&str>) -> bool {
    is_wan_ip(src_ip)
}

pub fn matches_flow_filter(flow: FlowFilter, entry: &LogEntry) -> bool {
    let src_local = is_local_ip(entry.src_ip.as_deref());
    let dst_local = is_local_ip(entry.dst_ip.as_deref());
    let dst_wan = is_wan_ip(entry.dst_ip.as_deref());

    match flow {
        FlowFilter::All => true,
        FlowFilter::LocalToLocal => src_local && dst_local,
        FlowFilter::LocalToExternal => src_local && dst_wan,
    }
}

pub fn matches_direction_filter(direction: DirectionFilter, entry: &LogEntry) -> bool {
    match direction {
        DirectionFilter::Both => true,
        DirectionFilter::In => entry.direction() == "IN",
        DirectionFilter::Out => entry.direction() == "OUT",
        DirectionFilter::Forwarded => entry.direction() == "FWD",
    }
}

pub fn is_wan_candidate_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == "lo"
        || lower.starts_with("docker")
        || lower.starts_with("veth")
        || lower.starts_with("virbr")
        || lower.starts_with("br-")
        || lower.starts_with("tailscale")
        || lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
    {
        return false;
    }

    lower.starts_with("en")
        || lower.starts_with("eth")
        || lower.starts_with("wl")
        || lower.starts_with("wwan")
        || lower.starts_with("ppp")
        || lower.contains("wan")
}

pub fn default_wan_interface(options: &[String]) -> Option<String> {
    options
        .iter()
        .find(|iface| is_wan_candidate_interface(iface))
        .cloned()
        .or_else(|| options.first().cloned())
}

fn is_local_ip(ip: Option<&str>) -> bool {
    let Some(ip) = ip else {
        return false;
    };

    let ip = ip.trim();
    if ip.is_empty() {
        return false;
    }

    let lower = ip.to_ascii_lowercase();
    if lower == "::1"
        || lower.starts_with("fe80:")
        || lower.starts_with("fc")
        || lower.starts_with("fd")
    {
        return true;
    }

    let mut octets = [0u8; 4];
    let mut parts = ip.split('.');
    for octet in &mut octets {
        let Some(part) = parts.next() else {
            return false;
        };
        let Ok(value) = part.parse::<u8>() else {
            return false;
        };
        *octet = value;
    }
    if parts.next().is_some() {
        return false;
    }

    match (octets[0], octets[1]) {
        (10, _) => true,
        (127, _) => true,
        (192, 168) => true,
        (172, second) if (16..=31).contains(&second) => true,
        (169, 254) => true,
        _ => false,
    }
}

fn is_wan_ip(ip: Option<&str>) -> bool {
    let Some(ip) = ip else {
        return false;
    };
    let ip = ip.trim();
    if ip.is_empty() {
        return false;
    }
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    if addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    !is_local_ip(Some(ip))
}
