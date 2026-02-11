use std::collections::HashMap;
use std::sync::OnceLock;

// Source of truth for service names: IANA CSV snapshot embedded at compile time.
const IANA_SERVICES_CSV: &str = include_str!("../data/service-names-port-numbers.csv");
static PORT_SERVICES: OnceLock<HashMap<u16, ServiceInfo>> = OnceLock::new();

#[derive(Clone, Copy)]
struct ServiceInfo {
    name: &'static str,
    description: &'static str,
}

pub fn service_from_port(port: u16) -> Option<&'static str> {
    PORT_SERVICES
        .get_or_init(build_port_services)
        .get(&port)
        .map(|info| info.name)
}

pub fn service_description_from_port(port: u16) -> Option<&'static str> {
    PORT_SERVICES
        .get_or_init(build_port_services)
        .get(&port)
        .and_then(|info| {
            if info.description.is_empty() {
                None
            } else {
                Some(info.description)
            }
        })
}

fn build_port_services() -> HashMap<u16, ServiceInfo> {
    let mut map = HashMap::new();

    for line in IANA_SERVICES_CSV.lines().skip(1) {
        // We only care about the first four CSV columns:
        // Service Name, Port Number, Transport Protocol, Description.
        let Some((service_raw, port_raw, proto_raw, description_raw)) =
            first_four_csv_columns(line)
        else {
            continue;
        };

        let service = csv_field(service_raw);
        if service.is_empty() {
            continue;
        }

        let proto = csv_field(proto_raw);
        if proto != "tcp" && proto != "udp" {
            continue;
        }

        let Ok(port) = csv_field(port_raw).parse::<u16>() else {
            continue;
        };
        let description = csv_field(description_raw);

        // Preserve the first seen service name per port to keep deterministic behavior.
        map.entry(port).or_insert(ServiceInfo {
            name: service,
            description,
        });
    }

    map
}

fn first_four_csv_columns(line: &str) -> Option<(&str, &str, &str, &str)> {
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    let mut start = 0usize;
    let mut fields: [&str; 4] = ["", "", "", ""];
    let mut idx = 0usize;
    let mut i = 0usize;

    while i <= bytes.len() {
        if i == bytes.len() || (!in_quotes && bytes[i] == b',') {
            if idx >= 4 {
                break;
            }
            fields[idx] = &line[start..i];
            idx += 1;
            if idx == 4 {
                break;
            }
            start = i + 1;
        } else if bytes[i] == b'"' {
            // Handle doubled quotes inside quoted fields.
            if in_quotes && i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                i += 1;
            } else {
                in_quotes = !in_quotes;
            }
        }
        i += 1;
    }

    if idx == 4 {
        Some((fields[0], fields[1], fields[2], fields[3]))
    } else {
        None
    }
}

fn csv_field(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_csv_is_present() {
        assert!(IANA_SERVICES_CSV.starts_with("Service Name,Port Number,Transport Protocol"));
        assert!(IANA_SERVICES_CSV.lines().count() > 10_000);
    }

    #[test]
    fn service_lookup_uses_embedded_iana_data() {
        assert_eq!(service_from_port(1), Some("tcpmux"));
        assert_eq!(service_from_port(22), Some("ssh"));
        assert_eq!(service_from_port(48000), Some("nimcontroller"));
        assert_eq!(
            service_description_from_port(22),
            Some("The Secure Shell (SSH) Protocol")
        );
    }
}
