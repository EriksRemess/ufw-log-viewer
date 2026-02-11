use crate::LogEntry;
use crate::services::service_from_port;

// Parses one kernel log line containing a UFW marker into a structured entry.
pub fn parse_ufw_line(line: &str) -> Option<LogEntry> {
    let action = parse_action(line)?;
    let timestamp = line
        .split(" kernel:")
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    let in_iface = parse_field(line, "IN");
    let out_iface = parse_field(line, "OUT");
    let src_ip = parse_field(line, "SRC");
    let dst_ip = parse_field(line, "DST");
    let proto = parse_field(line, "PROTO").map(|p| p.to_ascii_uppercase());
    let src_port = parse_field(line, "SPT").and_then(|v| v.parse::<u16>().ok());
    let dst_port = parse_field(line, "DPT").and_then(|v| v.parse::<u16>().ok());

    let service = dst_port
        .and_then(service_from_port)
        .or_else(|| src_port.and_then(service_from_port))
        .map(|name| name.to_string());

    Some(LogEntry {
        timestamp,
        action,
        in_iface,
        out_iface,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        service,
        raw: line.to_string(),
    })
}

fn parse_action(line: &str) -> Option<String> {
    let marker = "[UFW ";
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest.find(']')?;
    Some(rest[..end].trim().to_string())
}

fn parse_field(line: &str, name: &str) -> Option<String> {
    for token in line.split_whitespace() {
        if let Some((key, value)) = token.split_once('=')
            && key == name
        {
            return Some(
                value
                    .trim_matches(|c: char| c == ',' || c == ']')
                    .to_string(),
            );
        }
    }
    None
}
