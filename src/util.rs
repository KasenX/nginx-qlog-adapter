use chrono::NaiveDateTime;

/// Parse "YYYY/MM/DD HH:MM:SS" → milliseconds since Unix epoch.
pub(crate) fn parse_timestamp_ms(s: &str) -> f64 {
    NaiveDateTime::parse_from_str(s, "%Y/%m/%d %H:%M:%S")
        .map(|dt| dt.and_utc().timestamp_millis() as f64)
        .unwrap_or(0.0)
}

pub(crate) fn extract_u64(s: &str, key: &str) -> u64 {
    s.find(key).map_or(0, |p| {
        let r = &s[p + key.len()..];
        r.split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    })
}

pub(crate) fn extract_i64(s: &str, key: &str) -> i64 {
    s.find(key).map_or(0, |p| {
        let r = &s[p + key.len()..];
        let end = if let Some(digits) = r.strip_prefix('-') {
            1 + digits
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(digits.len())
        } else {
            r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len())
        };
        r[..end].parse().unwrap_or(0)
    })
}

pub(crate) fn extract_field<'a>(s: &'a str, key: &str) -> &'a str {
    s.find(key).map_or("", |p| {
        let r = &s[p + key.len()..];
        r.split([' ', '\t']).next().unwrap_or("")
    })
}

/// Parse "IP:port" or "[IPv6]:port".
pub(crate) fn parse_addr(addr: Option<&str>) -> (Option<String>, Option<u16>) {
    let Some(addr) = addr else {
        return (None, None);
    };
    if addr.starts_with('[')
        && let Some(close) = addr.rfind(']')
    {
        return (
            Some(addr[1..close].to_string()),
            addr.get(close + 2..).and_then(|s| s.parse().ok()),
        );
    }
    if let Some(colon) = addr.rfind(':') {
        return (
            Some(addr[..colon].to_string()),
            addr[colon + 1..].parse().ok(),
        );
    }
    (Some(addr.to_string()), None)
}

pub(crate) fn ip_version_str(ip: &str) -> &'static str {
    if ip.contains(':') { "v6" } else { "v4" }
}

pub(crate) fn non_empty<T>(v: Vec<T>) -> Option<Vec<T>> {
    if v.is_empty() { None } else { Some(v) }
}
