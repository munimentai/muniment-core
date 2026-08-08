//! Minimal percent-encoding helpers for OAuth query strings
//! without pulling a full URL crate into the dependency tree.

/// Percent-encode a query component: everything except RFC 3986 unreserved
/// characters.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode `%XX` escapes and `+`-as-space in a query component. Invalid
/// escapes pass through literally.
pub fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16).map(|v| v as u8);
                if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push(hi * 16 + lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Split a query string into decoded key/value pairs, preserving order.
pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reserved_and_keeps_unreserved() {
        assert_eq!(
            encode("http://127.0.0.1:8000/callback"),
            "http%3A%2F%2F127.0.0.1%3A8000%2Fcallback"
        );
        assert_eq!(encode("a-b.c_d~e"), "a-b.c_d~e");
        assert_eq!(encode("openid profile"), "openid%20profile");
    }

    #[test]
    fn decode_round_trips_encode() {
        let raw = "https://x?y=1&z= +%ü";
        assert_eq!(decode(&encode(raw)), raw);
    }

    #[test]
    fn parse_query_decodes_pairs_and_tolerates_flags() {
        let pairs = parse_query("code=abc%2F1&state=xyz&flag");
        assert_eq!(
            pairs,
            vec![
                ("code".into(), "abc/1".into()),
                ("state".into(), "xyz".into()),
                ("flag".into(), "".into()),
            ]
        );
    }
}
