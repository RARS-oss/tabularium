//! Canonical encodings and hashing. Everything the chain commits to goes through here.

use serde_json::Value;

pub const EVENT_DOMAIN: &[u8] = b"tabularium.event.v1";
pub const SIG_DOMAIN: &[u8] = b"tabularium.sig.v1";
pub const RECEIPT_DOMAIN: &[u8] = b"tabularium.receipt.v1";
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Canonical JSON: object keys sorted recursively, no whitespace, serde string escaping.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string is serializable")),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key is serializable"));
                out.push(':');
                write_canonical(&m[*k], out);
            }
            out.push('}');
        }
    }
}

pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn payload_hash(payload: &Value) -> String {
    blake3_hex(canonical_json(payload).as_bytes())
}

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Preimage of an event hash. Length-prefixed fields under a domain tag: no ambiguity, no delimiters.
pub fn event_preimage(
    seq: u64,
    ts: &str,
    channel: &str,
    kind: &str,
    trust: u8,
    payload_hash: &str,
    prev_hash: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(EVENT_DOMAIN);
    push_field(&mut buf, &seq.to_be_bytes());
    push_field(&mut buf, ts.as_bytes());
    push_field(&mut buf, channel.as_bytes());
    push_field(&mut buf, kind.as_bytes());
    push_field(&mut buf, &[trust]);
    push_field(&mut buf, payload_hash.as_bytes());
    push_field(&mut buf, prev_hash.as_bytes());
    buf
}

pub fn event_hash(
    seq: u64,
    ts: &str,
    channel: &str,
    kind: &str,
    trust: u8,
    payload_hash: &str,
    prev_hash: &str,
) -> String {
    blake3_hex(&event_preimage(seq, ts, channel, kind, trust, payload_hash, prev_hash))
}

/// Message that gets signed: domain tag + hex hash bytes.
pub fn sig_message(domain: &[u8], hash_hex: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(domain.len() + hash_hex.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(hash_hex.as_bytes());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys_recursively() {
        let v = json!({"b": 1, "a": {"z": [3, {"y": 2, "x": 1}], "c": "s\"q"}});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":"s\"q","z":[3,{"x":1,"y":2}]},"b":1}"#);
    }

    #[test]
    fn preimage_is_unambiguous() {
        let a = event_preimage(1, "ab", "c", "k", 1, "h", "p");
        let b = event_preimage(1, "a", "bc", "k", 1, "h", "p");
        assert_ne!(a, b);
    }
}
