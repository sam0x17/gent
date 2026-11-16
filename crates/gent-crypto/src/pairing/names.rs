//! Canonical, shell-safe labels in human-transferred invitation codes.
use anyhow::{Result, ensure};

pub(super) fn validate(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control),
        "invitation names must contain 1-128 bytes without control characters"
    );
    Ok(())
}

pub(super) fn encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("string write");
        }
    }
    encoded
}

pub(super) fn decode(value: &str) -> Result<String> {
    ensure!(value.len() <= 384, "invalid invitation name");
    let mut bytes = Vec::new();
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let a = input.next().and_then(|c| char::from(c).to_digit(16));
            let b = input.next().and_then(|c| char::from(c).to_digit(16));
            let (Some(a), Some(b)) = (a, b) else {
                anyhow::bail!("invalid invitation name");
            };
            bytes.push((a * 16 + b) as u8);
        } else {
            bytes.push(byte);
        }
    }
    let decoded =
        String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("invalid invitation name"))?;
    validate(&decoded)?;
    ensure!(
        encode(&decoded) == value,
        "invalid invitation name encoding"
    );
    Ok(decoded)
}
