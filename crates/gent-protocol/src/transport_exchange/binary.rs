//! V1 binary envelope on the existing authenticated exchange route. The first
//! JSON response advertises support; an old client can ignore that header.
//! All integers are big-endian. The 5-byte request/response magic precedes
//! a u8 item count. A request item starts with a u8 method (GET=0, PUT=1),
//! u16 path length and path bytes. A response item starts with its u16 status.
//! Both end in a u8 compact flag (0 or 1), u32 body length and body bytes.
//! Compact bodies use the signed object type implied by the mailbox operation.
use super::{MAX_BYTES, MAX_OPERATIONS, MAX_PATH_BYTES, valid_route};
use std::fmt;

pub const MEDIA_TYPE: &str = "application/vnd.gent.exchange-v1";
pub const SUPPORT_HEADER: &str = "x-gent-exchange";
pub const SUPPORT_VALUE: &str = "binary-v1";
/// A binary client that understands the extended /state body requests it
/// explicitly. Earlier binary clients use the same exchange media type.
pub const STATE_RETIREMENT_HEADER: &str = "x-gent-state-retirement";
const REQUEST: &[u8; 5] = b"GNTX\x01";
const RESPONSE: &[u8; 5] = b"GNTY\x01";

#[derive(Debug)]
pub struct InvalidExchange;
impl fmt::Display for InvalidExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid binary mailbox exchange")
    }
}
impl std::error::Error for InvalidExchange {}
type Result<T> = std::result::Result<T, InvalidExchange>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub method: String,
    pub path: String,
    pub compact: bool,
    pub body: Vec<u8>,
}
impl Operation {
    pub fn valid(&self) -> bool {
        valid_route(&self.method, &self.path, !self.body.is_empty())
            && (!self.compact || !self.body.is_empty())
            && self.body.len() <= crate::transport_batch::MAX_BYTES
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Item {
    pub status: u16,
    pub compact: bool,
    pub body: Vec<u8>,
}

fn header(magic: &[u8; 5], count: usize) -> Result<Vec<u8>> {
    if !(1..=MAX_OPERATIONS).contains(&count) {
        return Err(InvalidExchange);
    }
    let mut out = magic.to_vec();
    out.push(count as u8);
    Ok(out)
}
fn body(out: &mut Vec<u8>, compact: bool, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_BYTES || out.len() + 5 + bytes.len() > MAX_BYTES {
        return Err(InvalidExchange);
    }
    out.push(u8::from(compact));
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
pub fn encode_request(ops: &[Operation]) -> Result<Vec<u8>> {
    let mut out = header(REQUEST, ops.len())?;
    for op in ops {
        if !op.valid() {
            return Err(InvalidExchange);
        }
        out.push(u8::from(op.method == "PUT"));
        out.extend_from_slice(&(op.path.len() as u16).to_be_bytes());
        out.extend_from_slice(op.path.as_bytes());
        body(&mut out, op.compact, &op.body)?;
    }
    Ok(out)
}
pub fn encode_response(items: &[Item]) -> Result<Vec<u8>> {
    let mut out = header(RESPONSE, items.len())?;
    for item in items {
        if !(100..=599).contains(&item.status) {
            return Err(InvalidExchange);
        }
        out.extend_from_slice(&item.status.to_be_bytes());
        body(&mut out, item.compact, &item.body)?;
    }
    Ok(out)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (v, rest) = self.0.split_at_checked(len).ok_or(InvalidExchange)?;
        self.0 = rest;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| InvalidExchange)
    }
    fn flag(&mut self) -> Result<bool> {
        match self.array()? {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(InvalidExchange),
        }
    }
    fn body(&mut self, limit: usize) -> Result<(bool, Vec<u8>)> {
        let compact = self.flag()?;
        let len = u32::from_be_bytes(self.array()?) as usize;
        if len > limit {
            return Err(InvalidExchange);
        }
        Ok((compact, self.take(len)?.to_vec()))
    }
}
fn decode<T>(
    bytes: &[u8],
    magic: &[u8; 5],
    mut read: impl FnMut(&mut Reader<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    if bytes.len() > MAX_BYTES {
        return Err(InvalidExchange);
    }
    let mut r = Reader(bytes);
    if r.take(5)? != magic {
        return Err(InvalidExchange);
    }
    let [count] = r.array()?;
    if !(1..=MAX_OPERATIONS).contains(&(count as usize)) {
        return Err(InvalidExchange);
    }
    let items = (0..count)
        .map(|_| read(&mut r))
        .collect::<Result<Vec<_>>>()?;
    if !r.0.is_empty() {
        return Err(InvalidExchange);
    }
    Ok(items)
}
pub fn decode_request(bytes: &[u8]) -> Result<Vec<Operation>> {
    decode(bytes, REQUEST, |r| {
        let method = if r.flag()? { "PUT" } else { "GET" };
        let len = u16::from_be_bytes(r.array()?) as usize;
        if len > MAX_PATH_BYTES {
            return Err(InvalidExchange);
        }
        let path = std::str::from_utf8(r.take(len)?)
            .map_err(|_| InvalidExchange)?
            .to_owned();
        let (compact, body) = r.body(crate::transport_batch::MAX_BYTES)?;
        let op = Operation {
            method: method.into(),
            path,
            compact,
            body,
        };
        if !op.valid() {
            return Err(InvalidExchange);
        }
        Ok(op)
    })
}
pub fn decode_response(bytes: &[u8]) -> Result<Vec<Item>> {
    decode(bytes, RESPONSE, |r| {
        let status = u16::from_be_bytes(r.array()?);
        if !(100..=599).contains(&status) {
            return Err(InvalidExchange);
        }
        let (compact, body) = r.body(MAX_BYTES)?;
        Ok(Item {
            status,
            compact,
            body,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_framing_before_returning_any_operations() {
        let op = Operation {
            method: "PUT".into(),
            path: "/v1/mailboxes/g/batch/1".into(),
            compact: false,
            body: vec![0, 255],
        };
        let bytes = encode_request(std::slice::from_ref(&op)).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), vec![op.clone()]);
        for end in 0..bytes.len() {
            assert!(decode_request(&bytes[..end]).is_err());
        }
        for byte in [4, 5, 6, 7, 8, 9 + op.path.len(), 10 + op.path.len()] {
            let mut bad = bytes.clone();
            bad[byte] = 255;
            assert!(decode_request(&bad).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
        assert!(encode_request(&vec![op.clone(); MAX_OPERATIONS + 1]).is_err());
        assert!(
            encode_request(&[Operation {
                path: "/v1/configuration/g".into(),
                ..op
            }])
            .is_err()
        );
        let items = vec![
            Item {
                status: 200,
                compact: true,
                body: vec![255, 0],
            },
            Item {
                status: 409,
                compact: false,
                body: vec![],
            },
        ];
        let result = encode_response(&items).unwrap();
        assert_eq!(decode_response(&result).unwrap(), items);
        assert!(decode_response(&bytes).is_err());
        assert!(decode_response(&result[..result.len() - 1]).is_err());
    }
}
