//! An enrolled malicious writer can encrypt arbitrary bytes. Tests must prove
//! that authentic MLS transport alone cannot authorize a journal import.
use super::*;

pub(crate) fn publish(
    endpoint: &mut OrderedEndpoint<'_>,
    group: &[u8],
    body: &[u8],
    now: u64,
) -> Result<Packet> {
    endpoint.inner.transact_mode(now, true, |session| {
        let request = requests::allocate(session.db, group, body, None)?;
        publish_in(session, group, Purpose::Configuration, |session| {
            session.send(group, request, body)
        })
    })
}
