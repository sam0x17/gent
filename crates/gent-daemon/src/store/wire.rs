//! Authenticated capability proofs select the highest mutually supported codec.
use super::*;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS wire_peers(peer TEXT PRIMARY KEY,peer_key BLOB NOT NULL,version INTEGER NOT NULL,confirmed_at INTEGER NOT NULL);")?;
    Ok(())
}

pub(super) fn acknowledgement(challenge: uuid::Uuid, version: u8) -> uuid::Uuid {
    let digest = Sha256::digest(
        [
            b"gent/wire-capability/v1\0".as_slice(),
            challenge.as_bytes(),
            &[version],
        ]
        .concat(),
    );
    let mut bytes: [u8; 16] = digest[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

impl StoreSession<'_> {
    pub(super) fn wire_version(&self, peer: &str) -> Result<u8> {
        let Some(member) = self.state.state().nodes.get(peer) else {
            return Ok(1);
        };
        let version: Option<u8> = self.db.query_row("SELECT version FROM wire_peers WHERE peer=?1 AND peer_key=?2 AND confirmed_at>=?3 AND confirmed_at<=?4",params![peer,member.signing_key.as_slice(),self.timestamp-90,self.timestamp],|r|r.get(0)).optional()?;
        Ok(version
            .filter(|v| crate::messages::wire::NEGOTIATED.contains(v))
            .unwrap_or(1))
    }

    pub(super) fn confirm_wire_version(&self, peer: &str, version: u8) -> Result<()> {
        ensure!(
            crate::messages::wire::NEGOTIATED.contains(&version),
            "unsupported wire capability"
        );
        let member = self.state.state().nodes.get(peer).context("unknown peer")?;
        self.db.execute("INSERT INTO wire_peers VALUES(?1,?2,?3,?4) ON CONFLICT(peer) DO UPDATE SET peer_key=excluded.peer_key,version=excluded.version,confirmed_at=excluded.confirmed_at",params![peer,member.signing_key.as_slice(),version,self.timestamp])?;
        Ok(())
    }
}
