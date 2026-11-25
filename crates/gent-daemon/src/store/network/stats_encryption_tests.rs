use super::*;
use crate::encrypted::stats::{MAGIC, open, seal};

#[tokio::test]
async fn encrypted_stats_are_bound_to_the_directional_group_and_current_epoch() -> Result<()> {
    let pair = Pair::new().await;
    let [sender, receiver] = &pair.stores;
    let group = pair.group();
    let reverse: Vec<u8> =
        receiver
            .db
            .query_row("SELECT outgoing FROM network_links", [], |r| r.get(0))?;
    let sample = b"fixture stats, visible only to the two peers";
    let wire = seal(&sender.db, &group, sample)?;
    assert!(wire.starts_with(MAGIC));
    assert!(!wire.windows(sample.len()).any(|s| s == sample));
    assert_ne!(wire, seal(&sender.db, &group, sample)?);
    assert_eq!(open(&receiver.db, &group, &wire)?, sample);
    assert!(open(&receiver.db, &reverse, &wire).is_err());
    for pos in [0, MAGIC.len(), wire.len() - 1] {
        let mut corrupt = wire.clone();
        corrupt[pos] ^= 1;
        assert!(open(&receiver.db, &group, &corrupt).is_err());
    }
    let limit = vec![0; 128 * 1024];
    assert_eq!(
        open(&receiver.db, &group, &seal(&sender.db, &group, &limit)?)?,
        limit
    );
    assert!(seal(&sender.db, &group, &[]).is_err());
    assert!(seal(&sender.db, &group, &vec![0; limit.len() + 1]).is_err());
    assert!(open(&receiver.db, &group, MAGIC).is_err());

    let mut writer = OrderedEndpoint::open_runtime(pair.homes[0].path(), &sender.identity.node)?;
    let mut reader = OrderedEndpoint::open_runtime(pair.homes[1].path(), &receiver.identity.node)?;
    let timestamp = now() as u64;
    let update = writer.rotate(&group, Uuid::new_v4(), timestamp)?;
    let next = seal(&sender.db, &group, sample)?;
    assert!(open(&receiver.db, &group, &next).is_err());
    reader.stage(&update, timestamp)?;
    reader.drain(&group, 1, timestamp)?;
    assert_eq!(open(&receiver.db, &group, &next)?, sample);
    assert!(open(&receiver.db, &group, &wire).is_err());
    Ok(())
}
