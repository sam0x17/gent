//! Durable publication outbox scoped to the account and its service origin.
use super::*;
use gent_protocol::notifications::{Notice, Scope};

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS account_outbox(
            id TEXT PRIMARY KEY, scope TEXT NOT NULL, origin TEXT NOT NULL, notice TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS account_outbox_scope ON account_outbox(scope,origin);",
    )?;
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn enqueue_notice(&self, notice: &Notice, scope: Option<Scope>) -> Result<Value> {
        self.db.execute(
            "DELETE FROM account_outbox WHERE json_extract(notice,'$.created_at')<?1",
            [self.timestamp - 7 * 86400],
        )?;
        let Some(scope) = self
            .config
            .service
            .as_ref()
            .map(|s| Scope {
                account: s.account_id.clone(),
                origin: s.origin.clone(),
            })
            .or(scope)
        else {
            return Ok(json!({"queued":false}));
        };
        ensure!(notice.valid(self.timestamp), "invalid notification");
        let origin = crate::backend::ACCOUNT.identity(reqwest::Url::parse(&scope.origin)?);
        self.db.execute(
            "INSERT OR IGNORE INTO account_outbox VALUES(?1,?2,?3,?4)",
            params![
                notice.id.to_string(),
                scope.account,
                origin.as_str(),
                serde_json::to_string(notice)?
            ],
        )?;
        Ok(json!({"queued":true}))
    }
    pub(super) fn pending_notices(&self, scope: &Scope) -> Result<Value> {
        let mut list = Vec::new();
        let mut query = self
            .db
            .prepare("SELECT notice FROM account_outbox WHERE scope=?1 AND origin IN (?2,?3) ORDER BY rowid LIMIT 64")?;
        let origin = reqwest::Url::parse(&scope.origin)?;
        let account = crate::backend::ACCOUNT;
        let beta = account
            .contains(&origin)
            .then(|| reqwest::Url::parse(account.beta))
            .transpose()?;
        let stable = account.identity(origin);
        let mut rows = query.query(params![
            scope.account,
            stable.as_str(),
            beta.as_ref().map(reqwest::Url::as_str)
        ])?;
        while let Some(row) = rows.next()? {
            list.push(serde_json::from_str::<Notice>(&row.get::<_, String>(0)?)?);
        }
        Ok(json!(list))
    }
}
