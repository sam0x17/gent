use super::*;

fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    schema(&db).unwrap();
    db
}

fn envelope() -> MeshEnvelope {
    MeshEnvelope {
        origin: Uuid::new_v4().to_string(),
        target: Uuid::new_v4().to_string(),
        origin_key: [1; 32],
        target_key: [2; 32],
        link: Uuid::new_v4(),
        signal: MeshSignal::Offer {
            key_package: "synthetic".into(),
        },
    }
}

#[test]
fn migration_compacts_only_completed_jobs_and_preserves_exact_conflicting_retries() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE mesh_jobs(id TEXT PRIMARY KEY,body BLOB NOT NULL,done INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,retry_at INTEGER NOT NULL DEFAULT 0,error TEXT)").unwrap();
    let jobs: Vec<_> = (0..11).map(|_| envelope()).collect();
    for (i, job) in jobs.iter().enumerate() {
        db.execute(
            "INSERT INTO mesh_jobs VALUES(?1,?2,?3,7,123,'historical outcome')",
            params![
                job.id().to_string(),
                serde_json::to_vec(job).unwrap(),
                i < 9
            ],
        )
        .unwrap();
    }
    schema(&db).unwrap();
    schema(&db).unwrap();
    let before = status(&db).unwrap();
    let preview = clean(&db, true).unwrap();
    assert_eq!(preview["records_compacted"], 8);
    assert_eq!(preview["more_due"], 1);
    assert_eq!(status(&db).unwrap(), before);
    assert_eq!(clean(&db, false).unwrap(), preview);
    assert_eq!(clean(&db, false).unwrap()["records_compacted"], 1);
    assert_eq!(clean(&db, false).unwrap()["records_compacted"], 0);
    for (i, job) in jobs.iter().enumerate() {
        let id = job.id().to_string();
        let (row,body,done,attempts,retry,error,digest): (i64,Vec<u8>,bool,u32,i64,String,Option<Vec<u8>>) = db.query_row(
            "SELECT rowid,body,done,attempts,retry_at,error,fingerprint FROM mesh_jobs WHERE id=?1",[&id],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).unwrap();
        assert_eq!(row, i as i64 + 1);
        assert_eq!(done, i < 9);
        assert_eq!(
            (attempts, retry, error),
            (7, 123, "historical outcome".into())
        );
        if done {
            assert!(body.is_empty());
            assert_eq!(
                digest.unwrap(),
                fingerprint(&serde_json::to_vec(job).unwrap())
            );
        } else {
            assert_eq!(body, serde_json::to_vec(job).unwrap());
            assert!(digest.is_none());
        }
        admit(&db, job).unwrap();
        let mut changed = job.clone();
        changed.signal = MeshSignal::Offer {
            key_package: "different".into(),
        };
        assert!(
            admit(&db, &changed)
                .unwrap_err()
                .to_string()
                .contains("conflicting mesh signal")
        );
    }
    assert_eq!(usage(&db).unwrap().records, 11);
    assert_eq!(usage(&db).unwrap().pending, 2);
}

#[test]
fn corruption_and_failed_updates_roll_back_compaction_without_touching_pending_jobs() {
    for fault in 0..4 {
        let db = database();
        let jobs = [envelope(), envelope(), envelope()];
        for job in &jobs {
            admit(&db, job).unwrap();
        }
        for job in &jobs[..2] {
            db.execute(
                "UPDATE mesh_jobs SET done=1 WHERE id=?1",
                [job.id().to_string()],
            )
            .unwrap();
        }
        let second = jobs[1].id().to_string();
        match fault {
            0 => {
                db.execute("UPDATE mesh_jobs SET body=X'ff' WHERE id=?1", [&second])
                    .unwrap();
            }
            1 => {
                db.execute(
                    "UPDATE mesh_jobs SET fingerprint=zeroblob(32) WHERE id=?1",
                    [&second],
                )
                .unwrap();
            }
            2 => {
                db.execute("UPDATE mesh_jobs SET id='wrong' WHERE id=?1", [&second])
                    .unwrap();
            }
            _ => {
                db.execute_batch("CREATE TRIGGER fail_clean BEFORE UPDATE ON mesh_jobs WHEN OLD.rowid=2 BEGIN SELECT RAISE(ABORT,'disk failure'); END;").unwrap();
            }
        }
        let before = status(&db).unwrap();
        let tx = db.unchecked_transaction().unwrap();
        assert!(clean(&tx, false).is_err());
        tx.rollback().unwrap();
        assert_eq!(status(&db).unwrap(), before);
        assert_eq!(usage(&db).unwrap().due, 2);
        assert_eq!(usage(&db).unwrap().pending, 1);
    }
}

#[test]
fn full_byte_quota_preserves_pending_errors_completion_and_duplicates() {
    let db = database();
    let job = envelope();
    let id = job.id().to_string();
    let body = serde_json::to_vec(&job).unwrap();
    let bytes = id.len() + body.len() + 32 + ERROR_RESERVE;
    // A legacy completed error is retained verbatim and counts toward the cap.
    db.execute(
        "INSERT INTO mesh_jobs(id,body,done,error) VALUES('',X'',1,zeroblob(?1))",
        [MAX_BYTES - bytes as u64 + 1],
    )
    .unwrap();
    assert!(admit(&db, &job).unwrap_err().to_string().contains("quota"));
    db.execute(
        "UPDATE mesh_jobs SET error=zeroblob(?1)",
        [MAX_BYTES - bytes as u64],
    )
    .unwrap();
    admit(&db, &job).unwrap();
    assert_eq!(usage(&db).unwrap().reserved, MAX_BYTES);
    admit(&db, &job).unwrap();
    assert!(admit(&db, &envelope()).is_err());
    let error = error_text("机".repeat(500));
    assert!(error.len() <= ERROR_RESERVE && error.len() > ERROR_RESERVE - 3);
    db.execute(
        "UPDATE mesh_jobs SET error=?1 WHERE id=?2",
        params![error, id],
    )
    .unwrap();
    assert_eq!(usage(&db).unwrap().reserved, MAX_BYTES);
    let tx = db.unchecked_transaction().unwrap();
    finish(&tx, &id, Some(&error)).unwrap();
    tx.commit().unwrap();
    assert!(usage(&db).unwrap().reserved < MAX_BYTES);
    assert_eq!(usage(&db).unwrap().pending, 0);
    // Exact retries remain available even for an oversized legacy database.
    db.execute(
        "UPDATE mesh_jobs SET error=zeroblob(?1) WHERE id=''",
        [MAX_BYTES],
    )
    .unwrap();
    admit(&db, &job).unwrap();
    assert!(admit(&db, &envelope()).is_err());
}

#[test]
fn pending_and_total_record_limits_are_independent() {
    for (limit, done) in [(MAX_PENDING, false), (MAX_RECORDS, true)] {
        let db = database();
        let job = envelope();
        admit(&db, &job).unwrap();
        db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1)
            INSERT INTO mesh_jobs(id,body,done,fingerprint) SELECT CAST(x AS TEXT),X'',?2,zeroblob(32) FROM n",params![limit-1,done]).unwrap();
        let error = admit(&db, &envelope()).unwrap_err().to_string();
        assert!(
            error.contains(if done {
                "history quota"
            } else {
                "pending mesh queue"
            }),
            "{error}"
        );
        assert!(usage(&db).unwrap().reserved < MAX_BYTES);
        admit(&db, &job).unwrap();
        finish(&db, &job.id().to_string(), None).unwrap();
        if done {
            assert!(admit(&db, &envelope()).is_err());
        } else {
            admit(&db, &envelope()).unwrap();
        }
    }
}
