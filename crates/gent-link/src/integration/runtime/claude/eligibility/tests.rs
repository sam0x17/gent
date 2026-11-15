use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn recovery_requires_scoped_stable_job_and_history_without_native_work() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().canonicalize().unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    let assistant = uuid::Uuid::new_v4().to_string();
    let history = directory
        .join("projects/work")
        .join(format!("{session}.jsonl"));
    fs::create_dir_all(history.parent().unwrap()).unwrap();
    fs::write(
        &history,
        format!(
            "{}\n{}\n",
            json!({"type":"assistant","sessionId":session,"cwd":"/work","uuid":assistant,
            "message":{"role":"assistant","stop_reason":"end_turn"}}),
            json!({"type":"system","subtype":"turn_duration","parentUuid":assistant})
        ),
    )
    .unwrap();
    fs::set_permissions(&history, fs::Permissions::from_mode(0o600)).unwrap();
    let job = directory
        .join("jobs")
        .join(&session[..8])
        .join("state.json");
    fs::create_dir_all(job.parent().unwrap()).unwrap();
    let original = json!({"sessionId":session,"cwd":"/work","linkScanPath":history,
        "inFlight":{"tasks":0,"queued":0,"drainableMonitors":0,"kinds":[]}, "children":null});
    fs::write(&job, original.to_string()).unwrap();
    fs::set_permissions(&job, fs::Permissions::from_mode(0o600)).unwrap();
    let evidence = read(&directory, &session, Path::new("/work")).unwrap();
    evidence.verify().unwrap();
    for case in [
        "session", "cwd", "tasks", "queued", "monitor", "kinds", "children", "path", "unknown",
    ] {
        let mut value = original.clone();
        match case {
            "session" => value["sessionId"] = uuid::Uuid::new_v4().to_string().into(),
            "cwd" => value["cwd"] = "/foreign".into(),
            "tasks" => value["inFlight"]["tasks"] = 1.into(),
            "queued" => value["inFlight"]["queued"] = 1.into(),
            "monitor" => value["inFlight"]["drainableMonitors"] = 1.into(),
            "kinds" => value["inFlight"]["kinds"] = json!(["task"]),
            "children" => value["children"] = json!([{}]),
            "path" => value["linkScanPath"] = json!(directory.join(format!("{session}.jsonl"))),
            "unknown" => {
                value.as_object_mut().unwrap().remove("inFlight");
            }
            _ => unreachable!(),
        }
        fs::write(&job, value.to_string()).unwrap();
        assert!(
            read(&directory, &session, Path::new("/work")).is_err(),
            "{case}"
        );
        assert!(evidence.verify().is_err());
    }
    fs::write(&job, original.to_string()).unwrap();
    let alias = directory.join("elsewhere");
    fs::rename(&history, &alias).unwrap();
    std::os::unix::fs::symlink(&alias, &history).unwrap();
    assert!(read(&directory, &session, Path::new("/work")).is_err());
}
