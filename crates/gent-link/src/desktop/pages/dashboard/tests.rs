use super::super::Pages;
use super::*;
use gent_daemon::config;
use std::{fs, os::unix::fs::PermissionsExt};

fn board(agent: Uuid, chat: &str) -> Row {
    serde_json::from_value(json!({"agent":agent,"chat":chat,"revision":1,
        "board":{"title":"Training","widgets":[{"id":"loss","kind":"graph",
            "label":"Loss","unit":"%","value":[4,2,3]}]}}))
    .unwrap()
}

#[test]
fn dashboard_refresh_only_sends_charts_when_the_snapshot_changes() {
    let mut page = Page::default();
    let read_layout = |request| match serde_json::from_value::<Request>(request).unwrap() {
        Request::Dashboard(layout) => layout,
        _ => unreachable!(),
    };
    let light = read_layout(json!({"op":"dashboard"}));
    let dark = read_layout(json!({"op":"dashboard","palette":{
        "surface":[32,33,37],"text":[240,241,242],"secondary":[159,160,161],"accent":[180,155,255]
    }}));
    let agent = Uuid::new_v4();
    let mut rows = vec![board(agent, "Trainer")];
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("hidden.json");
    let first = page.refresh(&file, light.clone(), rows.clone()).unwrap();
    assert!(first["rows"][0]["board"]["widgets"][0]["chart_svg"].is_string());
    assert_eq!(
        page.refresh(&file, light, rows.clone()).unwrap(),
        json!({"unchanged":true})
    );
    let recolored = page.resize(dark.clone()).unwrap();
    assert_ne!(
        first["rows"][0]["board"]["widgets"][0]["chart_svg"],
        recolored["rows"][0]["board"]["widgets"][0]["chart_svg"]
    );
    assert_eq!(
        page.refresh(&file, dark.clone(), rows.clone()).unwrap(),
        json!({"unchanged":true})
    );
    rows[0].chat = "Renamed".into();
    assert_eq!(
        page.refresh(&file, dark.clone(), rows).unwrap()["rows"][0]["chat"],
        "Renamed"
    );
    assert_eq!(
        page.refresh(&file, dark.clone(), vec![]).unwrap(),
        json!({"rows":[],"hidden":[]})
    );
    assert_eq!(
        page.refresh(&file, dark, vec![]).unwrap(),
        json!({"unchanged":true})
    );
}

#[tokio::test]
async fn dashboard_resize_renders_each_row_at_its_width_from_cached_data() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("node");
    let cfg = config::initialize(&home, "cached-resize").unwrap();
    gent_daemon::entitlements::grant_test(&home, &cfg);
    let mut pages = Pages::default();
    let resize = r#"{"op":"dashboard_layout","chart_widths":[704,332]}"#;
    assert_eq!(pages.respond(&home, resize).await["unchanged"], true);
    let boards = ["C", "A", "B"].map(|chat| board(Uuid::new_v4(), chat));
    pages
        .dashboard
        .refresh(
            &active_file(&home).unwrap(),
            Layout::default(),
            Vec::from(boards),
        )
        .unwrap();
    let reply = pages.respond(&home, resize).await;
    assert_eq!(reply["layout_only"], true);
    for (i, (chat, width)) in [("A", 332), ("B", 332), ("C", 704)].into_iter().enumerate() {
        let row = &reply["rows"][i];
        assert_eq!(row["chat"], chat);
        let svg = row["board"]["widgets"][0]["chart_svg"].as_str().unwrap();
        assert!(svg.contains(&format!(r#"viewBox="0 0 {width} "#)));
    }
    for invalid in ["[]", "[0]", "[65535]", "[240,240,240,240,240]"] {
        let request = format!(r#"{{"op":"dashboard_layout","chart_widths":{invalid}}}"#);
        assert!(pages.respond(&home, &request).await["error"].is_string());
    }
    assert_eq!(pages.respond(&home, resize).await["unchanged"], true);
}

#[tokio::test]
async fn free_desktop_clears_cached_boards_and_refuses_old_clicks() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    config::initialize(&home, "free").unwrap();
    let mut pages = Pages::default();
    for op in [
        r#"{"op":"dashboard_layout"}"#,
        r#"{"op":"dashboard_hide","agent":"old"}"#,
        r#"{"op":"dashboard_restore","agent":"old"}"#,
        r#"{"op":"dashboard_click","agent":"old","revision":1,"widget":"run"}"#,
        r#"{"op":"dashboard"}"#,
    ] {
        let file = preferences::path(&home, &crate::node_home::inspect(&home).unwrap());
        let agent = Uuid::new_v4();
        pages
            .dashboard
            .refresh(&file, Layout::default(), vec![board(agent, "former")])
            .unwrap();
        pages.dashboard.view_mut().unwrap().hide(agent).unwrap();
        assert_eq!(
            pages.respond(&home, op).await,
            json!({"page":"dashboard","pro_required":true,"rows":[],"hidden":[],"example":example()})
        );
        assert!(pages.dashboard.view.is_none());
    }
}

fn paid_home() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    let cfg = config::initialize(&home, "desktop").unwrap();
    gent_daemon::entitlements::grant_test(&home, &cfg);
    (temp, home)
}

fn request(op: &str, agent: Uuid) -> String {
    json!({"op":op,"agent":agent}).to_string()
}

#[tokio::test]
async fn example_requires_a_complete_empty_snapshot_even_with_retained_labels() {
    let (_root, home) = paid_home();
    let file = active_file(&home).unwrap();
    let mut pages = Pages::default();
    let resize = r#"{"op":"dashboard_layout","chart_widths":[320]}"#;
    let first = pages.respond(&home, r#"{"op":"dashboard"}"#).await;
    assert!(first["error"].is_string() && first.get("example").is_none());
    assert!(pages.respond(&home, resize).await.get("example").is_none());

    let agent = Uuid::new_v4();
    let layout = Layout::default();
    pages
        .dashboard
        .refresh(&file, layout.clone(), vec![board(agent, "Runner")])
        .unwrap();
    let hidden = pages
        .respond(&home, &request("dashboard_hide", agent))
        .await;
    assert_eq!(hidden["rows"], json!([]));
    assert!(hidden.get("example").is_none());
    let deleted = pages.dashboard.refresh(&file, layout, vec![]).unwrap();
    assert_eq!(deleted["rows"], json!([]));
    assert_eq!(deleted["hidden"], hidden["hidden"]);
    let empty = pages.respond(&home, resize).await;
    assert_eq!(empty["example"], example());
    assert!(empty.get("pro_required").is_none());
    assert!(empty["example"].get("agent").is_none());
    let widgets = empty["example"]["board"]["widgets"].as_array().unwrap();
    assert!(
        widgets
            .iter()
            .all(|w| matches!(w["kind"].as_str(), Some("progress" | "events" | "text")))
    );
    assert_eq!(
        pages
            .respond(&home, &request("dashboard_restore", agent))
            .await["example"],
        example()
    );
    assert!(!file.exists());
}

#[tokio::test]
async fn hide_and_restore_filter_before_layout_and_only_persist_labels() {
    let (_root, home) = paid_home();
    let file = active_file(&home).unwrap();
    let agent = Uuid::new_v4();
    let other = Uuid::new_v4();
    let mut boards = vec![board(agent, "Trainer"), board(other, "Trainer")];
    let layout = Layout {
        chart_widths: vec![704, 332],
        ..Default::default()
    };
    let mut pages = Pages::default();
    pages
        .dashboard
        .refresh(&file, layout.clone(), boards.clone())
        .unwrap();
    assert!(!file.with_extension("lock").exists());
    let hide = request("dashboard_hide", agent);
    let restore = request("dashboard_restore", agent);
    let hidden = pages.respond(&home, &hide).await;
    let row = &hidden["rows"][0];
    assert_eq!(row["agent"], json!(other));
    assert!(
        row["board"]["widgets"][0]["chart_svg"]
            .as_str()
            .unwrap()
            .contains(r#"viewBox="0 0 704 "#)
    );
    assert_eq!(
        hidden["hidden"],
        json!([{"agent":agent,"chat":"Trainer","title":"Training"}])
    );
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&file).unwrap()).unwrap(),
        json!({agent.to_string():{"chat":"Trainer","title":"Training"}})
    );
    let click =
        json!({"op":"dashboard_click","agent":agent,"revision":1,"widget":"run"}).to_string();
    assert_eq!(
        pages.respond(&home, &click).await["error"],
        "Dashboard changed. Refresh before clicking."
    );

    let mut restarted = Pages::default();
    boards[0].revision = 2;
    boards[0].board.widgets[0]["value"] = json!([11, 22]);
    let reply = restarted
        .dashboard
        .refresh(&file, layout.clone(), boards.clone())
        .unwrap();
    assert_eq!(reply["rows"], hidden["rows"]);
    assert_eq!(reply["hidden"], hidden["hidden"]);
    boards[0].revision = 3;
    assert_eq!(
        restarted
            .dashboard
            .refresh(&file, layout.clone(), boards.clone())
            .unwrap(),
        json!({"unchanged":true})
    );
    let restored = restarted.respond(&home, &restore).await;
    assert_eq!(restored["hidden"], json!([]));
    assert_eq!(restored["rows"][0]["revision"], 3);
    assert_eq!(
        restored["rows"][0]["board"]["widgets"][0]["value"],
        json!([11, 22])
    );
    assert!(!file.exists());

    restarted.respond(&home, &hide).await;
    boards[0].chat = "Renamed".into();
    boards[0].board.title = "Last known title".into();
    let renamed = restarted
        .dashboard
        .refresh(&file, layout.clone(), boards.clone())
        .unwrap();
    assert_eq!(
        renamed["hidden"],
        json!([{"agent":agent,"chat":"Renamed","title":"Last known title"}])
    );
    let mut restarted = Pages::default();
    let absent = restarted
        .dashboard
        .refresh(&file, layout.clone(), vec![boards[1].clone()])
        .unwrap();
    assert_eq!(absent["hidden"], renamed["hidden"]);
    assert_eq!(absent["rows"][0]["agent"], json!(other));
    assert!(restarted.respond(&home, &hide).await["error"].is_string());
    let restored = restarted.respond(&home, &restore).await;
    assert_eq!(restored["rows"], absent["rows"]);
    assert_eq!(restored["hidden"], json!([]));
    assert_eq!(
        restarted.dashboard.refresh(&file, layout, boards).unwrap()["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn refresh_or_preference_errors_preserve_the_last_complete_display() {
    let (_root, home) = paid_home();
    let file = active_file(&home).unwrap();
    let agent = Uuid::new_v4();
    let other = Uuid::new_v4();
    let boards = vec![board(agent, "First"), board(other, "Second")];
    let mut pages = Pages::default();
    pages
        .dashboard
        .refresh(&file, Layout::default(), boards.clone())
        .unwrap();
    let hidden = pages
        .respond(&home, &request("dashboard_hide", agent))
        .await;
    fs::remove_file(home.join("owner.key")).unwrap();
    let error = pages.respond(&home, r#"{"op":"dashboard"}"#).await;
    assert!(error["error"].is_string());
    assert!(error.get("rows").is_none() && error.get("hidden").is_none());
    let click =
        json!({"op":"dashboard_click","agent":other,"revision":1,"widget":"run"}).to_string();
    assert_eq!(
        pages.respond(&home, &click).await["error"],
        "Dashboard changed. Refresh before clicking."
    );

    let saved = fs::read(&file).unwrap();
    config::write_private(&file, b"invalid").unwrap();
    let error = pages
        .respond(&home, &request("dashboard_restore", agent))
        .await;
    assert!(error["error"].is_string());
    assert_eq!(fs::read(&file).unwrap(), b"invalid");
    assert_eq!(
        pages.dashboard.view_mut().unwrap().render()["hidden"],
        hidden["hidden"]
    );
    config::write_private(&file, &saved).unwrap();
    let recovered = pages
        .dashboard
        .refresh(&file, Layout::default(), boards)
        .unwrap();
    assert_eq!(recovered["rows"], hidden["rows"]);
    assert_eq!(recovered["hidden"], hidden["hidden"]);

    let mut restarted = Pages::default();
    let offline = restarted.respond(&home, r#"{"op":"dashboard"}"#).await;
    assert!(offline["error"].is_string());
    assert_eq!(offline["hidden"], hidden["hidden"]);
    let restored = restarted
        .respond(&home, &request("dashboard_restore", agent))
        .await;
    assert_eq!(restored["hidden"], json!([]));
    assert!(!file.exists());
}

#[tokio::test]
async fn switching_profile_clears_old_cards_and_restore_choices() {
    let (_root, home) = paid_home();
    let original = active_file(&home).unwrap();
    let agent = Uuid::new_v4();
    let mut pages = Pages::default();
    pages
        .dashboard
        .refresh(&original, Layout::default(), vec![board(agent, "Original")])
        .unwrap();
    pages
        .respond(&home, &request("dashboard_hide", agent))
        .await;
    let mut cfg = crate::node_home::inspect(&home).unwrap();
    cfg.cluster.id = Uuid::new_v4().to_string();
    config::save(&home, &cfg).unwrap();
    let reply = pages
        .respond(&home, &request("dashboard_restore", agent))
        .await;
    assert_eq!(reply["rows"], json!([]));
    assert_eq!(reply["hidden"], json!([]));
    assert!(reply["error"].is_string());
    let switched = active_file(&home).unwrap();
    assert_ne!(original, switched);
    assert!(original.exists());
    let visible = pages
        .dashboard
        .refresh(&switched, Layout::default(), vec![board(agent, "Original")])
        .unwrap();
    assert_eq!(visible["rows"][0]["agent"], json!(agent));
    cfg.service = Some(config::ServiceConfig {
        origin: "https://api.gent.link".into(),
        account_id: Uuid::new_v4().to_string(),
    });
    let first = preferences::path(&home, &cfg);
    cfg.service.as_mut().unwrap().account_id = Uuid::new_v4().to_string();
    assert_ne!(first, preferences::path(&home, &cfg));
}

#[tokio::test]
async fn dashboard_fetch_preserves_newer_daemon_fields_and_widget_kinds() {
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixListener,
    };
    let (_root, home) = paid_home();
    let row = json!({"agent":Uuid::new_v4(), "chat":"Preview", "revision":3, "extra_row":1,
    "board":{"title":"Next","extra_board":"ok","widgets":[
        {"id":"new","kind":"future","label":"Preview","extra_widget":{"x":1},"value":"ok"},
        {"id":"old","kind":"graph","label":"Graph","new_field":true,"value":[1,2]}
    ]}});
    let listener = UnixListener::bind(home.join("daemon.sock")).unwrap();
    let serve = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let request: gent_protocol::Request = serde_json::from_str(&line).unwrap();
        assert!(matches!(
            request,
            gent_protocol::Request::Owner {
                action: OwnerOp::Dashboards { after: None },
                ..
            }
        ));
        let result = gent_protocol::Response::Ok(json!({"rows":[row],"next":null}));
        let bytes = format!("{}\n", serde_json::to_string(&result).unwrap());
        reader.get_mut().write_all(bytes.as_bytes()).await.unwrap();
    };
    let mut pages = Pages::default();
    let (_, reply) = tokio::join!(serve, pages.respond(&home, r#"{"op":"dashboard"}"#));
    let mut rendered = reply["rows"][0].clone();
    let graph = rendered["board"]["widgets"][1].as_object_mut().unwrap();
    assert!(graph.remove("chart_svg").unwrap().is_string());
    graph.remove("chart_description");
    assert_eq!(rendered, row);
}
