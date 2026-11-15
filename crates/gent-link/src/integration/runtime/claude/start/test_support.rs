use super::super::test_support::Fixture;
use super::*;
use crate::integration::{Bindings, now, record_hook};
use std::fs;

pub(super) struct Running {
    pub(super) fixture: Fixture,
    daemon: tokio::task::JoinHandle<Result<()>>,
    _bindings: Bindings,
    pub(super) session: String,
    pub(super) agent: String,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.daemon.abort();
    }
}
impl Running {
    pub(super) async fn new() -> Self {
        let fixture = Fixture::new();
        fixture.install(true);
        let session = uuid::Uuid::new_v4().to_string();
        let tool = uuid::Uuid::new_v4().to_string();
        let mut bindings = Bindings::new(&fixture.home, Host::ClaudeCode).unwrap();
        record_hook(
            &fixture.home,
            &json!({"hook_event_name":"PreToolUse","session_id":session,
            "tool_use_id":tool,"tool_name":"mcp__gent__gent_register","tool_input":{}}),
            now().unwrap(),
        )
        .unwrap();
        let key = bindings
            .credential(
                "claude-code",
                &json!({"claudecode/toolUseId":tool}),
                "gent_register",
                &json!({}),
            )
            .unwrap();
        let home = fixture.home.clone();
        let daemon = tokio::spawn(async move { gent_daemon::run(&home).await });
        let mut value = Self {
            fixture,
            daemon,
            _bindings: bindings,
            session,
            agent: String::new(),
        };
        for _ in 0..200 {
            if value.fixture.home.join("daemon.sock").exists() {
                break;
            }
            assert!(!value.daemon.is_finished());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let agent = gent_daemon::request(
            &value.fixture.home,
            Request::Agent {
                credential: key,
                action: AgentOp::Register {
                    name: "startup-target".into(),
                    provider: "claude-code".into(),
                },
            },
        )
        .await
        .unwrap();
        value.agent = agent["agent"]["id"].as_str().unwrap().into();
        value.fixture.script("if [ \"$1\" = agents ]; then cat \"$0.reply\"; else\nprintf '%s\\n' \"$@\" \"$PWD\" \"$CLAUDE_CONFIG_DIR\" >> \"$0.calls\"\ncp \"$0.after\" \"$0.reply\"\nfi\n");
        value.inventory(value.row(None), "reply");
        value.inventory(value.row(Some(23)), "after");
        value
    }
    pub(super) fn row(&self, pid: Option<u32>) -> Value {
        json!({"id":&self.session[..8],"sessionId":self.session,"kind":"background",
            "cwd":self.fixture.directory,"pid":pid,"state":"done","name":"PRIVATE_TITLE"})
    }
    pub(super) fn inventory(&self, row: Value, suffix: &str) {
        fs::write(
            format!("{}.{}", self.fixture.binary.display(), suffix),
            json!([row]).to_string(),
        )
        .unwrap();
    }
    pub(super) async fn start(&self) -> Result<Value> {
        run(
            &self.fixture.home,
            Args {
                host: Host::ClaudeCode,
                session_id: Some(self.session.clone()),
                config_dir: Some(self.fixture.directory.clone()),
                host_binary: Some(self.fixture.binary.clone()),
            },
        )
        .await
    }
    pub(super) fn calls(&self) -> String {
        fs::read_to_string(format!("{}.calls", self.fixture.binary.display())).unwrap_or_default()
    }
}
