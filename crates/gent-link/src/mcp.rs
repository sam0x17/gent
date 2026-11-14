use crate::integration::{Bindings, Host};
use anyhow::{Context, Result};
use fs2::FileExt;
use gent_daemon::{config, request};
use gent_protocol::{AgentOp, Request};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt, model::*, service::RequestContext};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
mod binding;

#[derive(Clone)]
enum Credentials {
    Fixed(String),
    Host(Arc<Mutex<Bindings>>),
    Remote(crate::gateway::Registry),
}

#[derive(Clone)]
pub(crate) struct GentMcp {
    home: PathBuf,
    credentials: Credentials,
}

impl GentMcp {
    pub(crate) fn remote(home: PathBuf, registry: crate::gateway::Registry) -> Self {
        Self {
            home,
            credentials: Credentials::Remote(registry),
        }
    }

    fn available_tools(&self) -> Vec<Tool> {
        let mut tools = tools();
        if matches!(self.credentials, Credentials::Remote(_)) {
            tools.retain(|t| {
                !matches!(
                    t.name.as_ref(),
                    "gent_file_paths" | "gent_file_import" | "gent_file_export"
                )
            });
        }
        tools
    }
}

fn tools() -> Vec<Tool> {
    let text = json!({"type":"string","maxLength":65536});
    let file = json!({"type":"object","additionalProperties":false,"required":["name","media_type","data_base64"],"properties":{"name":{"type":"string"},"media_type":{"type":"string"},"data_base64":{"type":"string"}}});
    let file_ids = json!({"type":"array","maxItems":4,"uniqueItems":true,"items":{"type":"string","format":"uuid"}});
    let declarations = vec![
        (
            "gent_request_ids",
            "Generate UUIDv7 request IDs for new sends, replies, file imports, relay attachments, or relay turns. First use must be within 24 hours. Use one ID per new operation; retain it for identical retries. Never replace an expired ID merely to retry old work. Generating IDs does not submit work.",
            json!({"count":{"type":"integer","minimum":1,"maximum":32,"default":1}}),
            vec![],
        ),
        (
            "gent_file_paths",
            "Get this agent's local file handoff folders. A CLI host can copy real files into import_directory with its own filesystem tools. Paths refer to the daemon machine.",
            json!({}),
            vec![],
        ),
        (
            "gent_file_import",
            "Import a regular file from this agent's import_directory by basename, up to 32 MiB. Returns a file ID usable in file_ids on send, reply, relay_send, or relay_respond. Keep source bytes unchanged for identical request_id retries. Gent cleans unchanged handoff copies after cleanup_after; save lasting files elsewhere.",
            json!({"request_id":{"type":"string","format":"uuid","description":"UUIDv7 from gent_request_ids; reuse only for an identical retry"},"name":{"type":"string","maxLength":128},"media_type":{"type":"string","maxLength":128}}),
            vec!["request_id", "name", "media_type"],
        ),
        (
            "gent_file_status",
            "Check a permitted file ID for pending download or ready bytes. Keys are never returned. Permissions and expiry are checked on every call.",
            json!({"file_id":{"type":"string","format":"uuid"}}),
            vec!["file_id"],
        ),
        (
            "gent_file_export",
            "Verify and export an authorized complete file into this agent's export_directory. Returns a local path for host file or image tools and cleanup_after for this temporary copy. Check gent_file_status while pending. Existing files with different bytes are never overwritten. Save lasting files outside the handoff folder.",
            json!({"file_id":{"type":"string","format":"uuid"}}),
            vec!["file_id"],
        ),
        (
            "gent_register",
            "Announce this conversation. The connection determines identity and node; registration does not grant messaging permissions.",
            json!({"name":{"type":"string","maxLength":128},"provider":{"type":"string","maxLength":128}}),
            vec!["name", "provider"],
        ),
        (
            "gent_identity",
            "Get this connection's registered identity and location.",
            json!({}),
            vec![],
        ),
        (
            "gent_agents",
            "List only agents this registration may discover.",
            json!({}),
            vec![],
        ),
        (
            "gent_send",
            "Send to the recipient agent ID returned by gent_agents. Get a UUIDv7 request_id from gent_request_ids for new work; reuse it only for an identical retry. Optional files contain actual bytes.",
            json!({"recipient":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid","description":"UUIDv7 from gent_request_ids; reuse only for an identical retry"},"text":text,"files":{"type":"array","maxItems":4,"items":file},"file_ids":file_ids}),
            vec!["recipient", "request_id", "text"],
        ),
        (
            "gent_reply",
            "Reply using a message ID from gent_inbox, within its bounded exchange. Reuse request_id only for an identical retry.",
            json!({"message_id":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid","description":"UUIDv7 from gent_request_ids; reuse only for an identical retry"},"text":text,"files":{"type":"array","maxItems":4,"items":file},"file_ids":file_ids}),
            vec!["message_id", "request_id", "text"],
        ),
        (
            "gent_inbox",
            "Retrieve unacknowledged permitted messages, including file bytes. Repeat reads retain the same IDs; acknowledge after retrieval.",
            json!({}),
            vec![],
        ),
        (
            "gent_ack",
            "Acknowledge a message delivered to this registration. This records receipt, not completion of the requested work.",
            json!({"message_id":{"type":"string","format":"uuid"}}),
            vec!["message_id"],
        ),
        (
            "gent_message_status",
            "Inspect a message sent or received by this registration.",
            json!({"message_id":{"type":"string","format":"uuid"}}),
            vec!["message_id"],
        ),
        (
            "gent_relay_attach",
            "Persist a target agent ID using an active owner relay grant and messaging permissions. Use a UUIDv7 request_id from gent_request_ids; an identical retry preserves the original attachment. This selects a target without sending a message.",
            json!({"target":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid","description":"UUIDv7 from gent_request_ids; reuse only for an identical retry"}}),
            vec!["target", "request_id"],
        ),
        (
            "gent_relay_status",
            "Inspect this agent's current attachment, or a specific attachment ID. Selection persists across restarts; use gent_relay_turns to recover pending work. Hidden targets are omitted.",
            json!({"attachment_id":{"type":"string","format":"uuid"}}),
            vec![],
        ),
        (
            "gent_relay_detach",
            "Detach this agent's specified attachment. It does not cancel work already sent, and cannot detach a different current target.",
            json!({"attachment_id":{"type":"string","format":"uuid"}}),
            vec!["attachment_id"],
        ),
        (
            "gent_relay_send",
            "Forward one new turn to a saved attachment. Preserve the user's text and file bytes. A new UUIDv7 request_id from gent_request_ids creates work; an identical retry never resends it or changes its original target. The message remains attributed to this intermediary, without proof of human authorship.",
            json!({"attachment_id":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid","description":"UUIDv7 from gent_request_ids; reuse only for an identical retry"},"text":text,"files":{"type":"array","maxItems":4,"items":file},"file_ids":file_ids}),
            vec!["attachment_id", "request_id", "text"],
        ),
        (
            "gent_relay_turns",
            "Recover this intermediary's durable turn IDs across all attachments, including detached targets. Returns up to 50 in creation order. Pass next_after as after_turn_id for the next page. This does not submit work.",
            json!({"after_turn_id":{"type":"string","format":"uuid"}}),
            vec![],
        ),
        (
            "gent_relay_turn_status",
            "Check one of this intermediary's turns without resubmitting it. Responses and files retain their original target. Pending survives timeouts and restarts; completed means the target reported a final outcome. Pass next_after as after_message_id to read more responses when has_more is true.",
            json!({"turn_id":{"type":"string","format":"uuid"},"after_message_id":{"type":"string","format":"uuid"}}),
            vec!["turn_id"],
        ),
        (
            "gent_relay_next",
            "As a target, retrieve your first unfinished relay turn and any cancellation request. It remains current after acknowledgment and across restarts. Process relay turns in this order and use gent_relay_respond to report progress or a final outcome.",
            json!({}),
            vec![],
        ),
        (
            "gent_relay_respond",
            "As the target, respond to your current relay turn with text and optional files. Use progress while work remains; complete to finish; cancelled only after handling a cancellation request. A final outcome advances the queue. Reuse request_id only for an identical retry. Normal host execution approvals still apply.",
            json!({"turn_id":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid","description":"UUIDv7 from gent_request_ids; reuse only for an identical retry"},"text":text,"files":{"type":"array","maxItems":4,"items":file},"file_ids":file_ids,"outcome":{"type":"string","enum":["progress","complete","cancelled"]}}),
            vec!["turn_id", "request_id", "text", "outcome"],
        ),
        (
            "gent_relay_cancel",
            "Request cancellation of a specific pending turn, including after detach. This does not prove that host execution stopped and does not finish the turn. Inspect its subsequent target response. Reuse request_id only for an identical retry.",
            json!({"turn_id":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid","description":"UUIDv7 from gent_request_ids; reuse only for an identical retry"}}),
            vec!["turn_id", "request_id"],
        ),
    ];
    declarations.into_iter().map(|(name,description,properties,required)|Tool::new_with_raw(name,Some(description.into()),Arc::new(json!({"type":"object","additionalProperties":false,"properties":properties,"required":required}).as_object().unwrap().clone()))).collect()
}

impl ServerHandler for GentMcp {
    fn get_info(&self) -> ServerConfig {
        let instructions = include_str!("../skills/gent/SKILL.md")
            .split_once("\n---\n")
            .expect("bundled skill has closing frontmatter")
            .1;
        let instructions = if matches!(self.credentials, Credentials::Remote(_)) {
            format!(
                "{instructions}\n\nRemote route: user-controlled gateway. Plaintext tool calls terminate on the owner's node and at the model provider. Gent's central relay receives encrypted node traffic. This is not encryption against the model provider. Each tool call requires host-owned conversation metadata; never put host credentials in tool arguments or prompts. Local file handoff tools are unavailable: use inline attachments (up to 1 MiB each, four per message) and supported file retrieval tools. Native hosted file handles are not supported.\n"
            )
        } else {
            instructions.to_string()
        };
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(instructions)
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        // Construction via serde tolerates SDK non-exhaustive response structs.
        Ok(
            serde_json::from_value(json!({"tools":self.available_tools()}))
                .expect("valid tools result"),
        )
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.available_tools()
            .into_iter()
            .find(|tool| tool.name == name)
    }

    async fn call_tool(
        &self,
        call: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let Some(operation) = call.name.strip_prefix("gent_") else {
            return Err(ErrorData::invalid_params("unknown tool", None));
        };
        let tool = self
            .get_tool(&call.name)
            .ok_or_else(|| ErrorData::invalid_params("unknown tool", None))?;
        let properties = tool.input_schema["properties"]
            .as_object()
            .expect("tool properties are an object");
        if call
            .arguments
            .as_ref()
            .is_some_and(|arguments| arguments.keys().any(|key| !properties.contains_key(key)))
        {
            return Ok(
                CallToolResult::error(vec![ContentBlock::text("unexpected tool argument")]).into(),
            );
        }
        let credential = match &self.credentials {
            Credentials::Fixed(credential) => credential.clone(),
            Credentials::Remote(registry) => {
                let permit = context
                    .extensions
                    .get::<axum::http::request::Parts>()
                    .and_then(|parts| parts.extensions.get::<crate::gateway::Permit>())
                    .cloned()
                    .ok_or_else(|| {
                        ErrorData::invalid_request("gateway authentication required", None)
                    })?;
                let meta = serde_json::to_value(&context.meta).expect("MCP metadata serializes");
                match registry.credential_remote(permit, meta).await {
                    Ok(credential) => credential,
                    Err(failure) => {
                        let message = if failure.is::<crate::gateway::registry::Busy>() {
                            "gateway is busy; retry identical arguments with the original request ID"
                        } else {
                            "gateway authorization or conversation binding unavailable; check host metadata and credential status"
                        };
                        return Ok(CallToolResult::error(vec![ContentBlock::text(message)]).into());
                    }
                }
            }
            Credentials::Host(bindings) => {
                let info = context.peer.peer_info();
                // MCP 2026-07-28 carries client information on each request;
                // older peers negotiate it during initialize.
                let client = context
                    .meta
                    .client_info()
                    .or_else(|| info.as_ref().map(|i| i.client_info.clone()));
                let client = client.as_ref().map(|i| i.name.as_str()).unwrap_or_default();
                let meta = serde_json::to_value(&context.meta).expect("MCP metadata serializes");
                let arguments = Value::Object(call.arguments.clone().unwrap_or_default());
                match bindings
                    .lock()
                    .expect("host bindings lock poisoned")
                    .credential(client, &meta, &call.name, &arguments)
                {
                    Ok(credential) => credential,
                    Err(error) => {
                        return Ok(CallToolResult::error(vec![ContentBlock::text(
                            error.to_string(),
                        )])
                        .into());
                    }
                }
            }
        };
        let mut arguments = call.arguments.unwrap_or_default();
        arguments.insert("op".into(), Value::String(operation.into()));
        let action = match serde_json::from_value::<AgentOp>(Value::Object(arguments)) {
            Ok(action) => action,
            Err(_) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    "invalid tool arguments",
                )])
                .into());
            }
        };
        let result = request(&self.home, Request::Agent { credential, action }).await;
        Ok(match result {
            Ok(mut value) => {
                if matches!(self.credentials, Credentials::Remote(_))
                    && matches!(operation, "register" | "identity" | "relay_attach" | "relay_status")
                    && let Some(object) = value.as_object_mut()
                {
                    object.insert("access_route".into(), json!({
                        "mode":"user_controlled_gateway",
                        "plaintext_endpoints":["model_provider","user_node"],
                        "gent_relay":"encrypted_node_traffic_only",
                        "file_access":"inline_attachments_only; no local filesystem or native hosted file handles"
                    }));
                }
                let mut content = vec![ContentBlock::text(value.to_string())];
                if matches!(operation, "inbox" | "relay_next" | "relay_turn_status") {
                    let messages: Vec<&Value> = match operation {
                        "relay_next" => value.get("request").into_iter().collect(),
                        "relay_turn_status" => value["responses"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .collect(),
                        _ => value.as_array().into_iter().flatten().collect(),
                    };
                    for message in messages {
                        for file in message["files"].as_array().into_iter().flatten() {
                            if let (Some(mime), Some(data)) =
                                (file["media_type"].as_str(), file["data_base64"].as_str())
                                && matches!(
                                    mime,
                                    "image/png" | "image/jpeg" | "image/webp" | "image/gif"
                                )
                            {
                                content.push(ContentBlock::image(data, mime));
                            }
                        }
                    }
                }
                CallToolResult::success(content)
            }
            Err(error) => CallToolResult::error(vec![ContentBlock::text(error.to_string())]),
        }
        .into())
    }
}

pub async fn run(
    home: PathBuf,
    binding_path: Option<PathBuf>,
    host: Option<Host>,
    explicit_context: bool,
) -> Result<()> {
    let cfg = config::load(&home)?;
    let mut guard = None;
    let credentials = if let Some(host) = host {
        anyhow::ensure!(
            explicit_context,
            "host bindings require a pinned --home or --cluster; use gent integration install to configure the host"
        );
        Credentials::Host(Arc::new(Mutex::new(Bindings::new(&home, host)?)))
    } else if let Some(path) = binding_path {
        // A binding file is selected outside the model by the owner/host per conversation.
        let existing = crate::managed_file::Snapshot::read(&path)?.text.is_some();
        let credential = config::binding(&path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        file.try_lock_exclusive()
            .context("binding is already in use by another MCP connection")?;
        binding::pin(&path, &cfg, &credential, !existing || explicit_context)?;
        guard = Some(file);
        Credentials::Fixed(credential)
    } else {
        eprintln!(
            "Gent: ephemeral registration; use a distinct --binding file per conversation for reconnect continuity."
        );
        Credentials::Fixed(config::secret())
    };
    let service = GentMcp { home, credentials }
        .serve(rmcp::transport::stdio())
        .await?;
    service.waiting().await?;
    drop(guard);
    Ok(())
}
