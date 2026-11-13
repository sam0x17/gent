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

#[derive(Clone)]
enum Credentials {
    Fixed(String),
    Host(Arc<Mutex<Bindings>>),
}

#[derive(Clone)]
struct GentMcp {
    home: PathBuf,
    credentials: Credentials,
}

fn tools() -> Vec<Tool> {
    let text = json!({"type":"string","maxLength":65536});
    let file = json!({"type":"object","additionalProperties":false,"required":["name","media_type","data_base64"],"properties":{"name":{"type":"string"},"media_type":{"type":"string"},"data_base64":{"type":"string"}}});
    let declarations = vec![
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
            "Send to the recipient agent ID returned by gent_agents. Use a new UUID request_id for new work; reuse it only for an identical retry. Optional files contain actual bytes.",
            json!({"recipient":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid"},"text":text,"files":{"type":"array","maxItems":4,"items":file}}),
            vec!["recipient", "request_id", "text"],
        ),
        (
            "gent_reply",
            "Reply using a message ID from gent_inbox, within its bounded exchange. Reuse request_id only for an identical retry.",
            json!({"message_id":{"type":"string","format":"uuid"},"request_id":{"type":"string","format":"uuid"},"text":text,"files":{"type":"array","maxItems":4,"items":file}}),
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
    ];
    declarations.into_iter().map(|(name,description,properties,required)|Tool::new_with_raw(name,Some(description.into()),Arc::new(json!({"type":"object","additionalProperties":false,"properties":properties,"required":required}).as_object().unwrap().clone()))).collect()
}

impl ServerHandler for GentMcp {
    fn get_info(&self) -> ServerConfig {
        let instructions = include_str!("../skills/gent/SKILL.md")
            .split_once("\n---\n")
            .expect("bundled skill has closing frontmatter")
            .1;
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(instructions)
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        // Construction via serde tolerates SDK non-exhaustive response structs.
        Ok(serde_json::from_value(json!({"tools":tools()})).expect("valid tools result"))
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        tools().into_iter().find(|tool| tool.name == name)
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
            Ok(value) => {
                let mut content = vec![ContentBlock::text(value.to_string())];
                if operation == "inbox" {
                    for message in value.as_array().into_iter().flatten() {
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

pub async fn run(home: PathBuf, binding_path: Option<PathBuf>, host: Option<Host>) -> Result<()> {
    config::load(&home)?;
    let mut guard = None;
    let credentials = if let Some(host) = host {
        Credentials::Host(Arc::new(Mutex::new(Bindings::new(&home, host)?)))
    } else if let Some(path) = binding_path {
        // A binding file is selected outside the model by the owner/host per conversation.
        let credential = config::binding(&path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        file.try_lock_exclusive()
            .context("binding is already in use by another MCP connection")?;
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
