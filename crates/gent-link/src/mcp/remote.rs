//! Remote-only tool schema and conversation selection. Explicit handles never
//! substitute for required host metadata unless the owner selected that mode.
use rmcp::{ErrorData, RoleServer, model::Tool, service::RequestContext};
use serde_json::json;
use std::sync::Arc;

pub(super) fn permit(
    context: &RequestContext<RoleServer>,
) -> Result<crate::gateway::Permit, ErrorData> {
    context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<crate::gateway::Permit>())
        .cloned()
        .ok_or_else(|| ErrorData::invalid_request("gateway authentication required", None))
}

pub(super) fn add_tools(tools: &mut Vec<Tool>) {
    for tool in tools.iter_mut() {
        Arc::make_mut(&mut tool.input_schema)["properties"]
            .as_object_mut().expect("tool properties")
            .insert("conversation".into(), json!({
                "type":"string", "maxLength":72,
                "description":"The handle returned by gent_conversation_open in THIS chat, when this connector uses explicit conversations. Keep it for all follow-ups."
            }));
    }
    tools.push(serde_json::from_value(json!({
        "name":"gent_conversation_open",
        "description":"Start a separate Gent identity for this chat when no conversation handle is retained here. Keep the returned handle and supply it on subsequent Gent calls. This allocates an identity only; it sends no message. Never open again to retry uncertain work or copy another chat's handle.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
        "annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}
    })).expect("conversation tool schema"));
}

pub(super) fn describe(tools: &mut Vec<Tool>, handles: bool) {
    if handles {
        for tool in tools {
            if tool.name == "gent_conversation_open" {
                continue;
            }
            Arc::make_mut(&mut tool.input_schema)
                .entry("required")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .expect("required properties")
                .push(json!("conversation"));
        }
    } else {
        tools.retain(|tool| tool.name != "gent_conversation_open");
        for tool in tools {
            Arc::make_mut(&mut tool.input_schema)["properties"]
                .as_object_mut()
                .expect("tool properties")
                .remove("conversation");
        }
    }
}
