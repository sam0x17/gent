use anyhow::{Context, Result, ensure};
use jsonc_parser::{
    ParseOptions, ast,
    cst::{CstInputValue, CstRootNode},
};
use serde_json::Value;
use std::collections::HashSet;
use toml_edit::{DocumentMut, Item, Table};

use super::super::Host;

const MATCHER: &str = "^mcp__gent__gent_";

fn strict() -> ParseOptions {
    ParseOptions {
        allow_comments: false,
        allow_loose_object_property_names: false,
        allow_trailing_commas: false,
        allow_missing_commas: false,
        allow_single_quoted_strings: false,
        allow_hexadecimal_numbers: false,
        allow_unary_plus_numbers: false,
        allow_bare_decimal_point_numbers: false,
        allow_non_finite_numbers: false,
        allow_extended_string_escapes: false,
    }
}

fn unique(value: &ast::Value<'_>) -> Result<()> {
    match value {
        ast::Value::Object(object) => {
            let mut keys = HashSet::new();
            for property in &object.properties {
                ensure!(
                    keys.insert(property.name.as_str()),
                    "duplicate JSON property in host configuration"
                );
                unique(&property.value)?;
            }
        }
        ast::Value::Array(array) => {
            for value in &array.elements {
                unique(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn json(text: &str) -> Result<(Value, CstRootNode)> {
    // Discard parser excerpts: host config may contain credentials. Serde also
    // bounds nesting before the CST parser visits the document.
    let value: Value = serde_json::from_str(text)
        .map_err(|_| anyhow::anyhow!("invalid strict JSON in host configuration"))?;
    ensure!(
        value.is_object(),
        "host configuration must be a JSON object"
    );
    let ast = jsonc_parser::parse_to_ast(text, &Default::default(), &strict())
        .map_err(|_| anyhow::anyhow!("invalid strict JSON in host configuration"))?;
    unique(ast.value.as_ref().context("empty JSON configuration")?)?;
    let root = CstRootNode::parse(text, &strict())
        .map_err(|_| anyhow::anyhow!("invalid strict JSON in host configuration"))?;
    Ok((value, root))
}
fn input(value: &Value) -> CstInputValue {
    match value {
        Value::Null => CstInputValue::Null,
        Value::Bool(v) => CstInputValue::Bool(*v),
        Value::Number(v) => CstInputValue::Number(v.to_string()),
        Value::String(v) => CstInputValue::String(v.clone()),
        Value::Array(v) => CstInputValue::Array(v.iter().map(input).collect()),
        Value::Object(v) => {
            CstInputValue::Object(v.iter().map(|(k, v)| (k.clone(), input(v))).collect())
        }
    }
}

pub struct Document {
    value: Value,
    format: Format,
    original: String,
}
enum Format {
    Toml(DocumentMut),
    Json(CstRootNode),
}
impl Document {
    pub fn parse(text: Option<&str>, host: Host) -> Result<Self> {
        let text = text.unwrap_or(if host == Host::Codex { "" } else { "{}\n" });
        let (value, format) = if host == Host::Codex {
            let doc: DocumentMut = text
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid TOML in host configuration"))?;
            let value = toml_edit::de::from_document(doc.clone())
                .map_err(|_| anyhow::anyhow!("invalid TOML in host configuration"))?;
            (value, Format::Toml(doc))
        } else {
            let (value, doc) = json(text)?;
            (value, Format::Json(doc))
        };
        Ok(Self {
            value,
            format,
            original: text.into(),
        })
    }
    fn servers(&self) -> &'static str {
        match self.format {
            Format::Toml(_) => "mcp_servers",
            Format::Json(_) => "mcpServers",
        }
    }
    pub fn server(&self) -> Result<Option<&Value>> {
        let servers = self.value.get(self.servers());
        ensure!(
            servers.is_none_or(Value::is_object),
            "MCP servers must be an object/table"
        );
        Ok(servers.and_then(|v| v.get("gent")))
    }
    pub fn set_server(mut self, value: Option<&Value>) -> Result<String> {
        if self.server()? == value {
            return Ok(self.original);
        }
        let key = self.servers();
        match &mut self.format {
            Format::Toml(doc) => {
                if doc.get(key).is_none() {
                    doc.insert(key, Item::Table(Table::new()));
                }
                let servers = doc[key]
                    .as_table_like_mut()
                    .context("MCP servers must be a table")?;
                if let Some(value) = value {
                    let mut generated =
                        toml_edit::ser::to_document(&serde_json::json!({"gent":value}))?;
                    let item = generated
                        .remove("gent")
                        .context("missing generated entry")?;
                    let table = item
                        .into_table()
                        .map_err(|_| anyhow::anyhow!("invalid generated entry"))?;
                    servers.insert("gent", Item::Table(table));
                } else {
                    servers.remove("gent");
                }
                Ok(doc.to_string())
            }
            Format::Json(doc) => {
                let servers = doc
                    .object_value()
                    .unwrap()
                    .object_value_or_create(key)
                    .context("MCP servers must be an object")?;
                if let Some(old) = servers.get("gent") {
                    if let Some(value) = value {
                        old.set_value(input(value));
                    } else {
                        old.remove();
                    }
                } else if let Some(value) = value {
                    servers.append("gent", input(value));
                }
                Ok(doc.to_string())
            }
        }
    }
    pub fn hooks_disabled(&self) -> bool {
        self.value["disableAllHooks"] == true
    }
    pub fn hook(&self) -> Result<Option<&Value>> {
        let hooks = self.value.get("hooks");
        ensure!(
            hooks.is_none_or(Value::is_object),
            "hooks must be an object"
        );
        let pre = hooks.and_then(|h| h.get("PreToolUse"));
        ensure!(
            pre.is_none_or(Value::is_array),
            "PreToolUse must be an array"
        );
        let mut selected = None;
        if let Some(pre) = pre.and_then(Value::as_array) {
            for hook in pre {
                ensure!(hook.is_object(), "PreToolUse entries must be objects");
                if hook["matcher"] == MATCHER {
                    ensure!(
                        selected.is_none(),
                        "duplicate Gent hook matchers; resolve before installing"
                    );
                    selected = Some(hook);
                }
            }
        }
        Ok(selected)
    }
    pub fn set_hook(self, value: Option<&Value>) -> Result<String> {
        if self.hook()? == value {
            return Ok(self.original);
        }
        let Format::Json(doc) = self.format else {
            anyhow::bail!("hooks require JSON");
        };
        let hooks = doc
            .object_value()
            .unwrap()
            .object_value_or_create("hooks")
            .context("hooks must be an object")?;
        let pre = hooks
            .array_value_or_create("PreToolUse")
            .context("PreToolUse must be an array")?;
        let index = self.value["hooks"]["PreToolUse"]
            .as_array()
            .and_then(|a| a.iter().position(|h| h["matcher"] == MATCHER));
        if let Some(index) = index {
            pre.elements()[index].clone().remove();
        }
        if let Some(value) = value {
            pre.append(input(value));
        }
        Ok(doc.to_string())
    }
}
