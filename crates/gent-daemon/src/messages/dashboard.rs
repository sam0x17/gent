//! Dashboard rows, V9 records and hosted checkpoints all carry the same
//! representation. Old carriers may parse and serialize any of them.
use anyhow::{Context, Result, ensure};
use gent_protocol::dashboard::{Board, Kind, Widget, web_url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const LINK_UNIT: &str = "↗ web link";
const EVENTS_UNIT: &str = "Gent widget v1";
const CHUNK_BYTES: usize = 2048;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
    kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x_unit: Option<String>,
}

fn advanced(kind: Kind) -> bool {
    match kind {
        Kind::Metric | Kind::Bar | Kind::Pie | Kind::Radar | Kind::Scatter | Kind::Image => true,
        Kind::Text
        | Kind::Events
        | Kind::Graph
        | Kind::Gauge
        | Kind::Progress
        | Kind::Button
        | Kind::Link => false,
    }
}

pub(crate) fn check_encoding(board: &Board) -> Result<(), &'static str> {
    if board
        .widgets
        .iter()
        .any(|w| w.x_unit.is_some() || w.kind == Kind::Link || advanced(w.kind))
    {
        return Err("encode dashboard widgets in their portable representation");
    }
    Ok(())
}

pub(crate) fn encode_board(board: &mut Board) -> Result<()> {
    board.validate().map_err(anyhow::Error::msg)?;
    let mut changed = false;
    for widget in &mut board.widgets {
        if widget.kind == Kind::Link {
            widget.kind = Kind::Text;
            widget.unit = Some(LINK_UNIT.into());
            changed = true;
        } else if advanced(widget.kind) {
            let header = Header {
                kind: widget.kind,
                unit: widget.unit.take(),
                x_unit: widget.x_unit.take(),
            };
            let payload = serde_json::to_string(&widget.value)?;
            let mut events = vec![Value::String(serde_json::to_string(&header)?)];
            let mut rest = payload.as_str();
            while !rest.is_empty() {
                let (chunk, tail) = rest.split_at(rest.floor_char_boundary(CHUNK_BYTES));
                events.push(Value::String(chunk.to_owned()));
                rest = tail;
            }
            widget.kind = Kind::Events;
            widget.unit = Some(EVENTS_UNIT.into());
            widget.value = Value::Array(events);
            changed = true;
        }
    }
    if changed {
        board.validate().map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn unpack_value(value: &Value) -> Option<(Header, Value)> {
    let (header, chunks) = value.as_array()?.split_first()?;
    let header: Header = serde_json::from_str(header.as_str()?).ok()?;
    if !advanced(header.kind) {
        return None;
    }
    let mut payload = String::new();
    for chunk in chunks {
        payload.push_str(chunk.as_str()?);
    }
    Some((header, serde_json::from_str(&payload).ok()?))
}

fn unpack(widget: &Widget) -> Option<Widget> {
    let (header, value) = unpack_value(&widget.value)?;
    let restored = Widget {
        kind: header.kind,
        unit: header.unit,
        x_unit: header.x_unit,
        value,
        id: widget.id.clone(),
        label: widget.label.clone(),
        min: widget.min,
        max: widget.max,
    };
    restored.validate().ok()?;
    Some(restored)
}

pub(crate) fn display_board(mut board: Board) -> Board {
    for widget in &mut board.widgets {
        match (widget.kind, widget.unit.as_deref()) {
            (Kind::Text, Some(LINK_UNIT)) if widget.value.as_str().is_some_and(web_url) => {
                widget.kind = Kind::Link;
                widget.unit = None;
            }
            (Kind::Events, Some(EVENTS_UNIT)) => {
                // An older publisher can use arbitrary event strings and units.
                // Only a complete, valid envelope opts into the new meaning.
                if let Some(restored) = unpack(widget) {
                    *widget = restored;
                }
            }
            _ => {}
        }
    }
    board
}

/// Normalize the retry payload as well as the board. An old carrier sees
/// the same values on a retry after hosted failover.
pub(crate) fn update_board(stored: Board, values: &mut BTreeMap<String, Value>) -> Result<Board> {
    ensure!(
        !values.is_empty() && values.len() <= 32,
        "supply 1–32 widget values"
    );
    let mut board = display_board(stored);
    for (key, value) in values.iter_mut() {
        let widget = board
            .widgets
            .iter_mut()
            .find(|w| &w.id == key)
            .context("unknown widget")?;
        if advanced(widget.kind)
            && let Some((header, data)) = unpack_value(value)
        {
            ensure!(
                header.kind == widget.kind
                    && header.unit == widget.unit
                    && header.x_unit == widget.x_unit,
                "a widget value update cannot change the kind or units"
            );
            widget.value = data;
        } else {
            widget.value = value.take();
        }
    }
    encode_board(&mut board)?;
    for widget in &board.widgets {
        if let Some(value) = values.get_mut(&widget.id) {
            *value = widget.value.clone();
        }
    }
    Ok(board)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gent_protocol::dashboard::MAX_BOARD_BYTES;
    use serde_json::json;

    #[test]
    fn portable_form_must_fit_the_legacy_board_limit() {
        let mut widgets = vec![json!({"id":"m","kind":"metric","label":"M","value":4})];
        for i in 0..16 {
            widgets.push(json!({"id":format!("s{i}"),"kind":"text","label":"S","value":""}));
        }
        let mut board: Board =
            serde_json::from_value(json!({"title":"Run","widgets":widgets})).unwrap();
        let mut space = MAX_BOARD_BYTES - serde_json::to_vec(&board).unwrap().len();
        for widget in &mut board.widgets[1..] {
            let n = space.min(CHUNK_BYTES);
            widget.value = Value::String("x".repeat(n));
            space -= n;
        }
        assert_eq!(space, 0);
        assert_eq!(serde_json::to_vec(&board).unwrap().len(), MAX_BOARD_BYTES);
        board.validate().unwrap();
        assert!(encode_board(&mut board).is_err());
    }
}
