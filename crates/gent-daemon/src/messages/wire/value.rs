//! Keep duplicate-field rejection while a codec translates an event's keys.
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
    struct Strict(Value);
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            deserialize(d).map(Self)
        }
    }
    struct Json;
    impl<'de> Visitor<'de> for Json {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("JSON with unique object keys")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Value, M::Error> {
            let mut values = Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if values.contains_key(&key) {
                    return Err(de::Error::custom("duplicate wire field"));
                }
                values.insert(key, map.next_value::<Strict>()?.0);
            }
            Ok(Value::Object(values))
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Value, S::Error> {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element::<Strict>()? {
                values.push(value.0);
            }
            Ok(Value::Array(values))
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
            Ok(value.into())
        }
        fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
            Ok(value.into())
        }
        fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
            Ok(value.into())
        }
        fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
            Ok(value.into())
        }
        fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
            Ok(value.into())
        }
        fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
            Number::from_f64(value)
                .map(Value::Number)
                .ok_or_else(|| de::Error::custom("invalid JSON number"))
        }
        fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_none<E: de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
    }
    d.deserialize_any(Json)
}
