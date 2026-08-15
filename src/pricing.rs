use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, de::MapAccess};

use crate::{
    error::{AppError, Result},
    security::sha256_hex,
};

const SNAPSHOTS: [(&str, &str, &str); 8] = [
    (
        "ModelPrice",
        "模型固定定价.json",
        include_str!("../assets/pricing/模型固定定价.json"),
    ),
    (
        "ModelRatio",
        "模型倍率.json",
        include_str!("../assets/pricing/模型倍率.json"),
    ),
    (
        "CacheRatio",
        "提示缓存倍率.json",
        include_str!("../assets/pricing/提示缓存倍率.json"),
    ),
    (
        "CreateCacheRatio",
        "创建缓存倍率.json",
        include_str!("../assets/pricing/创建缓存倍率.json"),
    ),
    (
        "CompletionRatio",
        "补全倍率.json",
        include_str!("../assets/pricing/补全倍率.json"),
    ),
    (
        "ImageRatio",
        "图片倍率.json",
        include_str!("../assets/pricing/图片倍率.json"),
    ),
    (
        "AudioRatio",
        "音频倍率.json",
        include_str!("../assets/pricing/音频倍率.json"),
    ),
    (
        "AudioCompletionRatio",
        "音频补全倍率.json",
        include_str!("../assets/pricing/音频补全倍率.json"),
    ),
];

#[derive(Clone, Debug)]
pub struct PricingOption {
    pub key: &'static str,
    pub file_name: &'static str,
    pub canonical_json: String,
    pub sha256: String,
}

pub fn embedded_pricing() -> Result<Vec<PricingOption>> {
    SNAPSHOTS
        .iter()
        .map(|(key, file_name, source)| {
            let canonical_json = canonical_price_json(source).map_err(|error| {
                AppError::State(format!("invalid embedded price file {file_name}: {error}"))
            })?;
            Ok(PricingOption {
                key,
                file_name,
                sha256: sha256_hex(canonical_json.as_bytes()),
                canonical_json,
            })
        })
        .collect()
}

pub fn canonical_price_json(source: &str) -> std::result::Result<String, String> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let parsed =
        StrictPriceMap::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    serde_json::to_string(&parsed.0).map_err(|error| error.to_string())
}

struct StrictPriceMap(BTreeMap<String, f64>);

impl<'de> Deserialize<'de> for StrictPriceMap {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(StrictPriceVisitor)
    }
}

struct StrictPriceVisitor;

impl<'de> serde::de::Visitor<'de> for StrictPriceVisitor {
    type Value = StrictPriceMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object mapping non-empty model names to finite numbers")
    }

    fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(raw_key) = access.next_key::<String>()? {
            let key = raw_key.trim();
            if key.is_empty() {
                return Err(serde::de::Error::custom("model name cannot be empty"));
            }
            if values.contains_key(key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate model name {key}"
                )));
            }
            let value = access.next_value::<f64>()?;
            if !value.is_finite() {
                return Err(serde::de::Error::custom(format!(
                    "price for {key} must be finite"
                )));
            }
            values.insert(key.to_owned(), value);
        }
        Ok(StrictPriceMap(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_price_snapshots_are_valid() {
        let snapshots = embedded_pricing().expect("parse snapshots");
        assert_eq!(snapshots.len(), 8);
        assert!(snapshots.iter().all(|snapshot| snapshot.sha256.len() == 64));
    }

    #[test]
    fn parser_rejects_duplicates_non_numbers_and_trailing_content() {
        assert!(canonical_price_json(r#"{"gpt":1,"gpt":2}"#).is_err());
        assert!(canonical_price_json(r#"{"gpt":"one"}"#).is_err());
        assert!(canonical_price_json(r#"{"gpt":1} trailing"#).is_err());
        assert!(canonical_price_json(r#"{"":1}"#).is_err());
    }

    #[test]
    fn canonical_output_is_sorted() {
        assert_eq!(
            canonical_price_json(r#"{"z":2,"a":1}"#).expect("canonicalize"),
            r#"{"a":1.0,"z":2.0}"#
        );
    }
}
