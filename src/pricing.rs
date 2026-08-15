use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, de::MapAccess};
use serde_json::Value;

use crate::{
    error::{AppError, Result},
    security::sha256_hex,
};

#[derive(Clone, Debug)]
pub struct PricingOption {
    pub key: &'static str,
    pub source_field: &'static str,
    pub canonical_json: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PricingConfig {
    model_price: StrictPriceMap,
    model_ratio: StrictPriceMap,
    cache_ratio: StrictPriceMap,
    create_cache_ratio: StrictPriceMap,
    completion_ratio: StrictPriceMap,
    image_ratio: StrictPriceMap,
    audio_ratio: StrictPriceMap,
    audio_completion_ratio: StrictPriceMap,
}

impl PricingConfig {
    pub fn from_value(value: Value) -> std::result::Result<Self, String> {
        serde_json::from_value(value).map_err(|error| error.to_string())
    }

    pub fn options(&self) -> Result<Vec<PricingOption>> {
        [
            ("ModelPrice", "model_price", &self.model_price),
            ("ModelRatio", "model_ratio", &self.model_ratio),
            ("CacheRatio", "cache_ratio", &self.cache_ratio),
            (
                "CreateCacheRatio",
                "create_cache_ratio",
                &self.create_cache_ratio,
            ),
            (
                "CompletionRatio",
                "completion_ratio",
                &self.completion_ratio,
            ),
            ("ImageRatio", "image_ratio", &self.image_ratio),
            ("AudioRatio", "audio_ratio", &self.audio_ratio),
            (
                "AudioCompletionRatio",
                "audio_completion_ratio",
                &self.audio_completion_ratio,
            ),
        ]
        .into_iter()
        .map(|(key, source_field, values)| {
            let canonical_json = serde_json::to_string(&values.0).map_err(|error| {
                AppError::State(format!(
                    "serialize source pricing field {source_field}: {error}"
                ))
            })?;
            Ok(PricingOption {
                key,
                source_field,
                sha256: sha256_hex(canonical_json.as_bytes()),
                canonical_json,
            })
        })
        .collect()
    }
}

pub fn canonical_price_json(source: &str) -> std::result::Result<String, String> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let parsed =
        StrictPriceMap::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    serde_json::to_string(&parsed.0).map_err(|error| error.to_string())
}

#[derive(Clone, Debug)]
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
    fn source_configuration_maps_all_eight_options() {
        let config = PricingConfig::from_value(serde_json::json!({
            "model_price": {"fixed": 2},
            "model_ratio": {"input": 1},
            "cache_ratio": {"cache": 0.5},
            "create_cache_ratio": {"create": 1.25},
            "completion_ratio": {"output": 3},
            "image_ratio": {"image": 4},
            "audio_ratio": {"audio": 5},
            "audio_completion_ratio": {"audio-output": 6}
        }))
        .expect("parse source pricing");

        let options = config.options().expect("build pricing options");
        assert_eq!(options.len(), 8);
        assert_eq!(options[0].key, "ModelPrice");
        assert_eq!(options[0].source_field, "model_price");
        assert_eq!(options[0].canonical_json, r#"{"fixed":2.0}"#);
        assert!(options.iter().all(|option| option.sha256.len() == 64));
    }

    #[test]
    fn source_configuration_requires_all_fields_and_valid_maps() {
        let missing = serde_json::json!({
            "model_price": {},
            "model_ratio": {},
            "cache_ratio": {},
            "create_cache_ratio": {},
            "completion_ratio": {},
            "image_ratio": {},
            "audio_ratio": {}
        });
        assert!(PricingConfig::from_value(missing).is_err());

        let invalid = serde_json::json!({
            "model_price": {"": 1},
            "model_ratio": {},
            "cache_ratio": {},
            "create_cache_ratio": {},
            "completion_ratio": {},
            "image_ratio": {},
            "audio_ratio": {},
            "audio_completion_ratio": {}
        });
        assert!(PricingConfig::from_value(invalid).is_err());
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
