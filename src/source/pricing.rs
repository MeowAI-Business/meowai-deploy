use reqwest::Method;
use serde_json::Value;

use crate::pricing::PricingConfig;

use super::{SourceClient, SourceError, SourceResult, require_data};

impl SourceClient {
    pub async fn pricing(&mut self) -> SourceResult<PricingConfig> {
        const ENDPOINT: &str = "/api/onboard/pricing";
        let envelope = self
            .authenticated_request::<Value>(Method::GET, ENDPOINT, None)
            .await?;
        let data = require_data(envelope, ENDPOINT)?;
        PricingConfig::from_value(data).map_err(|message| SourceError::InvalidResponse {
            endpoint: ENDPOINT.to_owned(),
            message,
        })
    }
}
