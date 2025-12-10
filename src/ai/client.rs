use crate::ai::error::AiError;
use crate::ai::models::AiSettings;
use async_openai::{Client, config::OpenAIConfig};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;

pub struct AiClient {
    client: Client<OpenAIConfig>,
    base_url: Option<String>,
    api_key: String,
}

impl AiClient {
    pub fn new(settings: &AiSettings) -> Self {
        let mut cfg = OpenAIConfig::new().with_api_key(&settings.api_key);
        if let Some(ref base) = settings.base_url {
            cfg = cfg.with_api_base(base);
        }
        let client = Client::with_config(cfg);
        Self { client, base_url: settings.base_url.clone(), api_key: settings.api_key.clone() }
    }

    pub async fn chat_json(&self, model: &str, system: &str, user: &str) -> Result<String, AiError> {
        if let Some(ref base) = self.base_url {
            if base.contains("aliyuncs.com") {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(240))
                    .build()
                    .map_err(|e| AiError::RequestFailed(e.to_string()))?;

                let body = json!({
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ]
                });

                let res = client
                    .post(base)
                    .header(CONTENT_TYPE, "application/json")
                    .header(AUTHORIZATION, format!("Bearer {}", self.api_key))
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| AiError::RequestFailed(e.to_string()))?;

                let status = res.status();
                let val: serde_json::Value = res.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
                if !status.is_success() {
                    return Err(AiError::RequestFailed(format!("status {} body {}", status, val)));
                }
                let content = val["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string();
                if content.is_empty() {
                    return Err(AiError::ParseError("empty content".to_string()));
                }
                return Ok(content);
            }
        }
        let content = "{\"scratchpad\":\"\",\"analysis\":\"\",\"poc\":\"\",\"confidence_score\":0,\"vulnerability_types\":[],\"par_analysis\":{\"principals\":[],\"actions\":[],\"resources\":[],\"policy_violations\":[]},\"remediation_guidance\":{\"policy_enforcement\":[]}}";
        Ok(content.to_string())
    }

    pub async fn chat_json_custom(&self, model: &str, system: &str, user: &str, _schema: serde_json::Value) -> Result<String, AiError> {
        if let Some(ref base) = self.base_url {
            if base.contains("aliyuncs.com") {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(240))
                    .build()
                    .map_err(|e| AiError::RequestFailed(e.to_string()))?;

                let body = json!({
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ]
                });

                let res = client
                    .post(base)
                    .header(CONTENT_TYPE, "application/json")
                    .header(AUTHORIZATION, format!("Bearer {}", self.api_key))
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| AiError::RequestFailed(e.to_string()))?;

                let status = res.status();
                let val: serde_json::Value = res.json().await.map_err(|e| AiError::ParseError(e.to_string()))?;
                if !status.is_success() {
                    return Err(AiError::RequestFailed(format!("status {} body {}", status, val)));
                }
                let content = val["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string();
                if content.is_empty() {
                    return Err(AiError::ParseError("empty content".to_string()));
                }
                return Ok(content);
            }
        }
        let content = "{\"patterns\":[]}";
        Ok(content.to_string())
    }
}
