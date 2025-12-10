use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AiSettings {
    pub api_key: String,
    pub base_url: Option<String>,
    pub model: String,
    pub org_id: Option<String>,
    pub project_id: Option<String>,
    pub timeout_secs: u64,
    pub retries: u32,
}

impl AiSettings {
    pub fn from_config(cfg: &crate::config::ParsentryConfig) -> Option<Self> {
        let api_key = cfg
            .api
            .api_keys
            .get("dashscope")
            .or_else(|| cfg.api.api_keys.get("openai"))
            .or_else(|| cfg.api.api_keys.get("groq"))
            .or_else(|| cfg.api.api_keys.get("azure"))
            .cloned()?;

        Some(Self {
            api_key,
            base_url: cfg.api.base_url.clone(),
            model: cfg.analysis.model.clone(),
            org_id: None,
            project_id: None,
            timeout_secs: 240,
            retries: 2,
        })
    }
}
