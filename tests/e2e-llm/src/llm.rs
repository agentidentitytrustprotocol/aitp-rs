//! Tiny LLM-provider abstraction. The whole tier-3 story is "take a
//! task string, produce an answer string", so we sidestep `rig-core`
//! and call the provider HTTP APIs directly. Two providers supported:
//! Anthropic Messages and OpenAI Chat Completions. Provider selection
//! is by env vars: `ANTHROPIC_API_KEY` wins, then `OPENAI_API_KEY`.

use anyhow::{anyhow, Context};
use serde_json::json;

const ANTHROPIC_DEFAULT_MODEL: &str = "claude-haiku-4-5";
const OPENAI_DEFAULT_MODEL: &str = "gpt-4o-mini";

/// Which provider this run will call. Resolved once at the start of a
/// test so failures are reported up front.
#[derive(Debug, Clone)]
pub enum Provider {
    Anthropic { api_key: String, model: String },
    OpenAi { api_key: String, model: String },
}

impl Provider {
    /// Pick a provider from env vars. Returns `Err` if neither key is
    /// set — callers should treat this as a configuration error, not
    /// a skip (the skip decision happens earlier in `should_skip`).
    pub fn from_env() -> anyhow::Result<Self> {
        let model_override = std::env::var("AITP_LLM_MODEL").ok();
        if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
            if !api_key.is_empty() {
                return Ok(Provider::Anthropic {
                    api_key,
                    model: model_override.unwrap_or_else(|| ANTHROPIC_DEFAULT_MODEL.into()),
                });
            }
        }
        if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
            if !api_key.is_empty() {
                return Ok(Provider::OpenAi {
                    api_key,
                    model: model_override.unwrap_or_else(|| OPENAI_DEFAULT_MODEL.into()),
                });
            }
        }
        Err(anyhow!(
            "no LLM provider configured (set ANTHROPIC_API_KEY or OPENAI_API_KEY)"
        ))
    }

    pub fn label(&self) -> String {
        match self {
            Provider::Anthropic { model, .. } => format!("anthropic/{model}"),
            Provider::OpenAi { model, .. } => format!("openai/{model}"),
        }
    }
}

/// Prompt the configured provider with a `system` instruction and a
/// `user` message. Returns the assistant's text reply.
pub async fn complete(provider: &Provider, system: &str, user: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("build reqwest client")?;

    match provider {
        Provider::Anthropic { api_key, model } => {
            let body = json!({
                "model": model,
                "max_tokens": 512,
                "system": system,
                "messages": [
                    { "role": "user", "content": user }
                ],
            });
            let resp = client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .context("anthropic request")?;
            let status = resp.status();
            let value: serde_json::Value = resp.json().await.context("anthropic response json")?;
            if !status.is_success() {
                return Err(anyhow!("anthropic {status}: {value}"));
            }
            // Response shape: { "content": [ { "type": "text", "text": "..." }, ... ] }
            let text = value
                .get("content")
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.iter().find_map(|b| b.get("text").and_then(|t| t.as_str())))
                .ok_or_else(|| anyhow!("anthropic response missing content[].text: {value}"))?
                .to_string();
            Ok(text)
        }
        Provider::OpenAi { api_key, model } => {
            let body = json!({
                "model": model,
                "max_tokens": 512,
                "messages": [
                    { "role": "system", "content": system },
                    { "role": "user",   "content": user   },
                ],
            });
            let resp = client
                .post("https://api.openai.com/v1/chat/completions")
                .bearer_auth(api_key)
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .context("openai request")?;
            let status = resp.status();
            let value: serde_json::Value = resp.json().await.context("openai response json")?;
            if !status.is_success() {
                return Err(anyhow!("openai {status}: {value}"));
            }
            // Response shape: { "choices": [ { "message": { "content": "..." } } ] }
            let text = value
                .pointer("/choices/0/message/content")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("openai response missing choices[0].message.content: {value}"))?
                .to_string();
            Ok(text)
        }
    }
}
