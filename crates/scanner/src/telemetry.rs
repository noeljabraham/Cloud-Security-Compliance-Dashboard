use serde::Serialize;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

const SENSITIVE_PATTERNS: &[&str] = &[
    "token",
    "secret",
    "password",
    "authorization",
    "credential",
    "bearer",
    "api_key",
    "access_key",
];

pub fn redact_sensitive_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::new();
            for (key, val) in map {
                let lower_key = key.to_lowercase();
                if SENSITIVE_PATTERNS
                    .iter()
                    .any(|pattern| lower_key.contains(pattern))
                {
                    sanitized.insert(key.clone(), json!("[REDACTED]"));
                } else {
                    sanitized.insert(key.clone(), redact_sensitive_value(val));
                }
            }
            Value::Object(sanitized)
        }
        Value::Array(arr) => {
            let sanitized: Vec<Value> = arr.iter().map(redact_sensitive_value).collect();
            Value::Array(sanitized)
        }
        Value::String(s) => {
            let lower = s.to_lowercase();
            if lower.starts_with("bearer ")
                || lower.starts_with("basic ")
                || lower.contains("aws_secret_access_key")
            {
                json!("[REDACTED]")
            } else {
                Value::String(s.clone())
            }
        }
        _ => value.clone(),
    }
}

#[derive(Debug, Serialize)]
pub struct StructuredLog {
    pub timestamp_ms: u64,
    pub level: &'static str,
    pub trace_id: String,
    pub message: String,
    pub context: Value,
}

impl StructuredLog {
    pub fn new(level: &'static str, trace_id: &str, message: &str, context: Value) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            timestamp_ms,
            level,
            trace_id: trace_id.to_string(),
            message: message.to_string(),
            context: redact_sensitive_value(&context),
        }
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}
