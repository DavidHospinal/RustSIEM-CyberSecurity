use crate::{LogEvent, Severity, EventType};
use anyhow::Result;
use regex::Regex;
use chrono::Utc;
use uuid::Uuid;
#[derive(Clone)]
pub struct SshParser {
    auth_regex: Regex,
    main_regex: Regex,
}

impl SshParser {
    pub fn new() -> Self {
        let auth_regex = Regex::new(
            r"(?i)(failed|accepted|invalid)\s+(password|publickey|keyboard-interactive)\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)"
        ).unwrap();
        let main_regex = auth_regex.clone();

        Self {
            auth_regex,
            main_regex,
        }
    }

    pub fn parse_line(&self, line: &str) -> Result<LogEvent> {
        // Implementación básica para SSH logs
        let log_event = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "ssh".to_string(),
            severity: Severity::Info,
            source_ip: self.extract_ip(line),
            raw_message: line.to_string(),
            parsed_data: serde_json::Value::Object(serde_json::Map::new()),
            event_type: EventType::Normal,
            iocs: vec![],
        };

        Ok(log_event)
    }

    fn extract_ip(&self, line: &str) -> Option<String> {
        // Básica extracción de IP para SSH
        let ip_regex = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        ip_regex.find(line).map(|m| m.as_str().to_string())
    }
}

impl Default for SshParser {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::parser::common::LogParser for SshParser {
    fn parse_line(&self, line: &str) -> Result<LogEvent> {
        self.parse_line(line)
    }

    fn can_parse(&self, line: &str) -> bool {
        line.contains("ssh") || line.contains("sshd")
    }

    // AÑADIR estos dos métodos:
    fn parser_name(&self) -> &'static str {
        "ssh"
    }

    fn main_regex(&self) -> &Regex {
        &self.main_regex
    }
}