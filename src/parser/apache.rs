use crate::{LogEvent, Severity, EventType};
use anyhow::Result;
use regex::Regex;
use chrono::{DateTime, Utc, NaiveDateTime};
use uuid::Uuid;
use std::str::FromStr;


#[derive(Clone)]
pub struct ApacheParser {
    common_log_regex: Regex,
    combined_log_regex: Regex,
    main_regex: Regex,
}

impl ApacheParser {
    pub fn new() -> Self {
        let common_log_regex = Regex::new(
            r#"^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)"#
        ).unwrap();

        let combined_log_regex = Regex::new(
            r#"^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)""#
        ).unwrap();
        let main_regex = combined_log_regex.clone();

        Self {
            common_log_regex,
            combined_log_regex,
            main_regex,
        }
    }

    pub fn parse_line(&self, line: &str) -> Result<LogEvent> {
        // Intentar primero con formato combined (más completo)
        if let Some(captures) = self.combined_log_regex.captures(line) {
            return self.parse_combined_format(line, captures);
        }

        // Fallback a formato common
        if let Some(captures) = self.common_log_regex.captures(line) {
            return self.parse_common_format(line, captures);
        }

        // Si no coincide con ningún formato, crear evento genérico
        Ok(LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "apache_unknown".to_string(),
            severity: Severity::Info,
            source_ip: None,
            raw_message: line.to_string(),
            parsed_data: serde_json::json!({
                "format": "unknown",
                "raw": line
            }),
            event_type: EventType::Normal,
            iocs: Vec::new(),
        })
    }

    fn parse_combined_format(&self, line: &str, captures: regex::Captures) -> Result<LogEvent> {
        let ip = captures.get(1).unwrap().as_str();
        let timestamp_str = captures.get(2).unwrap().as_str();
        let method = captures.get(3).unwrap().as_str();
        let path = captures.get(4).unwrap().as_str();
        let protocol = captures.get(5).unwrap().as_str();
        let status_code = captures.get(6).unwrap().as_str().parse::<u16>().unwrap_or(0);
        let size = captures.get(7).unwrap().as_str();
        let referer = captures.get(8).unwrap().as_str();
        let user_agent = captures.get(9).unwrap().as_str();

        let timestamp = self.parse_apache_timestamp(timestamp_str)?;
        let severity = self.determine_severity(status_code, method, path);
        let event_type = self.determine_event_type(method, path, status_code);

        Ok(LogEvent {
            id: Uuid::new_v4(),
            timestamp,
            source: "apache".to_string(),
            severity,
            source_ip: Some(ip.to_string()),
            raw_message: line.to_string(),
            parsed_data: serde_json::json!({
                "ip": ip,
                "method": method,
                "path": path,
                "protocol": protocol,
                "status_code": status_code,
                "size": size,
                "referer": referer,
                "user_agent": user_agent,
                "format": "combined"
            }),
            event_type,
            iocs: self.extract_iocs(path, user_agent),
        })
    }

    fn parse_common_format(&self, line: &str, captures: regex::Captures) -> Result<LogEvent> {
        let ip = captures.get(1).unwrap().as_str();
        let timestamp_str = captures.get(2).unwrap().as_str();
        let method = captures.get(3).unwrap().as_str();
        let path = captures.get(4).unwrap().as_str();
        let protocol = captures.get(5).unwrap().as_str();
        let status_code = captures.get(6).unwrap().as_str().parse::<u16>().unwrap_or(0);
        let size = captures.get(7).unwrap().as_str();

        let timestamp = self.parse_apache_timestamp(timestamp_str)?;
        let severity = self.determine_severity(status_code, method, path);
        let event_type = self.determine_event_type(method, path, status_code);

        Ok(LogEvent {
            id: Uuid::new_v4(),
            timestamp,
            source: "apache".to_string(),
            severity,
            source_ip: Some(ip.to_string()),
            raw_message: line.to_string(),
            parsed_data: serde_json::json!({
                "ip": ip,
                "method": method,
                "path": path,
                "protocol": protocol,
                "status_code": status_code,
                "size": size,
                "format": "common"
            }),
            event_type,
            iocs: self.extract_iocs(path, ""),
        })
    }

    fn parse_apache_timestamp(&self, timestamp_str: &str) -> Result<DateTime<Utc>> {
        // Formato Apache: [10/Oct/2000:13:55:36 +0000]
        let cleaned = timestamp_str.replace("[", "").replace("]", "");

        // Intentar parsear con diferentes formatos
        if let Ok(dt) = DateTime::parse_from_str(&cleaned, "%d/%b/%Y:%H:%M:%S %z") {
            return Ok(dt.with_timezone(&Utc));
        }

        // Fallback a timestamp actual si falla el parsing
        Ok(Utc::now())
    }

    fn determine_severity(&self, status_code: u16, _method: &str, path: &str) -> Severity {
        match status_code {
            500..=599 => Severity::Critical,
            400..=499 => {
                if status_code == 404 && path.contains("admin") {
                    Severity::Warning
                } else if status_code == 403 {
                    Severity::Warning
                } else {
                    Severity::Info
                }
            },
            _ => Severity::Info,
        }
    }

    fn determine_event_type(&self, method: &str, path: &str, status_code: u16) -> EventType {
        let path_lower = path.to_lowercase();

        // Detectar posibles ataques por patrones en la URL
        if path_lower.contains("union") || path_lower.contains("select") ||
            path_lower.contains("drop") || path_lower.contains("insert") {
            return EventType::SqlInjection;
        }

        if path_lower.contains("<script") || path_lower.contains("javascript:") ||
            path_lower.contains("onerror") || path_lower.contains("onload") {
            return EventType::XssAttempt;
        }

        if method == "POST" && status_code == 401 {
            return EventType::BruteForce;
        }

        EventType::Normal
    }

    fn extract_iocs(&self, path: &str, user_agent: &str) -> Vec<String> {
        let mut iocs = Vec::new();

        // IOCs comunes en ataques web
        let suspicious_patterns = [
            "union select", "drop table", "../../../", "cmd.exe",
            "powershell", "/etc/passwd", "base64_decode", "eval(",
            "<script>", "javascript:", "document.cookie"
        ];

        let combined_text = format!("{} {}", path.to_lowercase(), user_agent.to_lowercase());

        for pattern in &suspicious_patterns {
            if combined_text.contains(pattern) {
                iocs.push(pattern.to_string());
            }
        }

        iocs
    }
}

impl Default for ApacheParser {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::parser::common::LogParser for ApacheParser {
    fn parse_line(&self, line: &str) -> Result<LogEvent> {
        self.parse_line(line)
    }

    fn can_parse(&self, line: &str) -> bool {
        self.common_log_regex.is_match(line) || self.combined_log_regex.is_match(line)
    }

    // AÑADIR estos dos métodos:
    fn parser_name(&self) -> &'static str {
        "apache"
    }

    fn main_regex(&self) -> &Regex {
        &self.main_regex
    }
}