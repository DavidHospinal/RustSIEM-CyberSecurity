use crate::{LogEvent, Severity, EventType};
use crate::parser::common::{LogParser, extract_source_ip, detect_event_type, log_level_to_severity};
use anyhow::{Result, Context};
use regex::Regex;
use chrono::{DateTime, Utc, NaiveDateTime};
use uuid::Uuid;
use std::collections::HashMap;

pub struct NginxParser {
    access_log_regex: Regex,
    error_log_regex: Regex,
    custom_log_regex: Regex,
}

impl NginxParser {
    pub fn new() -> Self {
        // Nginx access log format típico: log_format combined
        let access_log_regex = Regex::new(
            r#"^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"(?:\s+"([^"]*)")?(?:\s+(\S+))?.*$"#
        ).unwrap();

        // Nginx error log format
        let error_log_regex = Regex::new(
            r#"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): (.+?)(?:, client: (\S+))?(?:, server: (\S+))?(?:, request: "([^"]*)")?(?:, host: "([^"]*)")?.*$"#
        ).unwrap();

        // Formato personalizado de Nginx
        let custom_log_regex = Regex::new(
            r#"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "([^"]*)" "([^"]*)" rt=(\d+\.\d+) uct="([^"]*)" uht="([^"]*)" urt="([^"]*)""#
        ).unwrap();

        Self {
            access_log_regex,
            error_log_regex,
            custom_log_regex,
        }
    }

    fn parse_access_log(&self, line: &str) -> Result<LogEvent> {
        if let Some(captures) = self.access_log_regex.captures(line) {
            let ip = captures.get(1).unwrap().as_str();
            let user = captures.get(2).unwrap().as_str();
            let timestamp_str = captures.get(3).unwrap().as_str();
            let request = captures.get(4).unwrap().as_str();
            let status_code = captures.get(5).unwrap().as_str().parse::<u16>().unwrap_or(0);
            let body_bytes = captures.get(6).unwrap().as_str();
            let referer = captures.get(7).unwrap().as_str();
            let user_agent = captures.get(8).unwrap().as_str();
            let forwarded_for = captures.get(9).map(|m| m.as_str()).unwrap_or("-");
            let request_time = captures.get(10).map(|m| m.as_str()).unwrap_or("-");

            let timestamp = self.parse_nginx_timestamp(timestamp_str)?;
            let severity = self.determine_severity_from_status(status_code);

            // Parsear la línea de request para extraer método, path y protocolo
            let (method, path, protocol) = self.parse_request_line(request);

            let mut parsed_data = HashMap::new();
            parsed_data.insert("ip".to_string(), ip.to_string());
            parsed_data.insert("user".to_string(), user.to_string());
            parsed_data.insert("method".to_string(), method.clone());
            parsed_data.insert("path".to_string(), path.clone());
            parsed_data.insert("protocol".to_string(), protocol);
            parsed_data.insert("status_code".to_string(), status_code.to_string());
            parsed_data.insert("body_bytes".to_string(), body_bytes.to_string());
            parsed_data.insert("referer".to_string(), referer.to_string());
            parsed_data.insert("user_agent".to_string(), user_agent.to_string());
            parsed_data.insert("forwarded_for".to_string(), forwarded_for.to_string());
            parsed_data.insert("request_time".to_string(), request_time.to_string());
            parsed_data.insert("log_type".to_string(), "access".to_string());

            let event_type = detect_event_type(line, &parsed_data);
            let iocs = self.extract_iocs(&path, user_agent, &method);

            Ok(LogEvent {
                id: Uuid::new_v4(),
                timestamp,
                source: "nginx_access".to_string(),
                severity,
                source_ip: Some(ip.to_string()),
                raw_message: line.to_string(),
                parsed_data: serde_json::to_value(parsed_data)
                    .context("Error serializando datos parseados")?,
                event_type,
                iocs,
            })
        } else {
            Err(anyhow::anyhow!("No coincide con formato de access log de Nginx"))
        }
    }

    fn parse_error_log(&self, line: &str) -> Result<LogEvent> {
        if let Some(captures) = self.error_log_regex.captures(line) {
            let timestamp_str = captures.get(1).unwrap().as_str();
            let log_level = captures.get(2).unwrap().as_str();
            let pid = captures.get(3).unwrap().as_str();
            let tid = captures.get(4).unwrap().as_str();
            let message = captures.get(5).unwrap().as_str();
            let client_ip = captures.get(6).map(|m| m.as_str()).unwrap_or("-");
            let server = captures.get(7).map(|m| m.as_str()).unwrap_or("-");
            let request = captures.get(8).map(|m| m.as_str()).unwrap_or("-");
            let host = captures.get(9).map(|m| m.as_str()).unwrap_or("-");

            let timestamp = self.parse_nginx_error_timestamp(timestamp_str)?;
            let severity = self.determine_severity_from_level(log_level);

            let mut parsed_data = HashMap::new();
            parsed_data.insert("log_level".to_string(), log_level.to_string());
            parsed_data.insert("pid".to_string(), pid.to_string());
            parsed_data.insert("tid".to_string(), tid.to_string());
            parsed_data.insert("message".to_string(), message.to_string());
            parsed_data.insert("client_ip".to_string(), client_ip.to_string());
            parsed_data.insert("server".to_string(), server.to_string());
            parsed_data.insert("request".to_string(), request.to_string());
            parsed_data.insert("host".to_string(), host.to_string());
            parsed_data.insert("log_type".to_string(), "error".to_string());

            let event_type = detect_event_type(line, &parsed_data);
            let iocs = self.extract_error_iocs(message, request);

            Ok(LogEvent {
                id: Uuid::new_v4(),
                timestamp,
                source: "nginx_error".to_string(),
                severity,
                source_ip: if client_ip != "-" { Some(client_ip.to_string()) } else { None },
                raw_message: line.to_string(),
                parsed_data: serde_json::to_value(parsed_data)
                    .context("Error serializando datos parseados")?,
                event_type,
                iocs,
            })
        } else {
            Err(anyhow::anyhow!("No coincide con formato de error log de Nginx"))
        }
    }

    fn parse_custom_log(&self, line: &str) -> Result<LogEvent> {
        if let Some(captures) = self.custom_log_regex.captures(line) {
            let ip = captures.get(1).unwrap().as_str();
            let timestamp_str = captures.get(2).unwrap().as_str();
            let request = captures.get(3).unwrap().as_str();
            let status_code = captures.get(4).unwrap().as_str().parse::<u16>().unwrap_or(0);
            let body_bytes = captures.get(5).unwrap().as_str();
            let referer = captures.get(6).unwrap().as_str();
            let user_agent = captures.get(7).unwrap().as_str();
            let response_time = captures.get(8).unwrap().as_str();
            let upstream_connect_time = captures.get(9).unwrap().as_str();
            let upstream_header_time = captures.get(10).unwrap().as_str();
            let upstream_response_time = captures.get(11).unwrap().as_str();

            let timestamp = self.parse_nginx_timestamp(timestamp_str)?;
            let severity = self.determine_severity_from_status(status_code);

            let (method, path, protocol) = self.parse_request_line(request);

            let mut parsed_data = HashMap::new();
            parsed_data.insert("ip".to_string(), ip.to_string());
            parsed_data.insert("method".to_string(), method.clone());
            parsed_data.insert("path".to_string(), path.clone());
            parsed_data.insert("protocol".to_string(), protocol);
            parsed_data.insert("status_code".to_string(), status_code.to_string());
            parsed_data.insert("body_bytes".to_string(), body_bytes.to_string());
            parsed_data.insert("referer".to_string(), referer.to_string());
            parsed_data.insert("user_agent".to_string(), user_agent.to_string());
            parsed_data.insert("response_time".to_string(), response_time.to_string());
            parsed_data.insert("upstream_connect_time".to_string(), upstream_connect_time.to_string());
            parsed_data.insert("upstream_header_time".to_string(), upstream_header_time.to_string());
            parsed_data.insert("upstream_response_time".to_string(), upstream_response_time.to_string());
            parsed_data.insert("log_type".to_string(), "custom".to_string());

            let event_type = detect_event_type(line, &parsed_data);
            let iocs = self.extract_iocs(&path, user_agent, &method);

            Ok(LogEvent {
                id: Uuid::new_v4(),
                timestamp,
                source: "nginx_custom".to_string(),
                severity,
                source_ip: Some(ip.to_string()),
                raw_message: line.to_string(),
                parsed_data: serde_json::to_value(parsed_data)
                    .context("Error serializando datos parseados")?,
                event_type,
                iocs,
            })
        } else {
            Err(anyhow::anyhow!("No coincide con formato custom de Nginx"))
        }
    }

    fn parse_nginx_timestamp(&self, timestamp_str: &str) -> Result<DateTime<Utc>> {
        // Formato típico de Nginx: 10/Oct/2000:13:55:36 +0000
        let formats = [
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d-%b-%Y %H:%M:%S",
        ];

        for format in &formats {
            if let Ok(dt) = DateTime::parse_from_str(timestamp_str, format) {
                return Ok(dt.with_timezone(&Utc));
            }
        }

        Ok(Utc::now())
    }

    fn parse_nginx_error_timestamp(&self, timestamp_str: &str) -> Result<DateTime<Utc>> {
        // Formato de error log: 2023/10/10 13:55:36
        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(timestamp_str, "%Y/%m/%d %H:%M:%S") {
            return Ok(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
        }

        Ok(Utc::now())
    }

    fn parse_request_line(&self, request: &str) -> (String, String, String) {
        let parts: Vec<&str> = request.split_whitespace().collect();

        if parts.len() >= 3 {
            (
                parts[0].to_string(),           // method
                parts[1].to_string(),           // path
                parts[2].to_string(),           // protocol
            )
        } else if parts.len() == 2 {
            (
                parts[0].to_string(),           // method
                parts[1].to_string(),           // path
                "HTTP/1.0".to_string(),         // default protocol
            )
        } else if parts.len() == 1 {
            (
                "GET".to_string(),              // default method
                parts[0].to_string(),           // path
                "HTTP/1.0".to_string(),         // default protocol
            )
        } else {
            (
                "UNKNOWN".to_string(),
                "-".to_string(),
                "-".to_string(),
            )
        }
    }

    fn determine_severity_from_status(&self, status_code: u16) -> Severity {
        match status_code {
            500..=599 => Severity::Critical,
            400..=499 => {
                match status_code {
                    401 | 403 | 429 => Severity::Warning,
                    404 => Severity::Info,
                    _ => Severity::Info,
                }
            },
            300..=399 => Severity::Info,
            200..=299 => Severity::Info,
            _ => Severity::Warning,
        }
    }

    fn determine_severity_from_level(&self, log_level: &str) -> Severity {
        match log_level.to_lowercase().as_str() {
            "emerg" | "emergency" | "alert" | "crit" | "critical" | "err" | "error" => Severity::Critical,
            "warn" | "warning" | "notice" => Severity::Warning,
            "info" | "debug" => Severity::Info,
            _ => Severity::Info,
        }
    }

    fn extract_iocs(&self, path: &str, user_agent: &str, method: &str) -> Vec<String> {
        let mut iocs = Vec::new();
        let combined_text = format!("{} {} {}", path.to_lowercase(), user_agent.to_lowercase(), method.to_lowercase());

        // Patrones de ataques web comunes
        let attack_patterns = [
            // SQL Injection
            "union select", "drop table", "insert into", "delete from", "update set",
            "exec(", "exec sp_", "xp_cmdshell", "sp_executesql", "0x", "char(",
            "ascii(", "substring(", "waitfor delay", "benchmark(",

            // XSS
            "<script", "javascript:", "onerror=", "onload=", "onclick=", "onmouseover=",
            "document.cookie", "document.write", "eval(", "alert(", "confirm(",
            "prompt(", "fromcharcode", "innerhtml", "outerhtml",

            // Path Traversal
            "../", "..\\", "/etc/passwd", "/etc/shadow", "/etc/hosts", "c:\\windows",
            "boot.ini", "win.ini", "system32", "/proc/version", "/proc/cpuinfo",

            // Command Injection
            "cmd.exe", "powershell", "bash", "/bin/sh", "whoami", "netstat",
            "ps aux", "ls -la", "cat /etc", "type c:\\", "dir c:\\",

            // File Inclusion
            "php://filter", "php://input", "data://", "file://", "ftp://",
            "expect://", "zip://", "compress.zlib://",

            // XXE
            "<!entity", "<!doctype", "system \"", "public \"", "file:///",

            // LDAP Injection
            "ldap://", "ldaps://", "(&", "(|", "*)(", "*)(",

            // NoSQL Injection
            "[$ne]", "[$regex]", "[$where]", "[$gt]", "[$lt]", "[$exists]",

            // Template Injection
            "{{", "}}", "${", "<%", "%>", "{%", "%}",
        ];

        for pattern in &attack_patterns {
            if combined_text.contains(pattern) {
                iocs.push(pattern.to_string());
            }
        }

        // Detectar user agents sospechosos
        let suspicious_user_agents = [
            "sqlmap", "nmap", "nikto", "burp", "zap", "w3af", "havij",
            "pangolin", "darkjumper", "sql power injector", "bbqsql",
            "python-requests", "curl", "wget", "libwww-perl", "lwp-request",
        ];

        for agent in &suspicious_user_agents {
            if user_agent.to_lowercase().contains(agent) {
                iocs.push(format!("suspicious_user_agent:{}", agent));
            }
        }

        // Detectar métodos HTTP sospechosos
        let suspicious_methods = ["TRACE", "TRACK", "DEBUG", "OPTIONS", "CONNECT"];
        for sus_method in &suspicious_methods {
            if method.to_uppercase() == *sus_method {
                iocs.push(format!("suspicious_method:{}", sus_method));
            }
        }

        iocs
    }

    fn extract_error_iocs(&self, message: &str, request: &str) -> Vec<String> {
        let mut iocs = Vec::new();
        let combined_text = format!("{} {}", message.to_lowercase(), request.to_lowercase());

        let error_patterns = [
            // Errores que indican ataques
            "access forbidden by rule", "modsecurity", "blocked by security",
            "rate limiting", "too many requests", "client denied by server",
            "ssl handshake failed", "certificate verify failed",
            "upstream timed out", "no live upstreams", "connection refused",
            "file not found", "permission denied", "directory index forbidden",

            // Patrones de exploit
            "buffer overflow", "stack overflow", "heap overflow", "format string",
            "use after free", "double free", "null pointer", "segmentation fault",
        ];

        for pattern in &error_patterns {
            if combined_text.contains(pattern) {
                iocs.push(format!("error_pattern:{}", pattern));
            }
        }

        iocs
    }
}

impl LogParser for NginxParser {
    fn parse_line(&self, line: &str) -> Result<LogEvent> {
        // Intentar diferentes formatos de Nginx en orden de preferencia

        // 1. Intentar access log format
        if let Ok(event) = self.parse_access_log(line) {
            return Ok(event);
        }

        // 2. Intentar error log format
        if let Ok(event) = self.parse_error_log(line) {
            return Ok(event);
        }

        // 3. Intentar custom log format
        if let Ok(event) = self.parse_custom_log(line) {
            return Ok(event);
        }

        // 4. Fallback a parsing genérico
        self.parse_generic_nginx_line(line)
    }

    fn can_parse(&self, line: &str) -> bool {
        // Verificar si la línea contiene patrones típicos de Nginx
        line.contains("nginx") ||
            self.access_log_regex.is_match(line) ||
            self.error_log_regex.is_match(line) ||
            self.custom_log_regex.is_match(line) ||
            // Otros indicadores de logs de Nginx
            (line.contains('[') && line.contains(']') && line.contains('"') && line.contains(" - "))
    }

    fn parser_name(&self) -> &'static str {
        "nginx"
    }

    fn main_regex(&self) -> &Regex {
        &self.access_log_regex
    }
}

impl NginxParser {
    fn parse_generic_nginx_line(&self, line: &str) -> Result<LogEvent> {
        // Parsing genérico para líneas que no coinciden con formatos estándar
        let source_ip = extract_source_ip(line);
        let event_type = detect_event_type(line, &HashMap::new());

        Ok(LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "nginx_generic".to_string(),
            severity: Severity::Info,
            source_ip,
            raw_message: line.to_string(),
            parsed_data: serde_json::json!({
                "format": "generic",
                "raw": line,
                "parser": "nginx_generic"
            }),
            event_type,
            iocs: Vec::new(),
        })
    }
}

impl Default for NginxParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::common::LogParser;

    #[test]
    fn test_parse_nginx_access_log() {
        let parser = NginxParser::new();
        let line = r#"192.168.1.100 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0""#;

        let result = parser.parse_line(line);
        assert!(result.is_ok());

        let event = result.unwrap();
        assert_eq!(event.source, "nginx_access");
        assert_eq!(event.source_ip, Some("192.168.1.100".to_string()));
        assert_eq!(event.event_type, EventType::Normal);
    }

    #[test]
    fn test_parse_nginx_error_log() {
        let parser = NginxParser::new();
        let line = r#"2023/10/10 13:55:36 [error] 1234#0: *5678 open() "/var/www/html/test.php" failed (2: No such file or directory), client: 192.168.1.100, server: example.com, request: "GET /test.php HTTP/1.1", host: "example.com""#;

        let result = parser.parse_line(line);
        assert!(result.is_ok());

        let event = result.unwrap();
        assert_eq!(event.source, "nginx_error");
        assert_eq!(event.severity, Severity::Critical);
    }

    #[test]
    fn test_detect_sql_injection() {
        let parser = NginxParser::new();
        let line = r#"192.168.1.100 - - [10/Oct/2000:13:55:36 +0000] "GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1" 200 1234 "-" "sqlmap/1.0""#;

        let result = parser.parse_line(line);
        assert!(result.is_ok());

        let event = result.unwrap();
        assert_eq!(event.event_type, EventType::SqlInjection);
        assert!(!event.iocs.is_empty());
    }

    #[test]
    fn test_can_parse() {
        let parser = NginxParser::new();

        let nginx_access = r#"192.168.1.100 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        assert!(parser.can_parse(nginx_access));

        let nginx_error = r#"2023/10/10 13:55:36 [error] 1234#0: test error message"#;
        assert!(parser.can_parse(nginx_error));

        let apache_log = r#"127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.0" 200 2326"#;
        assert!(!parser.can_parse(apache_log));
    }
}