use crate::{LogEvent, Severity, EventType};
use anyhow::{Result, Context};
use chrono::{DateTime, Utc, NaiveDateTime, Datelike};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Trait común para todos los parsers de logs
pub trait LogParser: Send + Sync {
    /// Parsea una línea de log y retorna un LogEvent
    fn parse_line(&self, line: &str) -> Result<LogEvent>;

    /// Verifica si el parser puede manejar este formato de log
    fn can_parse(&self, line: &str) -> bool;

    /// Retorna el nombre del parser
    fn parser_name(&self) -> &'static str;

    /// Retorna la expresión regular principal del parser
    fn main_regex(&self) -> &Regex;
}

/// Representa un log parseado con información básica
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedLogEntry {
    pub timestamp: DateTime<Utc>,
    pub source_ip: Option<String>,
    pub message: String,
    pub fields: HashMap<String, String>,
    pub log_level: LogLevel,
}

/// Niveles de log estándar
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

/// Tipos de formato de log detectados automáticamente
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogFormat {
    Apache,
    Nginx,
    Ssh,
    Syslog,
    Json,
    Custom(String),
    Unknown,
}

/// Detecta automáticamente el formato de una línea de log
pub fn detect_log_format(line: &str) -> LogFormat {
    // Apache Common/Combined Log Format
    if line.contains('[') && line.contains(']') && line.contains('"') &&
        line.matches('"').count() >= 2 {
        return LogFormat::Apache;
    }

    // Nginx típico
    if line.contains("nginx") || (line.contains(" - ") && line.contains(" [")) {
        return LogFormat::Nginx;
    }

    // SSH/OpenSSH
    if line.contains("sshd") || line.contains("ssh") || line.contains("SSH") {
        return LogFormat::Ssh;
    }

    // Syslog RFC3164
    if Regex::new(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}").unwrap().is_match(line) {
        return LogFormat::Syslog;
    }

    // JSON
    if line.trim_start().starts_with('{') && line.trim_end().ends_with('}') {
        return LogFormat::Json;
    }

    LogFormat::Unknown
}

/// Extrae timestamp de diferentes formatos de log
pub fn extract_timestamp(line: &str, format: &LogFormat) -> Result<DateTime<Utc>> {
    match format {
        LogFormat::Apache => extract_apache_timestamp(line),
        LogFormat::Nginx => extract_nginx_timestamp(line),
        LogFormat::Ssh | LogFormat::Syslog => extract_syslog_timestamp(line),
        LogFormat::Json => extract_json_timestamp(line),
        _ => Ok(Utc::now()), // Fallback a tiempo actual
    }
}

/// Extrae timestamp de formato Apache [10/Oct/2000:13:55:36 +0000]
fn extract_apache_timestamp(line: &str) -> Result<DateTime<Utc>> {
    let regex = Regex::new(r"\[([^\]]+)\]").context("Error compilando regex Apache timestamp")?;

    if let Some(captures) = regex.captures(line) {
        let timestamp_str = captures.get(1).unwrap().as_str();

        // Intentar diferentes formatos de Apache
        let formats = [
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
        ];

        for format in &formats {
            if let Ok(dt) = DateTime::parse_from_str(timestamp_str, format) {
                return Ok(dt.with_timezone(&Utc));
            }
        }
    }

    Ok(Utc::now())
}

/// Extrae timestamp de formato Nginx
fn extract_nginx_timestamp(line: &str) -> Result<DateTime<Utc>> {
    // Nginx típicamente usa formato ISO 8601 o similar
    let iso_regex = Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
        .context("Error compilando regex Nginx timestamp")?;

    if let Some(timestamp_match) = iso_regex.find(line) {
        let timestamp_str = timestamp_match.as_str();

        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(timestamp_str, "%Y-%m-%dT%H:%M:%S") {
            return Ok(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
        }
    }

    // Fallback a formato de fecha simple
    let date_regex = Regex::new(r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}")
        .context("Error compilando regex fecha Nginx")?;

    if let Some(timestamp_match) = date_regex.find(line) {
        let timestamp_str = timestamp_match.as_str();

        if let Ok(dt) = DateTime::parse_from_str(&format!("{} +0000", timestamp_str), "%d/%b/%Y:%H:%M:%S %z") {
            return Ok(dt.with_timezone(&Utc));
        }
    }

    Ok(Utc::now())
}

/// Extrae timestamp de formato Syslog
fn extract_syslog_timestamp(line: &str) -> Result<DateTime<Utc>> {
    // Formato syslog: Oct 10 13:55:36
    let syslog_regex = Regex::new(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
        .context("Error compilando regex Syslog timestamp")?;

    if let Some(captures) = syslog_regex.captures(line) {
        let month = captures.get(1).unwrap().as_str();
        let day = captures.get(2).unwrap().as_str();
        let time = captures.get(3).unwrap().as_str();

        let current_year = Utc::now().year();
        let timestamp_str = format!("{} {} {} {}", day, month, current_year, time);

        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(&timestamp_str, "%d %b %Y %H:%M:%S") {
            return Ok(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
        }
    }

    Ok(Utc::now())
}

/// Extrae timestamp de formato JSON
fn extract_json_timestamp(line: &str) -> Result<DateTime<Utc>> {
    // Intentar parsear como JSON y buscar campos comunes de timestamp
    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(line) {
        let timestamp_fields = ["timestamp", "time", "@timestamp", "datetime", "date"];

        for field in &timestamp_fields {
            if let Some(timestamp_value) = json_value.get(field) {
                if let Some(timestamp_str) = timestamp_value.as_str() {
                    // Intentar diferentes formatos de timestamp JSON
                    let formats = [
                        "%Y-%m-%dT%H:%M:%S%.fZ",
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S",
                        "%d/%m/%Y %H:%M:%S",
                    ];

                    for format in &formats {
                        if let Ok(dt) = DateTime::parse_from_str(timestamp_str, format) {
                            return Ok(dt.with_timezone(&Utc));
                        }
                    }
                }
            }
        }
    }

    Ok(Utc::now())
}

/// Extrae IP de origen de una línea de log
pub fn extract_source_ip(line: &str) -> Option<String> {
    // Regex para IPv4
    let ipv4_regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        .unwrap();

    // Regex para IPv6 (simplificado)
    let ipv6_regex = Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
        .unwrap();

    // Buscar IPv4 primero (más común)
    if let Some(ip_match) = ipv4_regex.find(line) {
        let ip = ip_match.as_str();
        // Filtrar IPs privadas/locales si se desea
        if !is_private_ip(ip) {
            return Some(ip.to_string());
        }
        return Some(ip.to_string());
    }

    // Buscar IPv6
    if let Some(ip_match) = ipv6_regex.find(line) {
        return Some(ip_match.as_str().to_string());
    }

    None
}

/// Verifica si una IP es privada/local
fn is_private_ip(ip: &str) -> bool {
    let private_ranges = [
        "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    ];

    private_ranges.iter().any(|range| ip.starts_with(range))
}

/// Convierte LogLevel a Severity
pub fn log_level_to_severity(level: &LogLevel) -> Severity {
    match level {
        LogLevel::Emergency | LogLevel::Alert | LogLevel::Critical | LogLevel::Error => Severity::Critical,
        LogLevel::Warning | LogLevel::Notice => Severity::Warning,
        LogLevel::Info | LogLevel::Debug => Severity::Info,
    }
}

/// Detecta el tipo de evento basado en contenido del log
pub fn detect_event_type(line: &str, _parsed_data: &HashMap<String, String>) -> EventType {
    let line_lower = line.to_lowercase();

    // Detectar SQL Injection
    let sql_patterns = [
        "union select", "drop table", "insert into", "delete from",
        "update set", "create table", "alter table", "exec(",
        "0x", "char(", "ascii(", "substring(", "waitfor delay"
    ];

    for pattern in &sql_patterns {
        if line_lower.contains(pattern) {
            return EventType::SqlInjection;
        }
    }

    // Detectar XSS
    let xss_patterns = [
        "<script", "javascript:", "onerror=", "onload=", "onclick=",
        "document.cookie", "document.write", "eval(", "alert("
    ];

    for pattern in &xss_patterns {
        if line_lower.contains(pattern) {
            return EventType::XssAttempt;
        }
    }

    // Detectar Brute Force
    let brute_force_patterns = [
        "failed login", "authentication failed", "invalid password",
        "login failed", "access denied", "unauthorized access"
    ];

    for pattern in &brute_force_patterns {
        if line_lower.contains(pattern) {
            return EventType::BruteForce;
        }
    }

    // Detectar actividad sospechosa
    let suspicious_patterns = [
        "../", "..\\", "/etc/passwd", "/etc/shadow", "cmd.exe",
        "powershell", "whoami", "netstat", "ps aux", "ls -la"
    ];

    for pattern in &suspicious_patterns {
        if line_lower.contains(pattern) {
            return EventType::SuspiciousActivity;
        }
    }

    EventType::Normal
}

/// Factory para crear el parser apropiado según el formato
pub fn create_parser(format: &LogFormat) -> Box<dyn LogParser> {
    match format {
        LogFormat::Apache => Box::new(crate::parser::apache::ApacheParser::new()),
        LogFormat::Nginx => Box::new(crate::parser::nginx::NginxParser::new()),
        LogFormat::Ssh => Box::new(crate::parser::ssh::SshParser::new()),
        _ => Box::new(crate::parser::apache::ApacheParser::new()), // Default fallback
    }
}

/// Utilidades para leer archivos de log
pub struct LogFileReader;

impl LogFileReader {
    /// Lee un archivo de log línea por línea
    pub fn read_file_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open(path).context("Error abriendo archivo de log")?;
        let reader = BufReader::new(file);

        let lines: Result<Vec<String>, std::io::Error> = reader.lines().collect();
        lines.context("Error leyendo líneas del archivo")
    }

    /// Detecta automáticamente el formato de un archivo de log
    pub fn detect_file_format<P: AsRef<Path>>(path: P) -> Result<LogFormat> {
        let lines = Self::read_file_lines(path)?;

        if lines.is_empty() {
            return Ok(LogFormat::Unknown);
        }

        // Analizar las primeras 10 líneas para determinar el formato
        let sample_lines = lines.iter().take(10);
        let mut format_votes: HashMap<LogFormat, usize> = HashMap::new();

        for line in sample_lines {
            let format = detect_log_format(line);
            *format_votes.entry(format).or_insert(0) += 1;
        }

        // Retornar el formato con más votos
        Ok(format_votes
            .into_iter()
            .max_by_key(|(_, votes)| *votes)
            .map(|(format, _)| format)
            .unwrap_or(LogFormat::Unknown))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_apache_format() {
        let apache_line = r#"127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.0" 200 2326"#;
        assert_eq!(detect_log_format(apache_line), LogFormat::Apache);
    }

    #[test]
    fn test_extract_source_ip() {
        let line = "192.168.1.100 - - [10/Oct/2000:13:55:36 +0000] GET /test";
        assert_eq!(extract_source_ip(line), Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_detect_sql_injection() {
        let line = "GET /search?q=1' UNION SELECT * FROM users--";
        let data = HashMap::new();
        assert_eq!(detect_event_type(line, &data), EventType::SqlInjection);
    }

    #[test]
    fn test_detect_xss() {
        let line = "GET /search?q=<script>alert('xss')</script>";
        let data = HashMap::new();
        assert_eq!(detect_event_type(line, &data), EventType::XssAttempt);
    }
}