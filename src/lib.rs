
//! Un SIEM (Security Information and Event Management)


pub mod parser;
pub mod detector;
pub mod alerting;
pub mod dashboard;
pub mod storage;
pub mod simulator;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;


/// Representa un evento de log parseado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub severity: Severity,
    pub source_ip: Option<String>,
    pub raw_message: String,
    pub parsed_data: serde_json::Value,
    pub event_type: EventType,
    pub iocs: Vec<String>,
}

/// Niveles de severidad
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Info,
    Medium,
    Warning,
    High,
    Critical,
}

/// Tipos de eventos de seguridad

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    Normal,
    SqlInjection,
    XssAttempt,
    BruteForce,
    Anomaly,
    SuspiciousActivity,
}

/// Representa una alerta de seguridad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub related_events: Vec<Uuid>,
    pub mitigation_steps: Vec<String>,
    pub acknowledged: bool,
}

/// Configuración general del sistema
#[derive(Debug, Deserialize)]
pub struct Config {
    pub detection_rules: DetectionConfig,
    pub ml_config: MLConfig,
    pub alerting: AlertingConfig,
}

#[derive(Debug, Deserialize)]
pub struct DetectionConfig {
    pub sql_injection: SqlInjectionConfig,
    pub xss: XssConfig,
    pub brute_force: BruteForceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlInjectionConfig {
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub max_risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssConfig {
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub max_risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceConfig {
    pub enabled: bool,
    pub max_attempts: u32,
    pub time_window_seconds: u64,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLConfig {
    pub enabled: bool,
    pub training_interval_hours: u64,
    pub anomaly_threshold: f64,
}

#[derive(Debug, Deserialize)]
pub struct AlertingConfig {
    pub email: EmailConfig,
    pub webhooks: Vec<WebhookConfig>,
}

#[derive(Debug, Deserialize)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub recipients: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
}

// Tipos adicionales para importaciones
pub type LogEntry = LogEvent;
pub type Alert = SecurityAlert;
pub type AlertSeverity = Severity;

/// Resultado de detección
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub detector_type: String,
    pub confidence: f64,
    pub risk_score: f64,
    pub details: String,
    pub recommendations: Vec<String>,
    pub has_threats: bool,
    pub sql_injection: Option<serde_json::Value>,
    pub xss: Option<serde_json::Value>,
    pub brute_force: Option<serde_json::Value>,
    pub anomaly_ml: Option<serde_json::Value>,
    pub combined_indicators: Vec<String>,
    pub recommended_actions: Vec<String>,
}

impl Default for DetectionResult {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            detector_type: String::new(),
            confidence: 0.0,
            risk_score: 0.0,
            details: String::new(),
            recommendations: Vec::new(),
            has_threats: false,
            sql_injection: None,
            xss: None,
            brute_force: None,
            anomaly_ml: None,
            combined_indicators: Vec::new(),
            recommended_actions: Vec::new(),
        }
    }
}

/// Configuración del detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    pub sql_injection: SqlInjectionConfig,
    pub xss: XssConfig,
    pub brute_force: BruteForceConfig,
    pub ml: MLConfig,
    pub risk_threshold: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            sql_injection: SqlInjectionConfig {
                enabled: true,
                patterns: vec![],
                max_risk_score: 0.7,
            },
            xss: XssConfig {
                enabled: true,
                patterns: vec![],
                max_risk_score: 0.7,
            },
            brute_force: BruteForceConfig {
                enabled: true,
                max_attempts: 5,
                time_window_seconds: 600,
                patterns: vec![],
            },
            ml: MLConfig {
                enabled: true,
                training_interval_hours: 24,
                anomaly_threshold: 0.5,
            },
            risk_threshold: 0.7,
        }
    }
}

/// Métricas del detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorMetrics {
    pub total_events_processed: u64,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub detection_rate: f64,
    pub processing_time_ms: f64,
    pub last_updated: DateTime<Utc>,
    pub total_detections: u64,
    pub average_processing_time_ms: f64,
    pub peak_processing_time_ms: f64,
}

impl DetectorMetrics {
    pub fn new() -> Self {
        Self {
            total_events_processed: 0,
            threats_detected: 0,
            false_positives: 0,
            detection_rate: 0.0,
            processing_time_ms: 0.0,
            last_updated: Utc::now(),
            total_detections: 0,
            average_processing_time_ms: 0.0,
            peak_processing_time_ms: 0.0,
        }
    }

    pub fn record_detection(&mut self, _detector_name: &str, duration: f64, _success: bool) {
        self.total_events_processed += 1;
        self.processing_time_ms = (self.processing_time_ms + duration) / 2.0;
        self.average_processing_time_ms = self.processing_time_ms;
        if duration > self.peak_processing_time_ms {
            self.peak_processing_time_ms = duration;
        }
        self.last_updated = Utc::now();
    }

    pub fn get_performance_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "total_events": self.total_events_processed,
            "threats_detected": self.threats_detected,
            "false_positives": self.false_positives,
            "detection_rate": self.detection_rate,
            "avg_processing_time": self.average_processing_time_ms
        })
    }
}