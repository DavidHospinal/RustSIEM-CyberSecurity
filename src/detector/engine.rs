use crate::{LogEvent, SecurityAlert, Severity, DetectionResult, DetectorConfig, DetectorMetrics};
use crate::storage::StorageManager;
use crate::alerting::AlertManager;
use super::{
    xss::XssDetector,
    sql_injection::SqlInjectionDetector,
    brute_force::BruteForceDetector,
    anomaly_ml::{AnomalyMLDetector, LogEventFeatures},
};
use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Instant;
use uuid::Uuid;
use chrono::Utc;
use serde::{Deserialize, Serialize};


/// Calcula el puntaje de riesgo combinado de múltiples detectores
pub fn calculate_combined_risk_score(
    sql_result: &Option<serde_json::Value>,
    xss_result: &Option<serde_json::Value>,
    brute_force_result: &Option<serde_json::Value>,
    anomaly_result: &Option<serde_json::Value>,
) -> f64 {
    let mut total_risk = 0.0;
    let mut detector_count = 0;

    // Extraer puntajes de riesgo de cada detector
    if let Some(sql) = sql_result {
        if let Some(score) = sql.get("risk_score").and_then(|v| v.as_f64()) {
            total_risk += score * 0.3; // 30% de peso para SQL injection
            detector_count += 1;
        }
    }

    if let Some(xss) = xss_result {
        if let Some(score) = xss.get("risk_score").and_then(|v| v.as_f64()) {
            total_risk += score * 0.25; // 25% de peso para XSS
            detector_count += 1;
        }
    }

    if let Some(bf) = brute_force_result {
        if let Some(score) = bf.get("risk_score").and_then(|v| v.as_f64()) {
            total_risk += score * 0.25; // 25% de peso para brute force
            detector_count += 1;
        }
    }

    if let Some(anomaly) = anomaly_result {
        if let Some(score) = anomaly.get("risk_score").and_then(|v| v.as_f64()) {
            total_risk += score * 0.2; // 20% de peso para anomalías ML
            detector_count += 1;
        }
    }

    // Normalizar el puntaje entre 0.0 y 1.0
    if detector_count > 0 {
        (total_risk / detector_count as f64).min(1.0).max(0.0)
    } else {
        0.0
    }
}

/// Motor principal de detección que coordina todos los detectores
#[derive(Clone)]
pub struct DetectorEngine {
    sql_detector: SqlInjectionDetector,
    xss_detector: XssDetector,
    brute_force_detector: BruteForceDetector,
    anomaly_detector: AnomalyMLDetector,
    storage: Arc<StorageManager>,
    alert_manager: Arc<AlertManager>,
    config: Arc<RwLock<DetectorConfig>>,
    metrics: Arc<RwLock<DetectorMetrics>>,
}

impl DetectorEngine {
    pub async fn new(
        storage: Arc<StorageManager>,
        alert_manager: Arc<AlertManager>
    ) -> Result<Self> {
        Ok(Self {
            sql_detector: SqlInjectionDetector::new(),
            xss_detector: XssDetector::new(),
            brute_force_detector: BruteForceDetector::new(),
            anomaly_detector: AnomalyMLDetector::new(),
            storage,
            alert_manager,
            config: Arc::new(RwLock::new(DetectorConfig::default())),
            metrics: Arc::new(RwLock::new(DetectorMetrics::new())),
        })
    }

    /// Procesa un evento de log a través de todos los detectores
    pub async fn process_log_event(&self, log_event: &LogEvent) -> Result<DetectionResult> {
        let start_time = Instant::now();
        let config = self.config.read().await;

        let mut sql_result = None;
        let mut xss_result = None;
        let mut brute_force_result = None;
        let mut anomaly_result = None;

        // Procesar con detector SQL Injection
        if config.sql_injection.enabled {
            if let Some(parsed_data) = log_event.parsed_data.as_object() {
                let raw_input = format!("{} {}",
                                        log_event.raw_message,
                                        serde_json::to_string(&log_event.parsed_data).unwrap_or_default()
                );

                let detection_start = Instant::now();
                match self.sql_detector.analyze(&raw_input) {
                    Ok(result) => {
                        sql_result = Some(result);
                        self.record_detection_metric("sql_injection", detection_start.elapsed(), true).await;
                    },
                    Err(e) => {
                        tracing::warn!("SQL injection detection failed: {}", e);
                        self.record_detection_metric("sql_injection", detection_start.elapsed(), false).await;
                    }
                }
            }
        }

        // Procesar con detector XSS
        if config.xss.enabled {
            let raw_input = format!("{} {}",
                                    log_event.raw_message,
                                    serde_json::to_string(&log_event.parsed_data).unwrap_or_default()
            );

            let detection_start = Instant::now();
            match self.xss_detector.analyze(&raw_input) {
                Ok(result) => {
                    xss_result = Some(result);
                    self.record_detection_metric("xss", detection_start.elapsed(), true).await;
                },
                Err(e) => {
                    tracing::warn!("XSS detection failed: {}", e);
                    self.record_detection_metric("xss", detection_start.elapsed(), false).await;
                }
            }
        }

        // Procesar con detector Brute Force
        if config.brute_force.enabled {
            if let Some(source_ip) = &log_event.source_ip {
                let username = self.extract_username_from_log(log_event);
                let service = self.extract_service_from_log(log_event);
                let user_agent = self.extract_user_agent_from_log(log_event);
                let response_code = self.extract_response_code_from_log(log_event);

                let detection_start = Instant::now();
                match self.brute_force_detector.analyze_event(
                    source_ip,
                    username.as_deref(),
                    &service,
                    &log_event.raw_message,
                    user_agent.as_deref(),
                    response_code,
                    log_event.timestamp,
                ) {
                    Ok(result) => {
                        brute_force_result = Some(result);
                        self.record_detection_metric("brute_force", detection_start.elapsed(), true).await;
                    },
                    Err(e) => {
                        tracing::warn!("Brute force detection failed: {}", e);
                        self.record_detection_metric("brute_force", detection_start.elapsed(), false).await;
                    }
                }
            }
        }

        // Procesar con detector ML de anomalías
        if config.ml.enabled {
            let log_features = self.convert_to_ml_features(log_event);

            let detection_start = Instant::now();
            match self.anomaly_detector.detect_anomaly(&log_features) {
                Ok(result) => {
                    anomaly_result = Some(result);
                    self.record_detection_metric("anomaly_ml", detection_start.elapsed(), true).await;
                },
                Err(e) => {
                    tracing::warn!("Anomaly ML detection failed: {}", e);
                    self.record_detection_metric("anomaly_ml", detection_start.elapsed(), false).await;
                }
            }
        }

        // Crear resultado básico sin correlación
        let detection_result = DetectionResult {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            detector_type: "combined".to_string(),
            confidence: 0.0,
            risk_score: calculate_combined_risk_score(
                &sql_result.as_ref().map(|r| serde_json::to_value(r).unwrap_or_default()),
                &xss_result.as_ref().map(|r| serde_json::to_value(r).unwrap_or_default()),
                &brute_force_result.as_ref().map(|r| serde_json::to_value(r).unwrap_or_default()),
                &anomaly_result.as_ref().map(|r| serde_json::to_value(r).unwrap_or_default()),
            ),
            details: "Combined detection result".to_string(),
            recommendations: Vec::new(),
            has_threats: sql_result.as_ref().map(|r| r.is_detected).unwrap_or(false) ||
                xss_result.as_ref().map(|r| r.is_detected).unwrap_or(false) ||
                brute_force_result.as_ref().map(|r| r.is_detected).unwrap_or(false) ||
                anomaly_result.as_ref().map(|r| r.is_anomaly).unwrap_or(false),
            sql_injection: sql_result.map(|r| serde_json::to_value(r).unwrap_or_default()),
            xss: xss_result.map(|r| serde_json::to_value(r).unwrap_or_default()),
            brute_force: brute_force_result.map(|r| serde_json::to_value(r).unwrap_or_default()),
            anomaly_ml: anomaly_result.map(|r| serde_json::to_value(r).unwrap_or_default()),
            combined_indicators: Vec::new(),
            recommended_actions: Vec::new(),
        };

        // Generar alertas si es necesario
        if detection_result.has_threats && detection_result.risk_score >= config.risk_threshold {
            self.generate_security_alert(log_event, &detection_result).await?;
        }

        // Registrar métricas generales
        let total_time = start_time.elapsed();
        tracing::debug!("Detection completed in {:?}", total_time);

        Ok(detection_result)
    }

    /// Extrae nombre de usuario del log
    fn extract_username_from_log(&self, log_event: &LogEvent) -> Option<String> {
        if let Some(parsed) = log_event.parsed_data.as_object() {
            // Buscar campos comunes de username
            for field in ["user", "username", "login", "email", "account"] {
                if let Some(value) = parsed.get(field) {
                    if let Some(username) = value.as_str() {
                        if !username.is_empty() && username != "-" {
                            return Some(username.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extrae servicio del log
    fn extract_service_from_log(&self, log_event: &LogEvent) -> String {
        // Determinar servicio basado en el source
        match log_event.source.as_str() {
            s if s.contains("apache") => "apache".to_string(),
            s if s.contains("nginx") => "nginx".to_string(),
            s if s.contains("ssh") => "ssh".to_string(),
            s if s.contains("ftp") => "ftp".to_string(),
            s if s.contains("mysql") || s.contains("postgres") => "database".to_string(),
            _ => "web".to_string(),
        }
    }

    /// Extrae User-Agent del log
    fn extract_user_agent_from_log(&self, log_event: &LogEvent) -> Option<String> {
        if let Some(parsed) = log_event.parsed_data.as_object() {
            for field in ["user_agent", "useragent", "ua"] {
                if let Some(value) = parsed.get(field) {
                    if let Some(ua) = value.as_str() {
                        if !ua.is_empty() && ua != "-" {
                            return Some(ua.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Extrae código de respuesta del log
    fn extract_response_code_from_log(&self, log_event: &LogEvent) -> Option<u16> {
        if let Some(parsed) = log_event.parsed_data.as_object() {
            for field in ["status_code", "response_code", "status", "code"] {
                if let Some(value) = parsed.get(field) {
                    if let Some(code_str) = value.as_str() {
                        if let Ok(code) = code_str.parse::<u16>() {
                            return Some(code);
                        }
                    } else if let Some(code_num) = value.as_u64() {
                        if code_num <= u16::MAX as u64 {
                            return Some(code_num as u16);
                        }
                    }
                }
            }
        }
        None
    }

    /// Convierte LogEvent a características ML
    fn convert_to_ml_features(&self, log_event: &LogEvent) -> LogEventFeatures {
        let parsed = log_event.parsed_data.as_object();

        LogEventFeatures {
            timestamp: log_event.timestamp,
            source_ip: log_event.source_ip.clone().unwrap_or_default(),
            request_size: log_event.raw_message.len(),
            response_size: parsed
                .and_then(|p| p.get("body_bytes"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            response_time_ms: parsed
                .and_then(|p| p.get("response_time"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok())
                .map(|f| (f * 1000.0) as u64),
            status_code: self.extract_response_code_from_log(log_event),
            user_agent: self.extract_user_agent_from_log(log_event),
            request_method: parsed
                .and_then(|p| p.get("method"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            request_path: parsed
                .and_then(|p| p.get("path"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            protocol: parsed
                .and_then(|p| p.get("protocol"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            referer: parsed
                .and_then(|p| p.get("referer"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            payload_entropy: self.calculate_payload_entropy(&log_event.raw_message),
            special_char_count: self.count_special_characters(&log_event.raw_message),
            keyword_matches: log_event.iocs.len(),
        }
    }

    /// Calcula entropía del payload
    fn calculate_payload_entropy(&self, payload: &str) -> f64 {
        if payload.is_empty() {
            return 0.0;
        }

        let mut char_counts = std::collections::HashMap::new();
        for ch in payload.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        let len = payload.len() as f64;
        let mut entropy = 0.0;

        for &count in char_counts.values() {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }

    /// Cuenta caracteres especiales
    fn count_special_characters(&self, text: &str) -> usize {
        let special_chars = ['<', '>', '"', '\'', ';', '(', ')', '{', '}', '[', ']', '&', '|', '*', '%', '$', '#', '@', '!', '?', '\\', '/', '+', '=', '~', '`', '^'];
        text.chars().filter(|&c| special_chars.contains(&c)).count()
    }

    /// Genera alerta de seguridad
    async fn generate_security_alert(&self, log_event: &LogEvent, detection_result: &DetectionResult) -> Result<()> {
        let severity = self.map_risk_to_severity(detection_result.risk_score);

        let title = format!("Security Threat Detected from {}",
                            log_event.source_ip.as_deref().unwrap_or("Unknown"));

        let mut description = String::new();
        description.push_str(&format!("Risk Score: {:.2}\n", detection_result.risk_score));

        // Usar los resultados individuales en lugar de combined_indicators
        if let Some(ref _sql_result) = detection_result.sql_injection {
            description.push_str(&format!("- SQL Injection detected (Confidence: {:.2})\n",
                                          detection_result.confidence));
        }
        if let Some(ref _xss_result) = detection_result.xss {
            description.push_str(&format!("- XSS Attack detected (Confidence: {:.2})\n",
                                          detection_result.confidence));
        }
        if let Some(ref _bf_result) = detection_result.brute_force {
            description.push_str(&format!("- Brute Force detected (Confidence: {:.2})\n",
                                          detection_result.confidence));
        }
        if let Some(ref _ml_result) = detection_result.anomaly_ml {
            description.push_str(&format!("- Anomaly detected (Confidence: {:.2})\n",
                                          detection_result.confidence));
        }

        let alert = SecurityAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            title,
            description,
            related_events: vec![log_event.id],
            mitigation_steps: detection_result.recommended_actions.clone(),
            acknowledged: false,
        };

        // Almacenar alerta
        self.storage.store_alert(alert.clone()).await?;

        // Enviar notificación
        self.alert_manager.send_alert(alert).await?;

        Ok(())
    }

    /// Mapea risk score a severidad
    fn map_risk_to_severity(&self, risk_score: f64) -> Severity {
        match risk_score {
            r if r >= 0.8 => Severity::Critical,
            r if r >= 0.6 => Severity::Warning,
            _ => Severity::Info,
        }
    }

    /// Registra métrica de detección
    async fn record_detection_metric(&self, detector_name: &str, duration: std::time::Duration, success: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.record_detection(detector_name, duration.as_secs_f64() * 1000.0, success);
    }

    /// Métodos públicos para configuración y estadísticas

    /// Actualiza configuración del detector
    pub async fn update_config(&self, new_config: DetectorConfig) -> Result<()> {
        let mut config = self.config.write().await;
        *config = new_config;
        tracing::info!("Detector configuration updated");
        Ok(())
    }

    /// Obtiene configuración actual
    pub async fn get_config(&self) -> DetectorConfig {
        self.config.read().await.clone()
    }

    /// Obtiene métricas de rendimiento
    pub async fn get_metrics(&self) -> DetectorMetrics {
        self.metrics.read().await.clone()
    }

    /// Obtiene estadísticas de todos los detectores
    pub async fn get_detector_statistics(&self) -> serde_json::Value {
        serde_json::json!({
           "sql_injection": self.sql_detector.get_statistics(),
           "xss": self.xss_detector.get_statistics(),
           "brute_force": self.brute_force_detector.get_statistics(),
           "anomaly_ml": self.anomaly_detector.get_statistics(),
           "engine_metrics": self.get_metrics().await.get_performance_summary()
       })
    }

    /// Entrena el modelo ML con datos históricos
    pub async fn train_ml_model(&self) -> Result<()> {
        tracing::info!("Starting ML model training...");
        self.anomaly_detector.train_models().context("Failed to train ML models")?;
        tracing::info!("ML model training completed");
        Ok(())
    }

    /// Limpia datos antiguos de todos los detectores
    pub async fn cleanup_old_data(&self) {
        tracing::info!("Cleaning up old detection data...");

        self.brute_force_detector.cleanup_old_records();
        self.anomaly_detector.cleanup_old_data();

        tracing::info!("Data cleanup completed");
    }

    /// Verifica si una IP está bloqueada por brute force
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        self.brute_force_detector.is_ip_blocked(ip)
    }

    /// Desbloquea una IP manualmente
    pub fn unblock_ip(&self, ip: &str) -> bool {
        self.brute_force_detector.unblock_ip(ip)
    }

    /// Exporta configuración y estado de detectores
    pub async fn export_detector_state(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
           "export_timestamp": Utc::now(),
           "config": self.get_config().await,
           "metrics": self.get_metrics().await,
           "ml_model_info": self.anomaly_detector.get_model_info(),
           "statistics": self.get_detector_statistics().await
       }))
    }

    /// Procesa múltiples eventos en lote
    pub async fn process_batch(&self, events: Vec<LogEvent>) -> Result<Vec<DetectionResult>> {
        let mut results = Vec::new();

        for event in events {
            match self.process_log_event(&event).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    tracing::error!("Failed to process event {}: {}", event.id, e);
                    // Continuar procesando otros eventos
                }
            }
        }

        tracing::info!("Processed batch of {} events, {} successful",
                     results.len(), results.iter().filter(|r| r.has_threats).count());

        Ok(results)
    }

    /// Obtiene resumen de amenazas activas
    pub async fn get_active_threats_summary(&self) -> Result<serde_json::Value> {
        let alerts = self.storage.get_active_alerts().await?;
        let blocked_ips = self.get_blocked_ips_count();
        let metrics = self.get_metrics().await;

        Ok(serde_json::json!({
           "active_alerts": alerts.len(),
           "blocked_ips": blocked_ips,
           "total_detections_today": metrics.total_detections,
           "false_positive_rate": if metrics.total_detections > 0 {
               metrics.false_positives as f64 / metrics.total_detections as f64
           } else {
               0.0
           },
           "average_processing_time_ms": metrics.average_processing_time_ms,
           "threat_types": self.get_threat_type_distribution().await
       }))
    }

    /// Obtiene conteo de IPs bloqueadas
    fn get_blocked_ips_count(&self) -> usize {
        // Esta sería una implementación más compleja que requeriría
        // acceso a las estadísticas del detector de brute force
        0 // Placeholder
    }

    /// Obtiene distribución de tipos de amenazas
    async fn get_threat_type_distribution(&self) -> serde_json::Value {
        let stats = self.get_detector_statistics().await;

        serde_json::json!({
           "sql_injection": stats.get("sql_injection").unwrap_or(&serde_json::Value::Null),
           "xss": stats.get("xss").unwrap_or(&serde_json::Value::Null),
           "brute_force": stats.get("brute_force").unwrap_or(&serde_json::Value::Null),
           "anomaly": stats.get("anomaly_ml").unwrap_or(&serde_json::Value::Null)
       })
    }

    /// Realiza diagnóstico de salud del sistema de detección
    pub async fn health_check(&self) -> serde_json::Value {
        let config = self.config.read().await;
        let metrics = self.metrics.read().await;

        let mut health = serde_json::json!({
           "status": "healthy",
           "timestamp": Utc::now(),
           "detectors": {
               "sql_injection": config.sql_injection.enabled,
                "xss": config.xss.enabled,
                "brute_force": config.brute_force.enabled,
                "anomaly_ml": config.ml.enabled
           },
           "performance": {
               "total_detections": metrics.total_detections,
               "average_processing_time_ms": metrics.average_processing_time_ms,
               "peak_processing_time_ms": metrics.peak_processing_time_ms
           }
       });

        // Verificar condiciones de salud
        let mut warnings = Vec::new();

        if metrics.average_processing_time_ms > 1000.0 {
            warnings.push("High average processing time detected");
        }

        if metrics.peak_processing_time_ms > 5000.0 {
            warnings.push("Very high peak processing time detected");
        }

        let false_positive_rate = if metrics.total_detections > 0 {
            metrics.false_positives as f64 / metrics.total_detections as f64
        } else {
            0.0
        };

        if false_positive_rate > 0.3 {
            warnings.push("High false positive rate detected");
        }

        if !warnings.is_empty() {
            health["status"] = serde_json::Value::String("warning".to_string());
            health["warnings"] = serde_json::Value::Array(
                warnings.into_iter().map(|w| serde_json::Value::String(w.to_string())).collect()
            );
        }

        health
    }
}

/// Utilidades adicionales para el motor de detección
pub mod utils {
    use super::*;
    use std::collections::HashMap;

    /// Analiza tendencias de detección
    pub fn analyze_detection_trends(results: &[DetectionResult]) -> serde_json::Value {
        let mut threat_counts: std::collections::HashMap<String, u32> = HashMap::new();
        let mut risk_scores = Vec::new();

        for result in results {
            if result.has_threats {
                risk_scores.push(result.risk_score);

                for indicator in &result.combined_indicators {

                }
            }
        }

        let avg_risk = if !risk_scores.is_empty() {
            risk_scores.iter().sum::<f64>() / risk_scores.len() as f64
        } else {
            0.0
        };

        let max_risk = risk_scores.iter().cloned().fold(0.0f64, f64::max);

        serde_json::json!({
           "total_detections": results.len(),
           "threats_detected": risk_scores.len(),
           "average_risk_score": avg_risk,
           "maximum_risk_score": max_risk,
           "threat_type_counts": threat_counts
       })
    }

    /// Genera reporte de seguridad
    pub fn generate_security_report(
        detection_results: &[DetectionResult],
        time_period: &str
    ) -> serde_json::Value {
        let trends = analyze_detection_trends(detection_results);

        let critical_threats = detection_results.iter()
            .filter(|r| r.risk_score >= 0.8)
            .count();

        let high_threats = detection_results.iter()
            .filter(|r| r.risk_score >= 0.6 && r.risk_score < 0.8)
            .count();

        let medium_threats = detection_results.iter()
            .filter(|r| r.risk_score >= 0.4 && r.risk_score < 0.6)
            .count();

        // Top recomendaciones
        let mut all_recommendations: Vec<String> = detection_results.iter()
            .flat_map(|r| r.recommended_actions.iter())
            .cloned()
            .collect();
        all_recommendations.sort();
        all_recommendations.dedup();

        serde_json::json!({
           "report_period": time_period,
           "generated_at": Utc::now(),
           "summary": {
               "total_events_analyzed": detection_results.len(),
               "threats_detected": trends["threats_detected"],
               "critical_threats": critical_threats,
               "high_threats": high_threats,
               "medium_threats": medium_threats,
               "average_risk_score": trends["average_risk_score"],
               "maximum_risk_score": trends["maximum_risk_score"]
           },
           "threat_breakdown": trends["threat_type_counts"],
           "top_recommendations": all_recommendations.into_iter().take(10).collect::<Vec<_>>(),
           "trends": trends
       })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventType, LogEvent, DetectorSubConfig};
    use uuid::Uuid;
    use std::sync::Arc;

    async fn create_test_engine() -> DetectorEngine {
        let storage = Arc::new(StorageManager::new().await.unwrap());
        let alert_manager = Arc::new(AlertManager::new().await.unwrap());
        DetectorEngine::new(storage, alert_manager).await.unwrap()
    }

    #[tokio::test]
    async fn test_log_event_processing() {
        let engine = create_test_engine().await;

        let log_event = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "test".to_string(),
            severity: Severity::Info,
            source_ip: Some("192.168.1.100".to_string()),
            raw_message: "GET /test HTTP/1.1".to_string(),
            parsed_data: serde_json::json!({
               "method": "GET",
               "path": "/test",
               "status_code": "200"
           }),
            event_type: EventType::Normal,
            iocs: vec![],
        };

        let result = engine.process_log_event(&log_event).await.unwrap();

        // Verificar que el procesamiento se completó
        assert!(result.sql_injection.is_some());
        assert!(result.xss.is_some());
        assert!(result.brute_force.is_some());
        assert!(result.anomaly_ml.is_some());
    }

    #[tokio::test]
    async fn test_malicious_event_detection() {
        let engine = create_test_engine().await;

        let malicious_log = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "web".to_string(),
            severity: Severity::Warning,
            source_ip: Some("10.0.0.1".to_string()),
            raw_message: "GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1".to_string(),
            parsed_data: serde_json::json!({
               "method": "GET",
               "path": "/search?q=1' UNION SELECT * FROM users--",
               "status_code": "200"
           }),
            event_type: EventType::SqlInjection,
            iocs: vec!["union select".to_string()],
        };

        let result = engine.process_log_event(&malicious_log).await.unwrap();

        // Debería detectar amenazas
        assert!(result.has_threats);
        assert!(result.risk_score > 0.0);

        // SQL injection debería ser detectado
        if let Some(sql_result) = &result.sql_injection {
            assert!(sql_result.is_detected);
        }
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let engine = create_test_engine().await;

        let events = vec![
            LogEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                source: "test1".to_string(),
                severity: Severity::Info,
                source_ip: Some("192.168.1.1".to_string()),
                raw_message: "Normal log entry".to_string(),
                parsed_data: serde_json::json!({}),
                event_type: EventType::Normal,
                iocs: vec![],
            },
            LogEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                source: "test2".to_string(),
                severity: Severity::Warning,
                source_ip: Some("192.168.1.2".to_string()),
                raw_message: "Suspicious log entry".to_string(),
                parsed_data: serde_json::json!({}),
                event_type: EventType::SuspiciousActivity,
                iocs: vec![],
            },
        ];

        let results = engine.process_batch(events).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_configuration_update() {
        let engine = create_test_engine().await;

        let new_config = DetectorConfig {
            sql_injection: DetectorSubConfig { enabled: false },
            xss: DetectorSubConfig { enabled: true },
            brute_force: DetectorSubConfig { enabled: true },
            ml: DetectorSubConfig { enabled: false },
            risk_threshold: 0.8,
        };

        engine.update_config(new_config.clone()).await.unwrap();
        let retrieved_config = engine.get_config().await;

        assert_eq!(retrieved_config.sql_injection.enabled, false);
        assert_eq!(retrieved_config.ml.enabled, false);
        assert_eq!(retrieved_config.risk_threshold, 0.8);
    }

    #[tokio::test]
    async fn test_health_check() {
        let engine = create_test_engine().await;

        let health = engine.health_check().await;

        assert!(health.get("status").is_some());
        assert!(health.get("detectors").is_some());
        assert!(health.get("performance").is_some());
    }



}