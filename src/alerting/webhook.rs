use crate::SecurityAlert;
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Alertador que envía notificaciones via webhooks
pub struct WebhookAlerter {
    config: WebhookAlerterConfig,
    client: Client,
    statistics: Arc<RwLock<WebhookStatistics>>,
    retry_queue: Arc<RwLock<Vec<RetryableWebhook>>>,
}

/// Configuración del alertador de webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAlerterConfig {
    pub enabled: bool,
    pub webhooks: Vec<WebhookEndpoint>,
    pub default_timeout_seconds: u64,
    pub max_retries: u32,
    pub retry_delay_seconds: u64,
    pub batch_webhooks: bool,
    pub batch_size: usize,
    pub batch_timeout_minutes: u32,
    pub include_raw_data: bool,
    pub user_agent: String,
    pub rate_limit_per_minute: u32,
}

/// Configuración de un endpoint de webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub id: String,
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub severity_filter: WebhookSeverityFilter,
    pub alert_types: Vec<String>,
    pub custom_payload_template: Option<String>,
    pub authentication: Option<WebhookAuth>,
    pub retry_config: Option<RetryConfig>,
    pub enabled: bool,
}

/// Métodos HTTP soportados
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HttpMethod {
    POST,
    PUT,
    PATCH,
}

/// Filtro de severidad para webhooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum WebhookSeverityFilter {
    All,
    Warning,
    Critical,
}

/// Tipos de autenticación para webhooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookAuth {
    Bearer { token: String },
    Basic { username: String, password: String },
    ApiKey { header_name: String, api_key: String },
    Custom { headers: HashMap<String, String> },
}

/// Configuración de reintentos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_seconds: u64,
    pub max_delay_seconds: u64,
    pub backoff_multiplier: f64,
}

/// Estadísticas del alertador de webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookStatistics {
    pub webhooks_sent: u64,
    pub webhooks_failed: u64,
    pub webhooks_retried: u64,
    pub last_webhook_time: Option<DateTime<Utc>>,
    pub webhooks_by_endpoint: HashMap<String, WebhookEndpointStats>,
    pub average_response_time_ms: f64,
    pub rate_limit_hits: u64,
}

/// Estadísticas por endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpointStats {
    pub requests_sent: u64,
    pub requests_failed: u64,
    pub last_success: Option<DateTime<Utc>>,
    pub last_failure: Option<DateTime<Utc>>,
    pub average_response_time_ms: f64,
    pub consecutive_failures: u32,
}

/// Webhook que requiere reintento
#[derive(Debug, Clone)]
pub struct RetryableWebhook {
    pub webhook_id: String,
    pub payload: WebhookPayload,
    pub attempt: u32,
    pub next_retry: DateTime<Utc>,
    pub original_alert_id: Uuid,
}

/// Payload estándar para webhooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub alert: SecurityAlert,
    pub metadata: WebhookMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_info: Option<BatchInfo>,
}

/// Metadatos adicionales del webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookMetadata {
    pub source: String,
    pub version: String,
    pub environment: String,
    pub webhook_id: String,
    pub delivery_attempt: u32,
}

/// Información de batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInfo {
    pub batch_id: String,
    pub total_alerts: usize,
    pub batch_timestamp: DateTime<Utc>,
}

/// Respuesta de webhook procesada
#[derive(Debug, Clone)]
pub struct WebhookResponse {
    pub endpoint_id: String,
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    pub error_message: Option<String>,
    pub retry_after: Option<Duration>,
}

impl Default for WebhookAlerterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            webhooks: vec![],
            default_timeout_seconds: 30,
            max_retries: 3,
            retry_delay_seconds: 60,
            batch_webhooks: false,
            batch_size: 10,
            batch_timeout_minutes: 5,
            include_raw_data: false,
            user_agent: "RustSIEM-WebhookAlerter/1.0".to_string(),
            rate_limit_per_minute: 60,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_seconds: 30,
            max_delay_seconds: 3600,
            backoff_multiplier: 2.0,
        }
    }
}

impl Default for WebhookStatistics {
    fn default() -> Self {
        Self {
            webhooks_sent: 0,
            webhooks_failed: 0,
            webhooks_retried: 0,
            last_webhook_time: None,
            webhooks_by_endpoint: HashMap::new(),
            average_response_time_ms: 0.0,
            rate_limit_hits: 0,
        }
    }
}

impl Default for WebhookEndpointStats {
    fn default() -> Self {
        Self {
            requests_sent: 0,
            requests_failed: 0,
            last_success: None,
            last_failure: None,
            average_response_time_ms: 0.0,
            consecutive_failures: 0,
        }
    }
}

impl WebhookAlerter {
    pub fn new() -> Self {
        Self::with_config(WebhookAlerterConfig::default())
    }

    pub fn with_config(config: WebhookAlerterConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.default_timeout_seconds))
            .user_agent(&config.user_agent)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            client,
            statistics: Arc::new(RwLock::new(WebhookStatistics::default())),
            retry_queue: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Envía alerta via webhooks
    pub async fn send_alert(&self, alert: &SecurityAlert) -> Result<Vec<WebhookResponse>> {
        if !self.config.enabled {
            return Ok(vec![]);
        }

        let start_time = std::time::Instant::now();
        let mut responses = Vec::new();

        // Filtrar webhooks según la alerta
        let applicable_webhooks = self.filter_webhooks_for_alert(alert);

        if applicable_webhooks.is_empty() {
            return Ok(responses);
        }

        // Verificar rate limit
        if self.is_rate_limited().await {
            self.update_rate_limit_stats().await;
            return Err(anyhow::anyhow!("Rate limit exceeded"));
        }

        // Crear payload base
        let payload = self.create_webhook_payload(alert, None).await;

        // Enviar a cada webhook aplicable
        for webhook in applicable_webhooks {
            let response = self.send_to_webhook(&webhook, &payload).await;

            // Actualizar estadísticas del endpoint
            self.update_endpoint_stats(&webhook.id, &response).await;

            // Manejar reintentos si es necesario
            if !response.success && self.should_retry(&webhook, &response) {
                self.schedule_retry(&webhook, &payload, alert.id).await;
            }

            responses.push(response);
        }

        // Actualizar estadísticas generales
        let total_time = start_time.elapsed().as_millis() as f64;
        self.update_general_stats(&responses, total_time).await;

        Ok(responses)
    }

    /// Filtra webhooks aplicables para la alerta
    fn filter_webhooks_for_alert(&self, alert: &SecurityAlert) -> Vec<&WebhookEndpoint> {
        self.config.webhooks.iter()
            .filter(|webhook| {
                // Verificar si está habilitado
                if !webhook.enabled {
                    return false;
                }

                // Verificar filtro de severidad
                if !self.severity_matches(&webhook.severity_filter, &alert.severity) {
                    return false;
                }

                // Verificar tipos de alerta específicos
                if !webhook.alert_types.is_empty() {
                    let alert_type = format!("{:?}", alert.severity);
                    if !webhook.alert_types.contains(&alert_type) {
                        return false;
                    }
                }

                true
            })
            .collect()
    }

    /// Verifica si la severidad coincide con el filtro
    fn severity_matches(&self, filter: &WebhookSeverityFilter, severity: &crate::Severity) -> bool {
        match filter {
            WebhookSeverityFilter::All => true,
            WebhookSeverityFilter::Warning => {
                matches!(severity, crate::Severity::Warning | crate::Severity::Critical)
            },
            WebhookSeverityFilter::Critical => {
                matches!(severity, crate::Severity::Critical)
            },
        }
    }

    /// Crea payload para webhook
    async fn create_webhook_payload(&self, alert: &SecurityAlert, batch_info: Option<BatchInfo>) -> WebhookPayload {
        WebhookPayload {
            event_type: "security_alert".to_string(),
            timestamp: Utc::now(),
            alert: alert.clone(),
            metadata: WebhookMetadata {
                source: "rustsiem".to_string(),
                version: "1.0.0".to_string(),
                environment: std::env::var("RUSTSIEM_ENV").unwrap_or_else(|_| "production".to_string()),
                webhook_id: Uuid::new_v4().to_string(),
                delivery_attempt: 1,
            },
            batch_info,
        }
    }

    /// Envía payload a un webhook específico
    async fn send_to_webhook(&self, webhook: &WebhookEndpoint, payload: &WebhookPayload) -> WebhookResponse {
        let start_time = std::time::Instant::now();

        // Preparar payload final
        let final_payload = if let Some(ref template) = webhook.custom_payload_template {
            self.apply_custom_template(template, payload)
        } else {
            serde_json::to_value(payload).unwrap_or_default()
        };

        // Construir request
        let mut request_builder = match webhook.method {
            HttpMethod::POST => self.client.post(&webhook.url),
            HttpMethod::PUT => self.client.put(&webhook.url),
            HttpMethod::PATCH => self.client.patch(&webhook.url),
        };

        // Agregar headers personalizados
        for (key, value) in &webhook.headers {
            request_builder = request_builder.header(key, value);
        }

        // Agregar autenticación
        if let Some(ref auth) = webhook.authentication {
            request_builder = self.apply_authentication(request_builder, auth);
        }

        // Configurar timeout específico
        if let Some(timeout) = webhook.timeout_seconds {
            request_builder = request_builder.timeout(Duration::from_secs(timeout));
        }

        // Agregar payload
        request_builder = request_builder
            .header("Content-Type", "application/json")
            .json(&final_payload);

        // Ejecutar request
        let response_result = request_builder.send().await;
        let response_time_ms = start_time.elapsed().as_millis() as u64;

        match response_result {
            Ok(response) => {
                let status_code = response.status().as_u16();
                let success = response.status().is_success();

                // Extraer Retry-After header si existe
                let retry_after = response.headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(Duration::from_secs);

                WebhookResponse {
                    endpoint_id: webhook.id.clone(),
                    success,
                    status_code: Some(status_code),
                    response_time_ms,
                    error_message: if !success {
                        Some(format!("HTTP {}", status_code))
                    } else {
                        None
                    },
                    retry_after,
                }
            },
            Err(e) => {
                WebhookResponse {
                    endpoint_id: webhook.id.clone(),
                    success: false,
                    status_code: None,
                    response_time_ms,
                    error_message: Some(e.to_string()),
                    retry_after: None,
                }
            }
        }
    }

    /// Aplica template personalizado al payload
    fn apply_custom_template(&self, template: &str, payload: &WebhookPayload) -> serde_json::Value {
        // En una implementación real, aquí usaríamos un motor de templates como Handlebars
        // Por simplicidad, hacemos sustituciones básicas
        let mut template_str = template.to_string();

        // Sustituciones básicas
        template_str = template_str.replace("{{alert.title}}", &payload.alert.title);
        template_str = template_str.replace("{{alert.severity}}", &format!("{:?}", payload.alert.severity));
        template_str = template_str.replace("{{alert.description}}", &payload.alert.description);
        template_str = template_str.replace("{{alert.id}}", &payload.alert.id.to_string());
        template_str = template_str.replace("{{timestamp}}", &payload.timestamp.to_rfc3339());

        // Intentar parsear como JSON, fallback a string
        serde_json::from_str(&template_str).unwrap_or_else(|_| {
            serde_json::json!({
                "message": template_str,
                "alert": payload.alert,
                "metadata": payload.metadata
            })
        })
    }

    /// Aplica autenticación al request
    fn apply_authentication(&self, mut request_builder: reqwest::RequestBuilder, auth: &WebhookAuth) -> reqwest::RequestBuilder {
        match auth {
            WebhookAuth::Bearer { token } => {
                request_builder.bearer_auth(token)
            },
            WebhookAuth::Basic { username, password } => {
                request_builder.basic_auth(username, Some(password))
            },
            WebhookAuth::ApiKey { header_name, api_key } => {
                request_builder.header(header_name, api_key)
            },
            WebhookAuth::Custom { headers } => {
                for (key, value) in headers {
                    request_builder = request_builder.header(key, value);
                }
                request_builder
            },
        }
    }

    /// Verifica si debe reintentar el webhook
    fn should_retry(&self, webhook: &WebhookEndpoint, response: &WebhookResponse) -> bool {
        if response.success {
            return false;
        }

        // Verificar límite de reintentos
        let default_retry_config = RetryConfig::default();
        let retry_config = webhook.retry_config.as_ref().unwrap_or(&default_retry_config);

        // Verificar códigos de estado que NO deben reintentarse
        if let Some(status_code) = response.status_code {
            match status_code {
                400 | 401 | 403 | 404 | 422 => return false, // Errores del cliente
                _ => {}
            }
        }

        true
    }

    /// Programa un reintento
    async fn schedule_retry(&self, webhook: &WebhookEndpoint, payload: &WebhookPayload, alert_id: Uuid) {
        let default_retry_config = RetryConfig::default();
        let retry_config = webhook.retry_config.as_ref().unwrap_or(&default_retry_config);

        let mut retry_queue = self.retry_queue.write().await;

        // Buscar si ya existe un reintento para este webhook y alerta
        if let Some(existing_retry) = retry_queue.iter_mut()
            .find(|r| r.webhook_id == webhook.id && r.original_alert_id == alert_id) {

            if existing_retry.attempt < retry_config.max_retries {
                existing_retry.attempt += 1;

                // Calcular delay con backoff exponencial
                let delay_seconds = (retry_config.initial_delay_seconds as f64
                    * retry_config.backoff_multiplier.powi(existing_retry.attempt as i32 - 1))
                    .min(retry_config.max_delay_seconds as f64) as u64;

                existing_retry.next_retry = Utc::now() + chrono::Duration::seconds(delay_seconds as i64);
            }
        } else {
            // Crear nuevo reintento
            let retry_webhook = RetryableWebhook {
                webhook_id: webhook.id.clone(),
                payload: payload.clone(),
                attempt: 1,
                next_retry: Utc::now() + chrono::Duration::seconds(retry_config.initial_delay_seconds as i64),
                original_alert_id: alert_id,
            };

            retry_queue.push(retry_webhook);
        }
    }

    /// Procesa reintentos pendientes
    pub async fn process_retries(&self) -> Result<()> {
        let now = Utc::now();
        let mut retry_queue = self.retry_queue.write().await;
        let mut processed_indices = Vec::new();

        for (index, retry_webhook) in retry_queue.iter().enumerate() {
            if retry_webhook.next_retry <= now {
                // Buscar el webhook correspondiente
                if let Some(webhook) = self.config.webhooks.iter()
                    .find(|w| w.id == retry_webhook.webhook_id) {

                    // Actualizar attempt en payload
                    let mut retry_payload = retry_webhook.payload.clone();
                    retry_payload.metadata.delivery_attempt = retry_webhook.attempt + 1;

                    // Intentar envío
                    let response = self.send_to_webhook(webhook, &retry_payload).await;

                    // Actualizar estadísticas
                    self.update_endpoint_stats(&webhook.id, &response).await;

                    let mut stats = self.statistics.write().await;
                    stats.webhooks_retried += 1;

                    // Si falló y aún puede reintentar, actualizarlo
                    if !response.success {
                        let default_config = RetryConfig::default();
                        let retry_config = webhook.retry_config.as_ref().unwrap_or(&default_config);
                        if retry_webhook.attempt < retry_config.max_retries {
                            // Se actualizará en la siguiente iteración
                            continue;
                        }
                    }
                }

                // Marcar para eliminación (exitoso o max reintentos alcanzado)
                processed_indices.push(index);
            }
        }

        // Eliminar reintentos procesados (en orden inverso para mantener índices)
        for &index in processed_indices.iter().rev() {
            retry_queue.remove(index);
        }

        Ok(())
    }

    /// Envía batch de alertas
    pub async fn send_alert_batch(&self, alerts: &[SecurityAlert]) -> Result<Vec<WebhookResponse>> {
        if alerts.is_empty() || !self.config.enabled || !self.config.batch_webhooks {
            return Ok(vec![]);
        }

        let batch_info = BatchInfo {
            batch_id: Uuid::new_v4().to_string(),
            total_alerts: alerts.len(),
            batch_timestamp: Utc::now(),
        };

        let mut all_responses = Vec::new();

        // Enviar cada alerta con información de batch
        for alert in alerts {
            let mut payload = self.create_webhook_payload(alert, Some(batch_info.clone())).await;
            payload.event_type = "security_alert_batch".to_string();

            let applicable_webhooks = self.filter_webhooks_for_alert(alert);

            for webhook in applicable_webhooks {
                let response = self.send_to_webhook(&webhook, &payload).await;
                self.update_endpoint_stats(&webhook.id, &response).await;
                all_responses.push(response);
            }
        }

        Ok(all_responses)
    }

    /// Envía webhook de prueba
    pub async fn send_test_webhook(&self, endpoint_id: &str) -> Result<WebhookResponse> {
        let webhook = self.config.webhooks.iter()
            .find(|w| w.id == endpoint_id)
            .ok_or_else(|| anyhow::anyhow!("Webhook endpoint not found: {}", endpoint_id))?;

        let test_alert = SecurityAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: crate::Severity::Warning,
            title: "Test Webhook Alert".to_string(),
            description: "This is a test webhook to verify endpoint configuration.".to_string(),
            related_events: vec![Uuid::new_v4()],
            mitigation_steps: vec!["This is a test - no action required".to_string()],
            acknowledged: false,
        };

        let mut payload = self.create_webhook_payload(&test_alert, None).await;
        payload.event_type = "test_webhook".to_string();

        Ok(self.send_to_webhook(webhook, &payload).await)
    }

    /// Verifica conectividad de todos los webhooks
    pub async fn verify_all_webhooks(&self) -> HashMap<String, bool> {
        let mut results = HashMap::new();

        for webhook in &self.config.webhooks {
            if !webhook.enabled {
                results.insert(webhook.id.clone(), false);
                continue;
            }

            // Hacer un HEAD request simple para verificar conectividad
            let health_check = self.client
                .head(&webhook.url)
                .timeout(Duration::from_secs(10))
                .send()
                .await;

            let is_reachable = match health_check {
                Ok(response) => response.status().as_u16() < 500,
                Err(_) => false,
            };

            results.insert(webhook.id.clone(), is_reachable);
        }

        results
    }

    /// Verifica rate limit
    async fn is_rate_limited(&self) -> bool {
        // Implementación básica - en producción usaríamos un sliding window
        let stats = self.statistics.read().await;

        if let Some(last_time) = stats.last_webhook_time {
            let minute_ago = Utc::now() - chrono::Duration::minutes(1);
            if last_time > minute_ago {
                // Simplificación: verificar si hemos excedido el límite
                return stats.webhooks_sent % self.config.rate_limit_per_minute as u64 == 0
                    && stats.webhooks_sent > 0;
            }
        }

        false
    }

    /// Actualiza estadísticas de rate limit
    async fn update_rate_limit_stats(&self) {
        let mut stats = self.statistics.write().await;
        stats.rate_limit_hits += 1;
    }

    /// Actualiza estadísticas del endpoint
    async fn update_endpoint_stats(&self, endpoint_id: &str, response: &WebhookResponse) {
        let mut stats = self.statistics.write().await;
        let endpoint_stats = stats.webhooks_by_endpoint
            .entry(endpoint_id.to_string())
            .or_insert_with(WebhookEndpointStats::default);

        endpoint_stats.requests_sent += 1;

        if response.success {
            endpoint_stats.last_success = Some(Utc::now());
            endpoint_stats.consecutive_failures = 0;
        } else {
            endpoint_stats.requests_failed += 1;
            endpoint_stats.last_failure = Some(Utc::now());
            endpoint_stats.consecutive_failures += 1;
        }

        // Actualizar tiempo promedio de respuesta
        let total_time = endpoint_stats.average_response_time_ms * (endpoint_stats.requests_sent - 1) as f64;
        endpoint_stats.average_response_time_ms = (total_time + response.response_time_ms as f64) / endpoint_stats.requests_sent as f64;
    }

    /// Actualiza estadísticas generales
    async fn update_general_stats(&self, responses: &[WebhookResponse], _total_time_ms: f64) {
        let mut stats = self.statistics.write().await;

        let successful_responses = responses.iter().filter(|r| r.success).count();
        let failed_responses = responses.len() - successful_responses;

        stats.webhooks_sent += successful_responses as u64;
        stats.webhooks_failed += failed_responses as u64;
        stats.last_webhook_time = Some(Utc::now());

        // Actualizar tiempo promedio general
        if !responses.is_empty() {
            let avg_response_time = responses.iter()
                .map(|r| r.response_time_ms as f64)
                .sum::<f64>() / responses.len() as f64;

            let total_requests = stats.webhooks_sent + stats.webhooks_failed;
            let total_time = stats.average_response_time_ms * (total_requests - responses.len() as u64) as f64;
            stats.average_response_time_ms = (total_time + (avg_response_time * responses.len() as f64)) / total_requests as f64;
        }
    }

    /// Obtiene estadísticas
    pub async fn get_statistics(&self) -> WebhookStatistics {
        self.statistics.read().await.clone()
    }

    /// Resetea estadísticas
    pub async fn reset_statistics(&self) {
        let mut stats = self.statistics.write().await;
        *stats = WebhookStatistics::default();
    }

    /// Actualiza configuración
    pub fn update_config(&mut self, new_config: WebhookAlerterConfig) {
        // Recrear cliente si cambió el user agent o timeout
        if new_config.user_agent != self.config.user_agent ||
            new_config.default_timeout_seconds != self.config.default_timeout_seconds {
            self.client = Client::builder()
                .timeout(Duration::from_secs(new_config.default_timeout_seconds))
                .user_agent(&new_config.user_agent)
                .build()
                .expect("Failed to recreate HTTP client");
        }

        self.config = new_config;
    }

    /// Obtiene configuración actual
    pub fn get_config(&self) -> &WebhookAlerterConfig {
        &self.config
    }

    /// Obtiene estado de la cola de reintentos
    pub async fn get_retry_queue_status(&self) -> serde_json::Value {
        let retry_queue = self.retry_queue.read().await;

        let mut counts = std::collections::HashMap::new();
        for retry in retry_queue.iter() {
            *counts.entry(retry.webhook_id.clone()).or_insert(0) += 1;
        }

        serde_json::json!({
        "pending_retries": retry_queue.len(),
        "next_retry": retry_queue.iter()
            .map(|r| r.next_retry)
            .min()
            .map(|dt| dt.to_rfc3339()),
        "retries_by_webhook": counts
    })
    }

    /// Limpia reintentos antiguos
    pub async fn cleanup_old_retries(&self, max_age_hours: i64) {
        let cutoff_time = Utc::now() - chrono::Duration::hours(max_age_hours);
        let mut retry_queue = self.retry_queue.write().await;

        retry_queue.retain(|retry| retry.next_retry > cutoff_time);
    }
}

impl Default for WebhookAlerter {
    fn default() -> Self {
        Self::new()
    }
}

/// Utilidades para el alertador de webhook
pub mod utils {
    use super::*;

    /// Crea webhook para Slack
    pub fn create_slack_webhook(id: &str, webhook_url: &str) -> WebhookEndpoint {
        WebhookEndpoint {
            id: id.to_string(),
            url: webhook_url.to_string(),
            method: HttpMethod::POST,
            headers: HashMap::new(),
            timeout_seconds: Some(30),
            severity_filter: WebhookSeverityFilter::All,
            alert_types: vec![],
            custom_payload_template: Some(r#"{
                "text": "🚨 Security Alert: {{alert.title}}",
                "attachments": [{
                    "color": "danger",
                    "fields": [
                        {"title": "Severity", "value": "{{alert.severity}}", "short": true},
                        {"title": "Time", "value": "{{timestamp}}", "short": true},
                        {"title": "Description", "value": "{{alert.description}}", "short": false}
                    ]
                }]
            }"#.to_string()),
            authentication: None,
            retry_config: Some(RetryConfig::default()),
            enabled: true,
        }
    }

    /// Crea webhook para Microsoft Teams
    pub fn create_teams_webhook(id: &str, webhook_url: &str) -> WebhookEndpoint {
        WebhookEndpoint {
            id: id.to_string(),
            url: webhook_url.to_string(),
            method: HttpMethod::POST,
            headers: HashMap::new(),
            timeout_seconds: Some(30),
            severity_filter: WebhookSeverityFilter::All,
            alert_types: vec![],
            custom_payload_template: Some(r#"{
               "@type": "MessageCard",
               "@context": "http://schema.org/extensions",
               "themeColor": "FF0000",
               "summary": "Security Alert: {{alert.title}}",
               "sections": [{
                   "activityTitle": "🚨 RustSIEM Security Alert",
                   "activitySubtitle": "{{alert.title}}",
                   "facts": [
                       {"name": "Severity", "value": "{{alert.severity}}"},
                       {"name": "Time", "value": "{{timestamp}}"},
                       {"name": "Alert ID", "value": "{{alert.id}}"}
                   ],
                   "text": "{{alert.description}}"
               }]
           }"#.to_string()),
            authentication: None,
            retry_config: Some(RetryConfig::default()),
            enabled: true,
        }
    }

    /// Crea webhook para Discord
    pub fn create_discord_webhook(id: &str, webhook_url: &str) -> WebhookEndpoint {
        WebhookEndpoint {
            id: id.to_string(),
            url: webhook_url.to_string(),
            method: HttpMethod::POST,
            headers: HashMap::new(),
            timeout_seconds: Some(30),
            severity_filter: WebhookSeverityFilter::All,
            alert_types: vec![],
            custom_payload_template: Some(r#"{
               "embeds": [{
                   "title": "🚨 Security Alert",
                   "description": "{{alert.title}}",
                   "color": 16711680,
                   "fields": [
                       {"name": "Severity", "value": "{{alert.severity}}", "inline": true},
                       {"name": "Time", "value": "{{timestamp}}", "inline": true},
                       {"name": "Description", "value": "{{alert.description}}", "inline": false}
                   ],
                   "footer": {"text": "RustSIEM Security Monitoring"}
               }]
           }"#.to_string()),
            authentication: None,
            retry_config: Some(RetryConfig::default()),
            enabled: true,
        }
    }

    /// Crea webhook genérico con autenticación Bearer
    pub fn create_authenticated_webhook(
        id: &str,
        url: &str,
        bearer_token: &str,
        severity_filter: WebhookSeverityFilter
    ) -> WebhookEndpoint {
        WebhookEndpoint {
            id: id.to_string(),
            url: url.to_string(),
            method: HttpMethod::POST,
            headers: HashMap::new(),
            timeout_seconds: Some(60),
            severity_filter,
            alert_types: vec![],
            custom_payload_template: None, // Usar payload estándar
            authentication: Some(WebhookAuth::Bearer {
                token: bearer_token.to_string(),
            }),
            retry_config: Some(RetryConfig {
                max_retries: 5,
                initial_delay_seconds: 30,
                max_delay_seconds: 1800,
                backoff_multiplier: 2.0,
            }),
            enabled: true,
        }
    }

    /// Crea webhook para PagerDuty
    pub fn create_pagerduty_webhook(id: &str, integration_key: &str) -> WebhookEndpoint {
        WebhookEndpoint {
            id: id.to_string(),
            url: "https://events.pagerduty.com/v2/enqueue".to_string(),
            method: HttpMethod::POST,
            headers: HashMap::new(),
            timeout_seconds: Some(30),
            severity_filter: WebhookSeverityFilter::Critical, // Solo críticas para PagerDuty
            alert_types: vec![],
            custom_payload_template: Some(format!(r#"{{
               "routing_key": "{}",
               "event_action": "trigger",
               "payload": {{
                   "summary": "{{{{alert.title}}}}",
                   "severity": "critical",
                   "source": "rustsiem",
                   "component": "security_monitor",
                   "group": "security",
                   "class": "{{{{alert.severity}}}}",
                   "custom_details": {{
                       "alert_id": "{{{{alert.id}}}}",
                       "description": "{{{{alert.description}}}}",
                       "timestamp": "{{{{timestamp}}}}"
                   }}
               }}
           }}"#, integration_key)),
            authentication: None,
            retry_config: Some(RetryConfig {
                max_retries: 3,
                initial_delay_seconds: 60,
                max_delay_seconds: 300,
                backoff_multiplier: 2.0,
            }),
            enabled: true,
        }
    }

    /// Crea webhook para sistema de tickets (Jira, ServiceNow, etc.)
    pub fn create_ticketing_webhook(
        id: &str,
        url: &str,
        username: &str,
        password: &str
    ) -> WebhookEndpoint {
        WebhookEndpoint {
            id: id.to_string(),
            url: url.to_string(),
            method: HttpMethod::POST,
            headers: {
                let mut headers = HashMap::new();
                headers.insert("Accept".to_string(), "application/json".to_string());
                headers
            },
            timeout_seconds: Some(120), // Mayor timeout para sistemas de tickets
            severity_filter: WebhookSeverityFilter::Warning,
            alert_types: vec![],
            custom_payload_template: Some(r#"{
               "fields": {
                   "project": {"key": "SEC"},
                   "summary": "Security Alert: {{alert.title}}",
                   "description": "Alert ID: {{alert.id}}\nSeverity: {{alert.severity}}\nTime: {{timestamp}}\n\nDescription:\n{{alert.description}}",
                   "issuetype": {"name": "Bug"},
                   "priority": {"name": "High"}
               }
           }"#.to_string()),
            authentication: Some(WebhookAuth::Basic {
                username: username.to_string(),
                password: password.to_string(),
            }),
            retry_config: Some(RetryConfig {
                max_retries: 2, // Menos reintentos para sistemas de tickets
                initial_delay_seconds: 120,
                max_delay_seconds: 600,
                backoff_multiplier: 2.0,
            }),
            enabled: true,
        }
    }

    /// Valida URL de webhook
    pub fn validate_webhook_url(url: &str) -> bool {
        url::Url::parse(url).is_ok() && (url.starts_with("http://") || url.starts_with("https://"))
    }

    /// Valida configuración de webhook
    pub fn validate_webhook_config(webhook: &WebhookEndpoint) -> Vec<String> {
        let mut errors = Vec::new();

        if webhook.id.is_empty() {
            errors.push("Webhook ID cannot be empty".to_string());
        }

        if !validate_webhook_url(&webhook.url) {
            errors.push("Invalid webhook URL".to_string());
        }

        if let Some(timeout) = webhook.timeout_seconds {
            if timeout == 0 || timeout > 300 {
                errors.push("Timeout must be between 1 and 300 seconds".to_string());
            }
        }

        if let Some(ref retry_config) = webhook.retry_config {
            if retry_config.max_retries > 10 {
                errors.push("Max retries should not exceed 10".to_string());
            }
            if retry_config.initial_delay_seconds == 0 {
                errors.push("Initial delay must be greater than 0".to_string());
            }
            if retry_config.backoff_multiplier < 1.0 {
                errors.push("Backoff multiplier must be >= 1.0".to_string());
            }
        }

        // Validar template personalizado si existe
        if let Some(ref template) = webhook.custom_payload_template {
            if let Err(_) = serde_json::from_str::<serde_json::Value>(&template.replace("{{", "\"").replace("}}", "\"")) {
                // Verificación básica de sintaxis JSON
                if !template.contains("{{") {
                    errors.push("Custom payload template appears to be invalid JSON".to_string());
                }
            }
        }

        errors
    }
}

/// Background task para procesar reintentos
pub struct WebhookRetryProcessor {
    alerter: Arc<WebhookAlerter>,
    processing_interval: Duration,
}

impl WebhookRetryProcessor {
    pub fn new(alerter: Arc<WebhookAlerter>, interval_seconds: u64) -> Self {
        Self {
            alerter,
            processing_interval: Duration::from_secs(interval_seconds),
        }
    }

    /// Inicia el procesamiento de reintentos en background
    pub async fn start(&self) {
        let mut interval = tokio::time::interval(self.processing_interval);

        loop {
            interval.tick().await;

            if let Err(e) = self.alerter.process_retries().await {
                tracing::error!("Error processing webhook retries: {}", e);
            }

            // Limpiar reintentos antiguos (más de 24 horas)
            self.alerter.cleanup_old_retries(24).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_alert() -> SecurityAlert {
        SecurityAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: crate::Severity::Critical,
            title: "Test Security Alert".to_string(),
            description: "This is a test security alert for webhook testing.".to_string(),
            related_events: vec![Uuid::new_v4()],
            mitigation_steps: vec!["Test action".to_string()],
            acknowledged: false,
        }
    }

    fn create_test_webhook() -> WebhookEndpoint {
        WebhookEndpoint {
            id: "test_webhook".to_string(),
            url: "https://httpbin.org/post".to_string(),
            method: HttpMethod::POST,
            headers: HashMap::new(),
            timeout_seconds: Some(30),
            severity_filter: WebhookSeverityFilter::All,
            alert_types: vec![],
            custom_payload_template: None,
            authentication: None,
            retry_config: Some(RetryConfig::default()),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_webhook_alerter_creation() {
        let alerter = WebhookAlerter::new();
        assert!(alerter.config.enabled);
        assert_eq!(alerter.config.webhooks.len(), 0);
    }

    #[tokio::test]
    async fn test_severity_filtering() {
        let config = WebhookAlerterConfig {
            enabled: true,
            webhooks: vec![
                WebhookEndpoint {
                    id: "critical_only".to_string(),
                    url: "https://example.com/critical".to_string(),
                    method: HttpMethod::POST,
                    headers: HashMap::new(),
                    timeout_seconds: None,
                    severity_filter: WebhookSeverityFilter::Critical,
                    alert_types: vec![],
                    custom_payload_template: None,
                    authentication: None,
                    retry_config: None,
                    enabled: true,
                }
            ],
            ..Default::default()
        };

        let alerter = WebhookAlerter::with_config(config);

        let critical_alert = create_test_alert();
        let applicable = alerter.filter_webhooks_for_alert(&critical_alert);
        assert_eq!(applicable.len(), 1);

        let mut warning_alert = create_test_alert();
        warning_alert.severity = crate::Severity::Warning;
        let applicable = alerter.filter_webhooks_for_alert(&warning_alert);
        assert_eq!(applicable.len(), 0);
    }

    #[test]
    fn test_custom_template_processing() {
        let alerter = WebhookAlerter::new();
        let alert = create_test_alert();
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            timestamp: Utc::now(),
            alert: alert.clone(),
            metadata: WebhookMetadata {
                source: "test".to_string(),
                version: "1.0".to_string(),
                environment: "test".to_string(),
                webhook_id: "test".to_string(),
                delivery_attempt: 1,
            },
            batch_info: None,
        };

        let template = r#"{"message": "Alert: {{alert.title}}", "severity": "{{alert.severity}}"}"#;
        let result = alerter.apply_custom_template(template, &payload);

        let result_str = result.to_string();
        assert!(result_str.contains(&alert.title));
        assert!(result_str.contains("Critical"));
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let alerter = WebhookAlerter::new();

        let response = WebhookResponse {
            endpoint_id: "test".to_string(),
            success: true,
            status_code: Some(200),
            response_time_ms: 150,
            error_message: None,
            retry_after: None,
        };

        alerter.update_endpoint_stats("test", &response).await;

        let stats = alerter.get_statistics().await;
        assert!(stats.webhooks_by_endpoint.contains_key("test"));

        let endpoint_stats = &stats.webhooks_by_endpoint["test"];
        assert_eq!(endpoint_stats.requests_sent, 1);
        assert_eq!(endpoint_stats.requests_failed, 0);
        assert_eq!(endpoint_stats.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn test_retry_scheduling() {
        let config = WebhookAlerterConfig {
            enabled: true,
            webhooks: vec![create_test_webhook()],
            ..Default::default()
        };

        let alerter = WebhookAlerter::with_config(config);
        let alert = create_test_alert();
        let payload = WebhookPayload {
            event_type: "test".to_string(),
            timestamp: Utc::now(),
            alert: alert.clone(),
            metadata: WebhookMetadata {
                source: "test".to_string(),
                version: "1.0".to_string(),
                environment: "test".to_string(),
                webhook_id: "test".to_string(),
                delivery_attempt: 1,
            },
            batch_info: None,
        };

        let webhook = &alerter.config.webhooks[0];
        alerter.schedule_retry(webhook, &payload, alert.id).await;

        let retry_queue = alerter.retry_queue.read().await;
        assert_eq!(retry_queue.len(), 1);
        assert_eq!(retry_queue[0].webhook_id, "test_webhook");
    }

    #[test]
    fn test_utility_webhooks() {
        let slack_webhook = utils::create_slack_webhook("slack_test", "https://hooks.slack.com/test");
        assert_eq!(slack_webhook.id, "slack_test");
        assert!(slack_webhook.custom_payload_template.is_some());

        let teams_webhook = utils::create_teams_webhook("teams_test", "https://outlook.office.com/webhook/test");
        assert_eq!(teams_webhook.id, "teams_test");
        assert!(teams_webhook.custom_payload_template.unwrap().contains("MessageCard"));

        let discord_webhook = utils::create_discord_webhook("discord_test", "https://discord.com/api/webhooks/test");
        assert_eq!(discord_webhook.id, "discord_test");
        assert!(discord_webhook.custom_payload_template.unwrap().contains("embeds"));
    }

    #[test]
    fn test_webhook_validation() {
        assert!(utils::validate_webhook_url("https://example.com/webhook"));
        assert!(utils::validate_webhook_url("http://localhost:8080/webhook"));
        assert!(!utils::validate_webhook_url("ftp://example.com"));
        assert!(!utils::validate_webhook_url("not_a_url"));

        let valid_webhook = create_test_webhook();
        let errors = utils::validate_webhook_config(&valid_webhook);
        assert!(errors.is_empty());

        let invalid_webhook = WebhookEndpoint {
            id: "".to_string(), // ID vacío
            url: "invalid_url".to_string(), // URL inválida
            timeout_seconds: Some(500), // Timeout muy alto
            ..create_test_webhook()
        };
        let errors = utils::validate_webhook_config(&invalid_webhook);
        assert!(!errors.is_empty());
        assert!(errors.len() >= 3);
    }

    #[test]
    fn test_authentication_types() {
        let bearer_auth = WebhookAuth::Bearer {
            token: "test_token".to_string(),
        };
        assert!(matches!(bearer_auth, WebhookAuth::Bearer { .. }));

        let basic_auth = WebhookAuth::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        assert!(matches!(basic_auth, WebhookAuth::Basic { .. }));

        let api_key_auth = WebhookAuth::ApiKey {
            header_name: "X-API-Key".to_string(),
            api_key: "key123".to_string(),
        };
        assert!(matches!(api_key_auth, WebhookAuth::ApiKey { .. }));
    }

    #[tokio::test]
    async fn test_retry_queue_status() {
        let alerter = WebhookAlerter::new();

        // Agregar algunos reintentos simulados
        {
            let mut retry_queue = alerter.retry_queue.write().await;
            retry_queue.push(RetryableWebhook {
                webhook_id: "test1".to_string(),
                payload: WebhookPayload {
                    event_type: "test".to_string(),
                    timestamp: Utc::now(),
                    alert: create_test_alert(),
                    metadata: WebhookMetadata {
                        source: "test".to_string(),
                        version: "1.0".to_string(),
                        environment: "test".to_string(),
                        webhook_id: "test".to_string(),
                        delivery_attempt: 1,
                    },
                    batch_info: None,
                },
                attempt: 1,
                next_retry: Utc::now() + chrono::Duration::minutes(5),
                original_alert_id: Uuid::new_v4(),
            });
        }

        let status = alerter.get_retry_queue_status().await;
        assert_eq!(status["pending_retries"], 1);
        assert!(status["next_retry"].is_string());
    }
}