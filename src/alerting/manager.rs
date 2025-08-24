use crate::SecurityAlert;
use super::console::ConsoleAlerter;
use super::email::EmailAlerter;
use super::webhook::WebhookAlerter;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, interval};
use uuid::Uuid;

/// Manager principal que coordina todos los alertadores
type AlertReceiver = Arc<RwLock<Option<mpsc::UnboundedReceiver<AlertManagerCommand>>>>;
pub struct AlertManager {
    config: AlertManagerConfig,
    console_alerter: Option<ConsoleAlerter>,
    email_alerter: Option<EmailAlerter>,
    webhook_alerter: Option<WebhookAlerter>,
    alert_queue: Arc<RwLock<Vec<QueuedAlert>>>,
    batch_queue: Arc<RwLock<HashMap<String, AlertBatch>>>,
    statistics: Arc<RwLock<AlertManagerStatistics>>,
    alert_sender: mpsc::UnboundedSender<AlertManagerCommand>,
    alert_receiver: AlertReceiver,

}

/// Configuración del manager de alertas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertManagerConfig {
    pub enabled: bool,
    pub console_enabled: bool,
    pub email_enabled: bool,
    pub webhook_enabled: bool,
    pub batch_alerts: bool,
    pub batch_timeout_minutes: u32,
    pub max_batch_size: usize,
    pub rate_limit_per_minute: u32,
    pub priority_routing: HashMap<String, Vec<String>>, // severity -> alerter types
    pub alert_deduplication: bool,
    pub deduplication_window_minutes: u32,
    pub emergency_fallback: bool,
    pub health_check_interval_minutes: u32,
}

/// Alerta en cola con metadatos
#[derive(Debug, Clone)]
pub struct QueuedAlert {
    pub alert: SecurityAlert,
    pub queued_at: DateTime<Utc>,
    pub priority: AlertPriority,
    pub target_alerters: Vec<AlerterType>,
    pub retry_count: u32,
    pub deduplication_key: Option<String>,
}

/// Prioridad de alerta
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AlertPriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Emergency = 4,
}

/// Tipos de alertadores
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlerterType {
    Console,
    Email,
    Webhook,
    All,
}

/// Batch de alertas para envío agrupado
#[derive(Debug, Clone)]
pub struct AlertBatch {
    pub id: String,
    pub alerts: Vec<SecurityAlert>,
    pub created_at: DateTime<Utc>,
    pub target_alerters: Vec<AlerterType>,
    pub severity_threshold: crate::Severity,
}

/// Estadísticas del manager de alertas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertManagerStatistics {
    pub alerts_processed: u64,
    pub alerts_sent: u64,
    pub alerts_failed: u64,
    pub alerts_deduplicated: u64,
    pub alerts_batched: u64,
    pub average_processing_time_ms: f64,
    pub alerter_statistics: HashMap<String, AlerterStatistics>,
    pub last_alert_time: Option<DateTime<Utc>>,
    pub health_status: HealthStatus,
}

/// Estadísticas por alertador
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlerterStatistics {
    pub alerts_sent: u64,
    pub alerts_failed: u64,
    pub last_success: Option<DateTime<Utc>>,
    pub last_failure: Option<DateTime<Utc>>,
    pub average_response_time_ms: f64,
    pub health_status: AlerterHealthStatus,
}

impl Default for AlerterStatistics {
    fn default() -> Self {
        Self {
            alerts_sent: 0,
            alerts_failed: 0,
            last_success: None,
            last_failure: None,
            average_response_time_ms: 0.0,
            health_status: AlerterHealthStatus::Healthy,
        }
    }
}

/// Estado de salud del alertador
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlerterHealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Disabled,
}

/// Estado de salud general
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Critical,
}

/// Comandos internos del manager
#[derive(Debug)]
pub enum AlertManagerCommand {
    SendAlert(SecurityAlert),
    ProcessBatch(String),
    HealthCheck,
    ProcessRetries,
    Cleanup,
    Shutdown,
}

/// Resultado de envío de alerta
#[derive(Debug, Clone)]
pub struct AlertSendResult {
    pub alert_id: Uuid,
    pub success: bool,
    pub results_by_alerter: HashMap<AlerterType, AlerterResult>,
    pub processing_time_ms: u64,
    pub was_deduplicated: bool,
    pub was_batched: bool,
}

/// Resultado por alertador
#[derive(Debug, Clone)]
pub struct AlerterResult {
    pub success: bool,
    pub response_time_ms: u64,
    pub error_message: Option<String>,
    pub retry_scheduled: bool,
}

impl Default for AlertManagerConfig {
    fn default() -> Self {
        let mut priority_routing = HashMap::new();
        priority_routing.insert("Critical".to_string(), vec!["Console".to_string(), "Email".to_string(), "Webhook".to_string()]);
        priority_routing.insert("Warning".to_string(), vec!["Console".to_string(), "Webhook".to_string()]);
        priority_routing.insert("Info".to_string(), vec!["Console".to_string()]);

        Self {
            enabled: true,
            console_enabled: true,
            email_enabled: false, // Deshabilitado hasta configurar
            webhook_enabled: false, // Deshabilitado hasta configurar
            batch_alerts: true,
            batch_timeout_minutes: 10,
            max_batch_size: 20,
            rate_limit_per_minute: 100,
            priority_routing,
            alert_deduplication: true,
            deduplication_window_minutes: 30,
            emergency_fallback: true,
            health_check_interval_minutes: 5,
        }
    }
}

impl Default for AlertManagerStatistics {
    fn default() -> Self {
        Self {
            alerts_processed: 0,
            alerts_sent: 0,
            alerts_failed: 0,
            alerts_deduplicated: 0,
            alerts_batched: 0,
            average_processing_time_ms: 0.0,
            alerter_statistics: HashMap::new(),
            last_alert_time: None,
            health_status: HealthStatus::Healthy,
        }
    }
}

impl AlertManager {
    pub async fn new() -> Result<Self> {
        Self::with_config(AlertManagerConfig::default()).await
    }

    pub async fn with_config(config: AlertManagerConfig) -> Result<Self> {
        let (alert_sender, alert_receiver) = mpsc::unbounded_channel();

        let console_alerter = if config.console_enabled {
            Some(ConsoleAlerter::new())
        } else {
            None
        };

        let email_alerter = if config.email_enabled {
            Some(EmailAlerter::new().await.context("Failed to create email alerter")?)
        } else {
            None
        };

        let webhook_alerter = if config.webhook_enabled {
            Some(WebhookAlerter::new())
        } else {
            None
        };

        Ok(Self {
            config,
            console_alerter,
            email_alerter,
            webhook_alerter,
            alert_queue: Arc::new(RwLock::new(Vec::new())),
            batch_queue: Arc::new(RwLock::new(HashMap::new())),
            statistics: Arc::new(RwLock::new(AlertManagerStatistics::default())),
            alert_sender,
            alert_receiver: Arc::new(RwLock::new(Some(alert_receiver))),

        })
    }

    /// Inicia el manager de alertas
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            tracing::info!("Alert manager is disabled");
            return Ok(());
        }

        tracing::info!("Starting alert manager...");



        // Enviar mensaje de inicio
        if let Some(ref console) = self.console_alerter {
            console.send_startup_banner("1.0.0").await?;
        }

        // Obtener receiver y procesarlo
        let mut receiver = {
            let mut receiver_guard = self.alert_receiver.write().await;
            receiver_guard.take().expect("Alert receiver already taken")

        };

        // Configurar intervalos
        let mut batch_interval = interval(Duration::from_secs(self.config.batch_timeout_minutes as u64 * 60));
        let mut health_check_interval = interval(Duration::from_secs(self.config.health_check_interval_minutes as u64 * 60));
        let mut cleanup_interval = interval(Duration::from_secs(3600)); // Cleanup cada hora

        // Loop principal de procesamiento
        loop {
            tokio::select! {
                // Procesar comando recibido
                command = receiver.recv() => {
                    match command {
                        Some(AlertManagerCommand::SendAlert(alert)) => {
                            self.process_alert_internal(alert).await;
                        },
                        Some(AlertManagerCommand::ProcessBatch(batch_id)) => {
                            self.process_batch_internal(&batch_id).await;
                        },
                        Some(AlertManagerCommand::HealthCheck) => {
                            self.perform_health_check().await;
                        },
                        Some(AlertManagerCommand::ProcessRetries) => {
                            self.process_retries().await;
                        },
                        Some(AlertManagerCommand::Cleanup) => {
                            self.cleanup_old_data().await;
                        },
                        Some(AlertManagerCommand::Shutdown) => {
                            tracing::info!("Alert manager shutting down...");
                            break;
                        },
                        None => {
                            tracing::warn!("Alert manager channel closed");
                            break;
                        }
                    }
                },

                // Procesar batches por timeout
                _ = batch_interval.tick() => {
                    self.process_timed_out_batches().await;
                },

                // Health check periódico
                _ = health_check_interval.tick() => {
                    self.perform_health_check().await;
                },

                // Cleanup periódico
                _ = cleanup_interval.tick() => {
                    self.cleanup_old_data().await;
                }
            }
        }

        // Enviar mensaje de shutdown
        if let Some(ref console) = self.console_alerter {
            console.send_shutdown_message().await?;
        }

        Ok(())
    }

    /// Envía una alerta
    pub async fn send_alert(&self, alert: SecurityAlert) -> Result<AlertSendResult> {
        if !self.config.enabled {
            return Ok(AlertSendResult {
                alert_id: alert.id,
                success: false,
                results_by_alerter: HashMap::new(),
                processing_time_ms: 0,
                was_deduplicated: false,
                was_batched: false,
            });
        }

        // Enviar comando para procesamiento async
        self.alert_sender.send(AlertManagerCommand::SendAlert(alert.clone()))
            .map_err(|_| anyhow::anyhow!("Failed to queue alert"))?;

        // Para esta implementación, retornar resultado inmediato
        // En una implementación completa, esto sería async con callback o polling
        Ok(AlertSendResult {
            alert_id: alert.id,
            success: true,
            results_by_alerter: HashMap::new(),
            processing_time_ms: 0,
            was_deduplicated: false,
            was_batched: false,
        })
    }

    /// Procesamiento interno de alerta
    async fn process_alert_internal(&self, alert: SecurityAlert) {
        let start_time = std::time::Instant::now();

        // Verificar deduplicación
        if self.config.alert_deduplication {
            if self.is_duplicate_alert(&alert).await {
                self.update_deduplication_stats().await;
                return;
            }
        }

        // Determinar prioridad
        let priority = self.determine_alert_priority(&alert);

        // Determinar alertadores objetivo
        let target_alerters = self.determine_target_alerters(&alert);

        // Crear alerta en cola
        let queued_alert = QueuedAlert {
            alert: alert.clone(),
            queued_at: Utc::now(),
            priority,
            target_alerters: target_alerters.clone(),
            retry_count: 0,
            deduplication_key: self.generate_deduplication_key(&alert),
        };

        // Verificar si debe ser batcheada
        if self.config.batch_alerts && !self.is_emergency_alert(&alert) {
            self.add_to_batch(queued_alert).await;
        } else {
            // Enviar inmediatamente
            self.send_alert_immediately(queued_alert).await;
        }

        // Actualizar estadísticas
        let processing_time = start_time.elapsed().as_millis() as f64;
        self.update_processing_stats(processing_time).await;
    }

    /// Verifica si es una alerta duplicada
    async fn is_duplicate_alert(&self, alert: &SecurityAlert) -> bool {
        let dedup_key = self.generate_deduplication_key(alert);
        if dedup_key.is_none() {
            return false;
        }

        let dedup_key = dedup_key.unwrap();
        let window_start = Utc::now() - chrono::Duration::minutes(self.config.deduplication_window_minutes as i64);

        let queue = self.alert_queue.read().await;
        queue.iter().any(|queued| {
            queued.queued_at > window_start &&
                queued.deduplication_key.as_ref() == Some(&dedup_key)
        })
    }

    /// Genera clave de deduplicación
    fn generate_deduplication_key(&self, alert: &SecurityAlert) -> Option<String> {
        // Crear clave basada en título y tipo de severidad
        Some(format!("{}:{:?}", alert.title, alert.severity))
    }

    /// Determina la prioridad de la alerta
    fn determine_alert_priority(&self, alert: &SecurityAlert) -> AlertPriority {
        match alert.severity {
            crate::Severity::Low => AlertPriority::Low,
            crate::Severity::Info => AlertPriority::Low,
            crate::Severity::Medium => AlertPriority::Normal,
            crate::Severity::Warning => AlertPriority::Normal,
            crate::Severity::High => AlertPriority::High,
            crate::Severity::Critical => AlertPriority::Emergency,
        }
    }

    /// Determina alertadores objetivo según configuración
    fn determine_target_alerters(&self, alert: &SecurityAlert) -> Vec<AlerterType> {
        let severity_key = format!("{:?}", alert.severity);

        if let Some(configured_alerters) = self.config.priority_routing.get(&severity_key) {
            configured_alerters.iter()
                .filter_map(|name| match name.as_str() {
                    "Console" if self.config.console_enabled => Some(AlerterType::Console),
                    "Email" if self.config.email_enabled => Some(AlerterType::Email),
                    "Webhook" if self.config.webhook_enabled => Some(AlerterType::Webhook),
                    _ => None,
                })
                .collect()
        } else {
            // Fallback por defecto
            let mut alerters = Vec::new();
            if self.config.console_enabled {
                alerters.push(AlerterType::Console);
            }
            if alert.severity == crate::Severity::Critical {
                if self.config.email_enabled {
                    alerters.push(AlerterType::Email);
                }
                if self.config.webhook_enabled {
                    alerters.push(AlerterType::Webhook);
                }
            }
            alerters
        }
    }

    /// Verifica si es una alerta de emergencia
    fn is_emergency_alert(&self, alert: &SecurityAlert) -> bool {
        alert.severity == crate::Severity::Critical
    }

    /// Agrega alerta a un batch
    async fn add_to_batch(&self, queued_alert: QueuedAlert) {
        let mut batch_queue = self.batch_queue.write().await;

        // Buscar batch existente compatible
        let batch_key = format!("{:?}", queued_alert.alert.severity);

        if let Some(batch) = batch_queue.get_mut(&batch_key) {
            if batch.alerts.len() < self.config.max_batch_size {
                batch.alerts.push(queued_alert.alert);
                return;
            }
        }

        // Crear nuevo batch
        let batch = AlertBatch {
            id: Uuid::new_v4().to_string(),
            alerts: vec![queued_alert.alert],
            created_at: Utc::now(),
            target_alerters: queued_alert.target_alerters,
            severity_threshold: match queued_alert.priority {
                AlertPriority::Emergency => crate::Severity::Critical,
                AlertPriority::High => crate::Severity::Warning,
                _ => crate::Severity::Info,
            },
        };

        batch_queue.insert(batch_key, batch);
    }

    /// Envía alerta inmediatamente
    async fn send_alert_immediately(&self, queued_alert: QueuedAlert) {
        let mut results = HashMap::new();

        for alerter_type in &queued_alert.target_alerters {
            let result = self.send_to_alerter(alerter_type, &queued_alert.alert).await;
            self.update_alerter_stats(alerter_type, &result).await;
            results.insert(alerter_type.clone(), result);
        }

        // Agregar a cola para tracking
        {
            let mut queue = self.alert_queue.write().await;
            queue.push(queued_alert);
        }
    }

    /// Envía alerta a un alertador específico
    async fn send_to_alerter(&self, alerter_type: &AlerterType, alert: &SecurityAlert) -> AlerterResult {
        let start_time = std::time::Instant::now();

        let result = match alerter_type {
            AlerterType::Console => {
                if let Some(ref console) = self.console_alerter {
                    match console.send_alert(alert).await {
                        Ok(()) => AlerterResult {
                            success: true,
                            response_time_ms: start_time.elapsed().as_millis() as u64,
                            error_message: None,
                            retry_scheduled: false,
                        },
                        Err(e) => AlerterResult {
                            success: false,
                            response_time_ms: start_time.elapsed().as_millis() as u64,
                            error_message: Some(e.to_string()),
                            retry_scheduled: false,
                        },
                    }
                } else {
                    AlerterResult {
                        success: false,
                        response_time_ms: 0,
                        error_message: Some("Console alerter not configured".to_string()),
                        retry_scheduled: false,
                    }
                }
            },
            AlerterType::Email => {
                if let Some(ref email) = self.email_alerter {
                    match email.send_alert(alert).await {
                        Ok(()) => AlerterResult {
                            success: true,
                            response_time_ms: start_time.elapsed().as_millis() as u64,
                            error_message: None,
                            retry_scheduled: false,
                        },
                        Err(e) => AlerterResult {
                            success: false,
                            response_time_ms: start_time.elapsed().as_millis() as u64,
                            error_message: Some(e.to_string()),
                            retry_scheduled: true, // Email puede reintentarse
                        },
                    }
                } else {
                    AlerterResult {
                        success: false,
                        response_time_ms: 0,
                        error_message: Some("Email alerter not configured".to_string()),
                        retry_scheduled: false,
                    }
                }
            },
            AlerterType::Webhook => {
                if let Some(ref webhook) = self.webhook_alerter {
                    match webhook.send_alert(alert).await {
                        Ok(responses) => {
                            let success = responses.iter().any(|r| r.success);
                            let avg_time = if !responses.is_empty() {
                                responses.iter().map(|r| r.response_time_ms).sum::<u64>() / responses.len() as u64
                            } else {
                                start_time.elapsed().as_millis() as u64
                            };

                            AlerterResult {
                                success,
                                response_time_ms: avg_time,
                                error_message: if !success {
                                    Some("One or more webhooks failed".to_string())
                                } else {
                                    None
                                },
                                retry_scheduled: !success,
                            }
                        },
                        Err(e) => AlerterResult {
                            success: false,
                            response_time_ms: start_time.elapsed().as_millis() as u64,
                            error_message: Some(e.to_string()),
                            retry_scheduled: true,
                        },
                    }
                } else {
                    AlerterResult {
                        success: false,
                        response_time_ms: 0,
                        error_message: Some("Webhook alerter not configured".to_string()),
                        retry_scheduled: false,
                    }
                }
            },
            AlerterType::All => {
                // Evitar recursión usando lógica directa
                let mut results = Vec::new();
                let mut success_count = 0;
                let mut total_time = 0u64;

                // Console alerter
                if let Some(ref console) = self.console_alerter {
                    match console.send_alert(alert).await {
                        Ok(()) => {
                            let response_time = start_time.elapsed().as_millis() as u64;
                            results.push(("console", true, response_time));
                            success_count += 1;
                            total_time += response_time;
                        },
                        Err(_) => {
                            let response_time = start_time.elapsed().as_millis() as u64;
                            results.push(("console", false, response_time));
                            total_time += response_time;
                        },
                    }
                }

                // Email alerter
                if let Some(ref email) = self.email_alerter {
                    let email_start = std::time::Instant::now();
                    match email.send_alert(alert).await {
                        Ok(()) => {
                            let response_time = email_start.elapsed().as_millis() as u64;
                            results.push(("email", true, response_time));
                            success_count += 1;
                            total_time += response_time;
                        },
                        Err(_) => {
                            let response_time = email_start.elapsed().as_millis() as u64;
                            results.push(("email", false, response_time));
                            total_time += response_time;
                        },
                    }
                }

                // Webhook alerter
                if let Some(ref webhook) = self.webhook_alerter {
                    let webhook_start = std::time::Instant::now();
                    match webhook.send_alert(alert).await {
                        Ok(responses) => {
                            let success = responses.iter().any(|r| r.success);
                            let response_time = webhook_start.elapsed().as_millis() as u64;
                            results.push(("webhook", success, response_time));
                            if success {
                                success_count += 1;
                            }
                            total_time += response_time;
                        },
                        Err(_) => {
                            let response_time = webhook_start.elapsed().as_millis() as u64;
                            results.push(("webhook", false, response_time));
                            total_time += response_time;
                        },
                    }
                }

                let success = success_count > 0;
                let avg_time = if results.is_empty() { 0 } else { total_time / results.len() as u64 };

                AlerterResult {
                    success,
                    response_time_ms: avg_time,
                    error_message: if !success {
                        Some("All alerters failed".to_string())
                    } else {
                        None
                    },
                    retry_scheduled: !success,
                }
            },
        };

        result
    }

    /// Procesa batches que han expirado por tiempo
    async fn process_timed_out_batches(&self) {
        let timeout_duration = chrono::Duration::minutes(self.config.batch_timeout_minutes as i64);
        let cutoff_time = Utc::now() - timeout_duration;

        let mut batch_queue = self.batch_queue.write().await;
        let mut expired_batches = Vec::new();

        // Identificar batches expirados
        for (key, batch) in batch_queue.iter() {
            if batch.created_at <= cutoff_time {
                expired_batches.push((key.clone(), batch.clone()));
            }
        }

        // Remover y procesar batches expirados
        for (key, batch) in expired_batches {
            batch_queue.remove(&key);
            drop(batch_queue); // Liberar lock antes de procesamiento async

            self.send_batch(batch).await;

            batch_queue = self.batch_queue.write().await; // Reacquirir lock
        }
    }

    /// Procesa un batch específico
    async fn process_batch_internal(&self, batch_id: &str) {
        let batch = {
            let batch_queue = self.batch_queue.write().await;
            batch_queue.values()
                .find(|b| b.id == batch_id)
                .cloned()
        };

        if let Some(batch) = batch {
            self.send_batch(batch).await;
        }
    }

    /// Envía un batch de alertas
    async fn send_batch(&self, batch: AlertBatch) {
        tracing::info!("Sending batch of {} alerts", batch.alerts.len());

        // Enviar a cada alertador configurado para el batch
        for alerter_type in &batch.target_alerters {
            match alerter_type {
                AlerterType::Console => {
                    if let Some(ref console) = self.console_alerter {
                        if let Err(e) = console.send_summary(&batch.alerts).await {
                            tracing::error!("Failed to send console batch: {}", e);
                        }
                    }
                },
                AlerterType::Email => {
                    if let Some(ref email) = self.email_alerter {
                        if let Err(e) = email.send_alert_batch(&batch.alerts).await {
                            tracing::error!("Failed to send email batch: {}", e);
                        }
                    }
                },
                AlerterType::Webhook => {
                    if let Some(ref webhook) = self.webhook_alerter {
                        if let Err(e) = webhook.send_alert_batch(&batch.alerts).await {
                            tracing::error!("Failed to send webhook batch: {}", e);
                        }
                    }
                },
                AlerterType::All => {
                    // Enviar a todos
                    if let Some(ref console) = self.console_alerter {
                        let _ = console.send_summary(&batch.alerts).await;
                    }
                    if let Some(ref email) = self.email_alerter {
                        let _ = email.send_alert_batch(&batch.alerts).await;
                    }
                    if let Some(ref webhook) = self.webhook_alerter {
                        let _ = webhook.send_alert_batch(&batch.alerts).await;
                    }
                },
            }
        }

        // Actualizar estadísticas
        self.update_batch_stats(batch.alerts.len()).await;
    }

    /// Realiza health check de todos los alertadores
    async fn perform_health_check(&self) {
        tracing::debug!("Performing alerters health check");

        let mut health_status = HealthStatus::Healthy;
        let mut alerter_statuses = HashMap::new();

        // Check console alerter
        if self.config.console_enabled {
            let status = AlerterHealthStatus::Healthy; // Console siempre es healthy si está habilitado
            alerter_statuses.insert("console".to_string(), status);
        }

        // Check email alerter
        if self.config.email_enabled {
            let status = if let Some(ref email) = self.email_alerter {
                match email.verify_configuration().await {
                    Ok(true) => AlerterHealthStatus::Healthy,
                    Ok(false) => AlerterHealthStatus::Disabled,
                    Err(_) => {
                        health_status = HealthStatus::Degraded;
                        AlerterHealthStatus::Unhealthy
                    },
                }
            } else {
                AlerterHealthStatus::Disabled
            };
            alerter_statuses.insert("email".to_string(), status);
        }

        // Check webhook alerter
        if self.config.webhook_enabled {
            let status = if let Some(ref webhook) = self.webhook_alerter {
                let webhook_health = webhook.verify_all_webhooks().await;
                let healthy_count = webhook_health.values().filter(|&&v| v).count();
                let total_count = webhook_health.len();

                if total_count == 0 {
                    AlerterHealthStatus::Disabled
                } else if healthy_count == total_count {
                    AlerterHealthStatus::Healthy
                } else if healthy_count > 0 {
                    health_status = HealthStatus::Degraded;
                    AlerterHealthStatus::Degraded
                } else {
                    health_status = HealthStatus::Degraded;
                    AlerterHealthStatus::Unhealthy
                }
            } else {
                AlerterHealthStatus::Disabled
            };
            alerter_statuses.insert("webhook".to_string(), status);
        }

        // Determinar estado general
        let unhealthy_count = alerter_statuses.values()
            .filter(|&status| *status == AlerterHealthStatus::Unhealthy)
            .count();

        if unhealthy_count > 0 {
            health_status = match unhealthy_count {
                1 => HealthStatus::Degraded,
                _ => HealthStatus::Unhealthy,
            };
        }

        // Si no hay alertadores habilitados, es crítico
        if alerter_statuses.is_empty() {
            health_status = HealthStatus::Critical;
        }

        // Actualizar estadísticas
        {
            let mut stats = self.statistics.write().await;
            stats.health_status = health_status;

            for (alerter_name, status) in alerter_statuses {
                let alerter_stats = stats.alerter_statistics
                    .entry(alerter_name)
                    .or_insert_with(AlerterStatistics::default);
                alerter_stats.health_status = status;
            }
        }
    }

    /// Procesa reintentos pendientes
    async fn process_retries(&self) {
        // Procesar reintentos de webhook
        if let Some(ref webhook) = self.webhook_alerter {
            if let Err(e) = webhook.process_retries().await {
                tracing::error!("Failed to process webhook retries: {}", e);
            }
        }

        // Aquí podríamos agregar lógica para reintentos de email
        // y otros alertadores que lo soporten
    }

    /// Limpia datos antiguos
    async fn cleanup_old_data(&self) {
        tracing::debug!("Cleaning up old alert data");

        // Limpiar cola de alertas (mantener solo las últimas 1000)
        {
            let mut queue = self.alert_queue.write().await;
            if queue.len() > 1000 {
                let drain_count = queue.len() - 1000;
                queue.drain(0..drain_count);
            }
        }

        // Limpiar batches antiguos (más de 1 hora)
        {
            let mut batch_queue = self.batch_queue.write().await;
            let cutoff_time = Utc::now() - chrono::Duration::hours(1);

            batch_queue.retain(|_, batch| batch.created_at > cutoff_time);
        }

        // Limpiar reintentos de webhook
        if let Some(ref webhook) = self.webhook_alerter {
            webhook.cleanup_old_retries(24).await; // 24 horas
        }
    }

    /// Actualiza estadísticas de procesamiento
    async fn update_processing_stats(&self, processing_time_ms: f64) {
        let mut stats = self.statistics.write().await;
        stats.alerts_processed += 1;
        stats.last_alert_time = Some(Utc::now());

        // Actualizar tiempo promedio de procesamiento
        let total_time = stats.average_processing_time_ms * (stats.alerts_processed - 1) as f64;
        stats.average_processing_time_ms = (total_time + processing_time_ms) / stats.alerts_processed as f64;
    }

    /// Actualiza estadísticas de deduplicación
    async fn update_deduplication_stats(&self) {
        let mut stats = self.statistics.write().await;
        stats.alerts_deduplicated += 1;
    }

    /// Actualiza estadísticas de batch
    async fn update_batch_stats(&self, batch_size: usize) {
        let mut stats = self.statistics.write().await;
        stats.alerts_batched += batch_size as u64;
    }

    /// Actualiza estadísticas por alertador
    async fn update_alerter_stats(&self, alerter_type: &AlerterType, result: &AlerterResult) {
        let mut stats = self.statistics.write().await;

        let alerter_name = match alerter_type {
            AlerterType::Console => "console",
            AlerterType::Email => "email",
            AlerterType::Webhook => "webhook",
            AlerterType::All => "all",
        };

        let alerter_stats = stats.alerter_statistics
            .entry(alerter_name.to_string())
            .or_insert_with(AlerterStatistics::default);

        if result.success {
            alerter_stats.alerts_sent += 1;
            alerter_stats.last_success = Some(Utc::now());
        } else {
            alerter_stats.alerts_failed += 1;
            alerter_stats.last_failure = Some(Utc::now());
        }

        // Actualizar tiempo promedio de respuesta
        let total_requests = alerter_stats.alerts_sent + alerter_stats.alerts_failed;
        let total_time = alerter_stats.average_response_time_ms * (total_requests - 1) as f64;
        alerter_stats.average_response_time_ms = (total_time + result.response_time_ms as f64) / total_requests as f64;

        // Actualizar estadísticas generales
        if result.success {
            stats.alerts_sent += 1;
        } else {
            stats.alerts_failed += 1;
        }
    }

    /// Envía alerta de prueba a todos los alertadores
    pub async fn send_test_alert(&self) -> Result<HashMap<AlerterType, AlerterResult>> {
        let test_alert = SecurityAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: crate::Severity::Warning,
            title: "Test Alert - Alert Manager".to_string(),
            description: "This is a test alert to verify all alerter configurations. If you receive this alert, the alert manager is working correctly.".to_string(),
            related_events: vec![Uuid::new_v4()],
            mitigation_steps: vec![
                "This is a test - no action required".to_string(),
                "Verify all alerters are functioning properly".to_string(),
            ],
            acknowledged: false,
        };

        let mut results = HashMap::new();

        // Test console alerter
        if self.config.console_enabled {
            let result = self.send_to_alerter(&AlerterType::Console, &test_alert).await;
            results.insert(AlerterType::Console, result);
        }

        // Test email alerter
        if self.config.email_enabled {
            let result = self.send_to_alerter(&AlerterType::Email, &test_alert).await;
            results.insert(AlerterType::Email, result);
        }

        // Test webhook alerter
        if self.config.webhook_enabled {
            let result = self.send_to_alerter(&AlerterType::Webhook, &test_alert).await;
            results.insert(AlerterType::Webhook, result);
        }

        Ok(results)
    }

    /// Envía alerta de emergencia (fallback)
    pub async fn send_emergency_alert(&self, alert: SecurityAlert) -> Result<()> {
        if !self.config.emergency_fallback {
            return Err(anyhow::anyhow!("Emergency fallback is disabled"));
        }

        tracing::warn!("Sending emergency alert: {}", alert.title);

        // Intentar enviar por al menos un medio disponible
        let mut success = false;

        // Prioridad: Console (siempre disponible) -> Email -> Webhook
        if let Some(ref console) = self.console_alerter {
            if console.send_alert(&alert).await.is_ok() {
                success = true;
            }
        }

        if !success {
            if let Some(ref email) = self.email_alerter {
                if email.send_alert(&alert).await.is_ok() {
                    success = true;
                }
            }
        }

        if !success {
            if let Some(ref webhook) = self.webhook_alerter {
                if webhook.send_alert(&alert).await.is_ok() {
                    success = true;
                }
            }
        }

        if !success {
            return Err(anyhow::anyhow!("All emergency alerters failed"));
        }

        Ok(())
    }

    /// Fuerza el procesamiento de todos los batches pendientes
    pub async fn flush_all_batches(&self) -> Result<()> {
        let batches = {
            let mut batch_queue = self.batch_queue.write().await;
            let batches: Vec<AlertBatch> = batch_queue.values().cloned().collect();
            batch_queue.clear();
            batches
        };

        for batch in batches {
            self.send_batch(batch).await;
        }

        Ok(())
    }

    /// Obtiene estadísticas del manager
    pub async fn get_statistics(&self) -> AlertManagerStatistics {
        self.statistics.read().await.clone()
    }

    /// Resetea estadísticas
    pub async fn reset_statistics(&self) {
        let mut stats = self.statistics.write().await;
        *stats = AlertManagerStatistics::default();
    }

    /// Actualiza configuración
    pub async fn update_config(&mut self, new_config: AlertManagerConfig) -> Result<()> {
        // Recrear alertadores si cambiaron las configuraciones
        if new_config.console_enabled != self.config.console_enabled {
            self.console_alerter = if new_config.console_enabled {
                Some(ConsoleAlerter::new())
            } else {
                None
            };
        }

        if new_config.email_enabled != self.config.email_enabled {
            self.email_alerter = if new_config.email_enabled {
                Some(EmailAlerter::new().await.context("Failed to recreate email alerter")?)
            } else {
                None
            };
        }

        if new_config.webhook_enabled != self.config.webhook_enabled {
            self.webhook_alerter = if new_config.webhook_enabled {
                Some(WebhookAlerter::new())
            } else {
                None
            };
        }

        self.config = new_config;
        tracing::info!("Alert manager configuration updated");
        Ok(())
    }

    /// Obtiene configuración actual
    pub fn get_config(&self) -> &AlertManagerConfig {
        &self.config
    }

    /// Obtiene estado de salud detallado
    pub async fn get_health_status(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;

        serde_json::json!({
           "overall_status": stats.health_status,
           "timestamp": Utc::now(),
           "alerters": {
               "console": {
                   "enabled": self.config.console_enabled,
                   "status": stats.alerter_statistics.get("console")
                       .map(|s| &s.health_status)
                       .unwrap_or(&AlerterHealthStatus::Disabled)
               },
               "email": {
                   "enabled": self.config.email_enabled,
                   "status": stats.alerter_statistics.get("email")
                       .map(|s| &s.health_status)
                       .unwrap_or(&AlerterHealthStatus::Disabled)
               },
               "webhook": {
                   "enabled": self.config.webhook_enabled,
                   "status": stats.alerter_statistics.get("webhook")
                       .map(|s| &s.health_status)
                       .unwrap_or(&AlerterHealthStatus::Disabled)
               }
           },
           "statistics": {
               "alerts_processed": stats.alerts_processed,
               "alerts_sent": stats.alerts_sent,
               "alerts_failed": stats.alerts_failed,
               "alerts_deduplicated": stats.alerts_deduplicated,
               "alerts_batched": stats.alerts_batched,
               "average_processing_time_ms": stats.average_processing_time_ms,
               "last_alert_time": stats.last_alert_time
           },
           "queues": {
               "pending_alerts": self.alert_queue.read().await.len(),
               "pending_batches": self.batch_queue.read().await.len()
           }
       })
    }

    /// Obtiene resumen de actividad reciente
    pub async fn get_activity_summary(&self, hours: i64) -> serde_json::Value {
        let cutoff_time = Utc::now() - chrono::Duration::hours(hours);
        let queue = self.alert_queue.read().await;

        let recent_alerts: Vec<&QueuedAlert> = queue.iter()
            .filter(|alert| alert.queued_at > cutoff_time)
            .collect();

        let mut severity_counts = HashMap::new();
        let mut alerter_usage = HashMap::new();

        for alert in &recent_alerts {
            let severity_key = format!("{:?}", alert.alert.severity);
            *severity_counts.entry(severity_key).or_insert(0) += 1;

            for alerter in &alert.target_alerters {
                let alerter_key = format!("{:?}", alerter);
                *alerter_usage.entry(alerter_key).or_insert(0) += 1;
            }
        }

        serde_json::json!({
           "time_period_hours": hours,
           "total_alerts": recent_alerts.len(),
           "severity_breakdown": severity_counts,
           "alerter_usage": alerter_usage,
           "recent_alerts": recent_alerts.iter().take(10).map(|alert| {
               serde_json::json!({
                   "id": alert.alert.id,
                   "title": alert.alert.title,
                   "severity": alert.alert.severity,
                   "queued_at": alert.queued_at,
                   "priority": alert.priority,
                   "target_alerters": alert.target_alerters
               })
           }).collect::<Vec<_>>()
       })
    }

    /// Para el manager de alertas
    pub async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping alert manager...");

        // Enviar comando de shutdown
        self.alert_sender.send(AlertManagerCommand::Shutdown)
            .map_err(|_| anyhow::anyhow!("Failed to send shutdown command"))?;

        // Procesar batches pendientes antes de parar
        self.flush_all_batches().await?;

        Ok(())
    }

    /// Comandos de control del manager
    pub async fn trigger_health_check(&self) -> Result<()> {
        self.alert_sender.send(AlertManagerCommand::HealthCheck)
            .map_err(|_| anyhow::anyhow!("Failed to send health check command"))
    }

    pub async fn trigger_retry_processing(&self) -> Result<()> {
        self.alert_sender.send(AlertManagerCommand::ProcessRetries)
            .map_err(|_| anyhow::anyhow!("Failed to send retry processing command"))
    }

    pub async fn trigger_cleanup(&self) -> Result<()> {
        self.alert_sender.send(AlertManagerCommand::Cleanup)
            .map_err(|_| anyhow::anyhow!("Failed to send cleanup command"))
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        futures::executor::block_on(Self::new()).unwrap()
    }
}

/// Utilidades para el manager de alertas
pub mod utils {
    use super::*;

    /// Crea configuración optimizada para desarrollo
    pub fn create_development_config() -> AlertManagerConfig {
        AlertManagerConfig {
            enabled: true,
            console_enabled: true,
            email_enabled: false,
            webhook_enabled: false,
            batch_alerts: false, // Envío inmediato en desarrollo
            batch_timeout_minutes: 5,
            max_batch_size: 5,
            rate_limit_per_minute: 1000, // Sin límite en desarrollo
            priority_routing: {
                let mut routing = HashMap::new();
                routing.insert("Critical".to_string(), vec!["Console".to_string()]);
                routing.insert("Warning".to_string(), vec!["Console".to_string()]);
                routing.insert("Info".to_string(), vec!["Console".to_string()]);
                routing
            },
            alert_deduplication: false, // Deshabilitado en desarrollo
            deduplication_window_minutes: 5,
            emergency_fallback: true,
            health_check_interval_minutes: 1,
        }
    }

    /// Crea configuración optimizada para producción
    pub fn create_production_config() -> AlertManagerConfig {
        AlertManagerConfig {
            enabled: true,
            console_enabled: true,
            email_enabled: true,
            webhook_enabled: true,
            batch_alerts: true,
            batch_timeout_minutes: 15,
            max_batch_size: 50,
            rate_limit_per_minute: 60,
            priority_routing: {
                let mut routing = HashMap::new();
                routing.insert("Critical".to_string(), vec![
                    "Console".to_string(),
                    "Email".to_string(),
                    "Webhook".to_string()
                ]);
                routing.insert("Warning".to_string(), vec![
                    "Console".to_string(),
                    "Webhook".to_string()
                ]);
                routing.insert("Info".to_string(), vec!["Console".to_string()]);
                routing
            },
            alert_deduplication: true,
            deduplication_window_minutes: 60,
            emergency_fallback: true,
            health_check_interval_minutes: 10,
        }
    }

    /// Crea configuración para alertas críticas únicamente
    pub fn create_critical_only_config() -> AlertManagerConfig {
        AlertManagerConfig {
            enabled: true,
            console_enabled: true,
            email_enabled: true,
            webhook_enabled: true,
            batch_alerts: false, // Sin batch para críticas
            batch_timeout_minutes: 5,
            max_batch_size: 1,
            rate_limit_per_minute: 30,
            priority_routing: {
                let mut routing = HashMap::new();
                routing.insert("Critical".to_string(), vec![
                    "Console".to_string(),
                    "Email".to_string(),
                    "Webhook".to_string()
                ]);
                // Solo alertas críticas
                routing
            },
            alert_deduplication: true,
            deduplication_window_minutes: 30,
            emergency_fallback: true,
            health_check_interval_minutes: 5,
        }
    }

    /// Valida configuración del manager
    pub fn validate_config(config: &AlertManagerConfig) -> Vec<String> {
        let mut errors = Vec::new();

        if !config.enabled {
            return errors; // Si está deshabilitado, no validar más
        }

        // Verificar que al menos un alertador esté habilitado
        if !config.console_enabled && !config.email_enabled && !config.webhook_enabled {
            errors.push("At least one alerter must be enabled".to_string());
        }

        // Validar timeouts y límites
        if config.batch_timeout_minutes == 0 {
            errors.push("Batch timeout must be greater than 0".to_string());
        }

        if config.max_batch_size == 0 {
            errors.push("Max batch size must be greater than 0".to_string());
        }

        if config.rate_limit_per_minute == 0 {
            errors.push("Rate limit must be greater than 0".to_string());
        }

        if config.deduplication_window_minutes == 0 && config.alert_deduplication {
            errors.push("Deduplication window must be greater than 0 when deduplication is enabled".to_string());
        }

        if config.health_check_interval_minutes == 0 {
            errors.push("Health check interval must be greater than 0".to_string());
        }

        // Validar routing de prioridades
        if config.priority_routing.is_empty() {
            errors.push("Priority routing configuration is required".to_string());
        } else {
            for (severity, alerters) in &config.priority_routing {
                if alerters.is_empty() {
                    errors.push(format!("No alerters configured for severity: {}", severity));
                }

                for alerter in alerters {
                    match alerter.as_str() {
                        "Console" | "Email" | "Webhook" | "All" => {},
                        _ => errors.push(format!("Invalid alerter type: {}", alerter)),
                    }
                }
            }
        }

        errors
    }

    /// Crea resumen de configuración
    pub fn config_summary(config: &AlertManagerConfig) -> String {
        format!(
            "AlertManager Config: Enabled={}, Console={}, Email={}, Webhook={}, Batch={}, Dedup={}",
            config.enabled,
            config.console_enabled,
            config.email_enabled,
            config.webhook_enabled,
            config.batch_alerts,
            config.alert_deduplication
        )
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
            description: "This is a test security alert.".to_string(),
            related_events: vec![Uuid::new_v4()],
            mitigation_steps: vec!["Test action".to_string()],
            acknowledged: false,
        }
    }

    #[tokio::test]
    async fn test_alert_manager_creation() {
        let manager = AlertManager::new().await.unwrap();
        assert!(manager.config.enabled);
        assert!(manager.config.console_enabled);
    }

    #[tokio::test]
    async fn test_priority_determination() {
        let manager = AlertManager::new().await.unwrap();

        let critical_alert = create_test_alert();
        let priority = manager.determine_alert_priority(&critical_alert);
        assert_eq!(priority, AlertPriority::Emergency);

        let mut warning_alert = create_test_alert();
        warning_alert.severity = crate::Severity::Warning;
        let priority = manager.determine_alert_priority(&warning_alert);
        assert_eq!(priority, AlertPriority::High);
    }

    #[tokio::test]
    async fn test_target_alerters_determination() {
        let manager = AlertManager::new().await.unwrap();

        let critical_alert = create_test_alert();
        let alerters = manager.determine_target_alerters(&critical_alert);

        // Solo console debería estar habilitado por defecto
        assert!(alerters.contains(&AlerterType::Console));
    }

    #[tokio::test]
    async fn test_deduplication_key_generation() {
        let manager = AlertManager::new().await.unwrap();

        let alert1 = create_test_alert();
        let alert2 = SecurityAlert {
            title: alert1.title.clone(),
            severity: alert1.severity,
            ..create_test_alert()
        };

        let key1 = manager.generate_deduplication_key(&alert1);
        let key2 = manager.generate_deduplication_key(&alert2);

        assert_eq!(key1, key2);
    }

    #[tokio::test]
    async fn test_emergency_alert_detection() {
        let manager = AlertManager::new().await.unwrap();

        let critical_alert = create_test_alert();
        assert!(manager.is_emergency_alert(&critical_alert));

        let mut warning_alert = create_test_alert();
        warning_alert.severity = crate::Severity::Warning;
        assert!(!manager.is_emergency_alert(&warning_alert));
    }

    #[tokio::test]
    async fn test_statistics_updates() {
        let manager = AlertManager::new().await.unwrap();

        manager.update_processing_stats(100.0).await;
        manager.update_deduplication_stats().await;
        manager.update_batch_stats(5).await;

        let stats = manager.get_statistics().await;
        assert_eq!(stats.alerts_processed, 1);
        assert_eq!(stats.alerts_deduplicated, 1);
        assert_eq!(stats.alerts_batched, 5);
        assert_eq!(stats.average_processing_time_ms, 100.0);
    }

    #[tokio::test]
    async fn test_alerter_stats_updates() {
        let manager = AlertManager::new().await.unwrap();

        let result = AlerterResult {
            success: true,
            response_time_ms: 150,
            error_message: None,
            retry_scheduled: false,
        };

        manager.update_alerter_stats(&AlerterType::Console, &result).await;

        let stats = manager.get_statistics().await;
        let console_stats = stats.alerter_statistics.get("console").unwrap();

        assert_eq!(console_stats.alerts_sent, 1);
        assert_eq!(console_stats.alerts_failed, 0);
        assert_eq!(console_stats.average_response_time_ms, 150.0);
    }

    #[test]
    fn test_utility_configs() {
        let dev_config = utils::create_development_config();
        assert!(dev_config.console_enabled);
        assert!(!dev_config.batch_alerts);
        assert!(!dev_config.alert_deduplication);

        let prod_config = utils::create_production_config();
        assert!(prod_config.console_enabled);
        assert!(prod_config.email_enabled);
        assert!(prod_config.webhook_enabled);
        assert!(prod_config.batch_alerts);
        assert!(prod_config.alert_deduplication);

        let critical_config = utils::create_critical_only_config();
        assert!(!critical_config.batch_alerts);
        assert_eq!(critical_config.priority_routing.len(), 1);
        assert!(critical_config.priority_routing.contains_key("Critical"));
    }

    #[test]
    fn test_config_validation() {
        let valid_config = utils::create_production_config();
        let errors = utils::validate_config(&valid_config);
        assert!(errors.is_empty());

        let invalid_config = AlertManagerConfig {
            enabled: true,
            console_enabled: false,
            email_enabled: false,
            webhook_enabled: false,
            batch_timeout_minutes: 0,
            max_batch_size: 0,
            rate_limit_per_minute: 0,
            priority_routing: HashMap::new(),
            ..Default::default()
        };

        let errors = utils::validate_config(&invalid_config);
        assert!(!errors.is_empty());
        assert!(errors.len() >= 5); // Múltiples errores
    }

    #[tokio::test]
    async fn test_health_status_generation() {
        let manager = AlertManager::new().await.unwrap();
        let health = manager.get_health_status().await;

        assert!(health.get("overall_status").is_some());
        assert!(health.get("alerters").is_some());
        assert!(health.get("statistics").is_some());
        assert!(health.get("queues").is_some());
    }

    #[tokio::test]
    async fn test_activity_summary() {
        let manager = AlertManager::new().await.unwrap();

        // Agregar algunas alertas simuladas
        let alert = create_test_alert();
        let queued_alert = QueuedAlert {
            alert,
            queued_at: Utc::now(),
            priority: AlertPriority::Emergency,
            target_alerters: vec![AlerterType::Console],
            retry_count: 0,
            deduplication_key: None,
        };

        {
            let mut queue = manager.alert_queue.write().await;
            queue.push(queued_alert);
        }

        let summary = manager.get_activity_summary(24).await;
        assert_eq!(summary["total_alerts"], 1);
        assert!(summary["severity_breakdown"].is_object());
        assert!(summary["recent_alerts"].is_array());
    }
}