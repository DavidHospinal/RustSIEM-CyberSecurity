use crate::{LogEvent, SecurityAlert, Severity, EventType};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use std::collections::{HashMap, VecDeque};

/// Implementación de storage en memoria con optimizaciones para rendimiento
/// Útil para testing, desarrollo, y sistemas con requisitos de alta velocidad
#[derive(Clone)]
pub struct MemoryStorage {
    events: Arc<RwLock<VecDeque<LogEvent>>>,
    alerts: Arc<RwLock<Vec<SecurityAlert>>>,
    config: MemoryStorageConfig,
    // Índices para búsquedas rápidas
    event_indices: Arc<RwLock<EventIndices>>,
    alert_indices: Arc<RwLock<AlertIndices>>,
}

/// Configuración para el storage en memoria
#[derive(Clone, Debug)]
pub struct MemoryStorageConfig {
    /// Máximo número de eventos en memoria
    pub max_events: usize,
    /// Máximo número de alertas en memoria
    pub max_alerts: usize,
    /// Habilitar índices para búsquedas rápidas
    pub enable_indices: bool,
    /// Limpiar automáticamente datos antiguos
    pub auto_cleanup: bool,
    /// Intervalo de limpieza en horas
    pub cleanup_interval_hours: u64,
}

impl Default for MemoryStorageConfig {
    fn default() -> Self {
        Self {
            max_events: 100_000,
            max_alerts: 10_000,
            enable_indices: true,
            auto_cleanup: true,
            cleanup_interval_hours: 24,
        }
    }
}

/// Índices para eventos - permite búsquedas rápidas
#[derive(Default)]
struct EventIndices {
    by_severity: HashMap<String, Vec<usize>>,
    by_source: HashMap<String, Vec<usize>>,
    by_source_ip: HashMap<String, Vec<usize>>,
    by_event_type: HashMap<String, Vec<usize>>,
}

/// Índices para alertas
#[derive(Default)]
struct AlertIndices {
    by_severity: HashMap<String, Vec<usize>>,
    active_alerts: Vec<usize>,
    acknowledged_alerts: Vec<usize>,
}

impl MemoryStorage {
    /// Crea una nueva instancia con configuración por defecto
    pub async fn new() -> Result<Self> {
        Self::with_config(MemoryStorageConfig::default()).await
    }

    /// Crea una nueva instancia con configuración personalizada
    pub async fn with_config(config: MemoryStorageConfig) -> Result<Self> {
        let storage = Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(config.max_events))),
            alerts: Arc::new(RwLock::new(Vec::with_capacity(config.max_alerts))),
            config,
            event_indices: Arc::new(RwLock::new(EventIndices::default())),
            alert_indices: Arc::new(RwLock::new(AlertIndices::default())),
        };

        if storage.config.auto_cleanup {
            storage.start_cleanup_task().await;
        }

        tracing::info!("Memory storage initialized with max {} events and {} alerts", 
            storage.config.max_events, storage.config.max_alerts);

        Ok(storage)
    }

    /// Almacena un evento de log
    pub async fn store_event(&self, event: LogEvent) -> Result<()> {
        let mut events = self.events.write().await;

        // Verificar límite de capacidad
        if events.len() >= self.config.max_events {
            // Remover el evento más antiguo
            if let Some(old_event) = events.pop_front() {
                if self.config.enable_indices {
                    self.remove_event_from_indices(&old_event, 0).await;
                }
            }
        }

        let new_index = events.len();
        events.push_back(event.clone());

        // Actualizar índices si están habilitados
        if self.config.enable_indices {
            self.add_event_to_indices(&event, new_index).await;
        }

        tracing::debug!("Stored event in memory: {} (total: {})", event.id, events.len());
        Ok(())
    }

    /// Almacena una alerta de seguridad
    pub async fn store_alert(&self, alert: SecurityAlert) -> Result<()> {
        let mut alerts = self.alerts.write().await;

        // Verificar límite de capacidad
        if alerts.len() >= self.config.max_alerts {
            // Remover alertas reconocidas más antiguas primero
            if let Some(pos) = alerts.iter().position(|a| a.acknowledged) {
                let removed_alert = alerts.remove(pos);
                if self.config.enable_indices {
                    self.remove_alert_from_indices(&removed_alert, pos).await;
                }
            } else if !alerts.is_empty() {
                // Si no hay alertas reconocidas, remover la más antigua
                let removed_alert = alerts.remove(0);
                if self.config.enable_indices {
                    self.remove_alert_from_indices(&removed_alert, 0).await;
                }
            }
        }

        let new_index = alerts.len();
        alerts.push(alert.clone());

        // Actualizar índices si están habilitados
        if self.config.enable_indices {
            self.add_alert_to_indices(&alert, new_index).await;
        }

        tracing::debug!("Stored alert in memory: {} (total: {})", alert.id, alerts.len());
        Ok(())
    }

    /// Obtiene eventos recientes
    pub async fn get_recent_events(&self, limit: usize) -> Result<Vec<LogEvent>> {
        let events = self.events.read().await;
        let events_to_take = limit.min(events.len());

        Ok(events
            .iter()
            .rev()
            .take(events_to_take)
            .cloned()
            .collect())
    }

    /// Obtiene eventos filtrados
    pub async fn get_events_filtered(
        &self,
        limit: usize,
        severity: Option<&Severity>,
        source: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<LogEvent>> {
        if self.config.enable_indices && (severity.is_some() || source.is_some()) {
            self.get_events_filtered_with_indices(limit, severity, source, from, to).await
        } else {
            self.get_events_filtered_linear(limit, severity, source, from, to).await
        }
    }

    /// Búsqueda filtrada usando índices (más rápida)
    async fn get_events_filtered_with_indices(
        &self,
        limit: usize,
        severity: Option<&Severity>,
        source: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<LogEvent>> {
        let events = self.events.read().await;
        let indices = self.event_indices.read().await;

        let mut candidate_indices = Vec::new();

        // Usar índices para filtros principales
        if let Some(sev) = severity {
            let severity_key = severity_to_string(sev);
            if let Some(sev_indices) = indices.by_severity.get(&severity_key) {
                candidate_indices.extend(sev_indices.iter().cloned());
            }
        } else if let Some(src) = source {
            if let Some(src_indices) = indices.by_source.get(src) {
                candidate_indices.extend(src_indices.iter().cloned());
            }
        } else {
            // Si no hay filtros principales, usar todos los índices
            candidate_indices.extend(0..events.len());
        }

        // Filtrar por tiempo y otros criterios
        let mut filtered_events = Vec::new();
        for &index in &candidate_indices {
            if index >= events.len() {
                continue;
            }

            let event = &events[index];

            // Aplicar filtros adicionales
            if let Some(sev) = severity {
                if &event.severity != sev {
                    continue;
                }
            }

            if let Some(src) = source {
                if event.source != src {
                    continue;
                }
            }

            if let Some(from_time) = from {
                if event.timestamp < from_time {
                    continue;
                }
            }

            if let Some(to_time) = to {
                if event.timestamp > to_time {
                    continue;
                }
            }

            filtered_events.push(event.clone());

            if filtered_events.len() >= limit {
                break;
            }
        }

        // Ordenar por timestamp descendente
        filtered_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        filtered_events.truncate(limit);

        Ok(filtered_events)
    }

    /// Búsqueda filtrada lineal (más lenta pero completa)
    async fn get_events_filtered_linear(
        &self,
        limit: usize,
        severity: Option<&Severity>,
        source: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<LogEvent>> {
        let events = self.events.read().await;

        let filtered: Vec<LogEvent> = events
            .iter()
            .filter(|event| {
                if let Some(sev) = severity {
                    if &event.severity != sev {
                        return false;
                    }
                }

                if let Some(src) = source {
                    if event.source != src {
                        return false;
                    }
                }

                if let Some(from_time) = from {
                    if event.timestamp < from_time {
                        return false;
                    }
                }

                if let Some(to_time) = to {
                    if event.timestamp > to_time {
                        return false;
                    }
                }

                true
            })
            .rev()
            .take(limit)
            .cloned()
            .collect();

        Ok(filtered)
    }

    /// Obtiene alertas activas (no reconocidas)
    pub async fn get_active_alerts(&self) -> Result<Vec<SecurityAlert>> {
        if self.config.enable_indices {
            self.get_active_alerts_with_indices().await
        } else {
            self.get_active_alerts_linear().await
        }
    }

    /// Obtiene alertas activas usando índices
    async fn get_active_alerts_with_indices(&self) -> Result<Vec<SecurityAlert>> {
        let alerts = self.alerts.read().await;
        let indices = self.alert_indices.read().await;

        let mut active_alerts = Vec::new();
        for &index in &indices.active_alerts {
            if index < alerts.len() {
                active_alerts.push(alerts[index].clone());
            }
        }

        // Ordenar por timestamp descendente
        active_alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(active_alerts)
    }

    /// Obtiene alertas activas con búsqueda lineal
    async fn get_active_alerts_linear(&self) -> Result<Vec<SecurityAlert>> {
        let alerts = self.alerts.read().await;

        let active: Vec<SecurityAlert> = alerts
            .iter()
            .filter(|alert| !alert.acknowledged)
            .rev()
            .cloned()
            .collect();

        Ok(active)
    }

    /// Obtiene todas las alertas
    pub async fn get_all_alerts(&self, limit: Option<usize>) -> Result<Vec<SecurityAlert>> {
        let alerts = self.alerts.read().await;
        let alerts_to_take = limit.unwrap_or(alerts.len()).min(alerts.len());

        Ok(alerts
            .iter()
            .rev()
            .take(alerts_to_take)
            .cloned()
            .collect())
    }

    /// Reconoce una alerta
    pub async fn acknowledge_alert(&self, alert_id: &Uuid) -> Result<bool> {
        let mut alerts = self.alerts.write().await;

        if let Some(alert) = alerts.iter_mut().find(|a| a.id == *alert_id && !a.acknowledged) {
            alert.acknowledged = true;

            // Actualizar índices si están habilitados
            if self.config.enable_indices {
                if let Some(index) = alerts.iter().position(|a| a.id == *alert_id) {
                    self.update_alert_indices_after_acknowledgment(index).await;
                }
            }

            tracing::debug!("Acknowledged alert: {}", alert_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Obtiene estadísticas del dashboard
    pub async fn get_dashboard_stats(&self) -> Result<serde_json::Value> {
        let events = self.events.read().await;
        let alerts = self.alerts.read().await;

        let critical_alerts = alerts
            .iter()
            .filter(|a| matches!(a.severity, Severity::Critical) && !a.acknowledged)
            .count();

        let hour_ago = Utc::now() - chrono::Duration::hours(1);
        let events_last_hour = events
            .iter()
            .filter(|e| e.timestamp > hour_ago)
            .count();

        let acknowledged_alerts = alerts.iter().filter(|a| a.acknowledged).count();

        // Contar fuentes únicas en las últimas 24 horas
        let day_ago = Utc::now() - chrono::Duration::hours(24);
        let active_sources: std::collections::HashSet<String> = events
            .iter()
            .filter(|e| e.timestamp > day_ago)
            .map(|e| e.source.clone())
            .collect();

        // Calcular score de amenaza
        let recent_alerts = alerts
            .iter()
            .filter(|a| a.timestamp > day_ago && !a.acknowledged)
            .count();

        let threat_score = if recent_alerts == 0 {
            1.0
        } else if recent_alerts <= 5 {
            3.0 + (recent_alerts as f64 * 0.5)
        } else {
            6.0 + ((recent_alerts - 5) as f64 * 0.3).min(4.0)
        };

        Ok(serde_json::json!({
            "events_per_second": events_last_hour as f64 / 3600.0,
            "critical_alerts": critical_alerts,
            "threat_score": threat_score,
            "active_sources": active_sources.len(),
            "total_events": events.len(),
            "total_alerts": alerts.len(),
            "acknowledged_alerts": acknowledged_alerts
        }))
    }

    /// Obtiene estadísticas de eventos por severidad
    pub async fn get_events_by_severity(&self) -> Result<serde_json::Value> {
        let events = self.events.read().await;
        let mut stats = std::collections::HashMap::new();

        for event in events.iter() {
            let severity_str = severity_to_string(&event.severity);
            *stats.entry(severity_str).or_insert(0u64) += 1;
        }

        Ok(serde_json::to_value(stats)?)
    }

    /// Obtiene eventos por fuente
    pub async fn get_events_by_source(&self) -> Result<serde_json::Value> {
        let events = self.events.read().await;
        let mut stats = std::collections::HashMap::new();

        for event in events.iter() {
            *stats.entry(event.source.clone()).or_insert(0u64) += 1;
        }

        // Tomar solo los top 10
        let mut sorted_stats: Vec<_> = stats.into_iter().collect();
        sorted_stats.sort_by(|a, b| b.1.cmp(&a.1));
        sorted_stats.truncate(10);

        Ok(serde_json::to_value(sorted_stats.into_iter().collect::<std::collections::HashMap<_, _>>())?)
    }

    /// Limpia eventos antiguos
    pub async fn cleanup_old_events(&self, hours: u64) -> Result<u64> {
        let cutoff_time = Utc::now() - chrono::Duration::hours(hours as i64);
        let mut events = self.events.write().await;

        let original_len = events.len();
        events.retain(|event| event.timestamp > cutoff_time);
        let removed_count = original_len - events.len();

        if removed_count > 0 && self.config.enable_indices {
            self.rebuild_event_indices().await;
        }

        tracing::info!("Cleaned up {} old events", removed_count);
        Ok(removed_count as u64)
    }

    /// Limpia alertas reconocidas antiguas
    pub async fn cleanup_old_alerts(&self, hours: u64) -> Result<u64> {
        let cutoff_time = Utc::now() - chrono::Duration::hours(hours as i64);
        let mut alerts = self.alerts.write().await;

        let original_len = alerts.len();
        alerts.retain(|alert| {
            !alert.acknowledged || alert.timestamp > cutoff_time
        });
        let removed_count = original_len - alerts.len();

        if removed_count > 0 && self.config.enable_indices {
            self.rebuild_alert_indices().await;
        }

        tracing::info!("Cleaned up {} old alerts", removed_count);
        Ok(removed_count as u64)
    }

    /// Obtiene información sobre el storage en memoria
    pub async fn get_memory_info(&self) -> Result<serde_json::Value> {
        let events = self.events.read().await;
        let alerts = self.alerts.read().await;

        Ok(serde_json::json!({
            "events_count": events.len(),
            "events_capacity": self.config.max_events,
            "events_usage_percent": (events.len() as f64 / self.config.max_events as f64) * 100.0,
            "alerts_count": alerts.len(),
            "alerts_capacity": self.config.max_alerts,
            "alerts_usage_percent": (alerts.len() as f64 / self.config.max_alerts as f64) * 100.0,
            "indices_enabled": self.config.enable_indices,
            "auto_cleanup": self.config.auto_cleanup,
        }))
    }

    /// Limpia todo el contenido
    pub async fn clear_all(&self) -> Result<()> {
        let mut events = self.events.write().await;
        let mut alerts = self.alerts.write().await;

        events.clear();
        alerts.clear();

        if self.config.enable_indices {
            let mut event_indices = self.event_indices.write().await;
            let mut alert_indices = self.alert_indices.write().await;

            *event_indices = EventIndices::default();
            *alert_indices = AlertIndices::default();
        }

        tracing::info!("Cleared all data from memory storage");
        Ok(())
    }

    /// Inicia tarea de limpieza automática
    async fn start_cleanup_task(&self) {
        let storage = self.clone();
        let interval_hours = self.config.cleanup_interval_hours;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(interval_hours * 3600)
            );

            loop {
                interval.tick().await;

                if let Err(e) = storage.cleanup_old_events(interval_hours * 2).await {
                    tracing::error!("Auto cleanup events failed: {}", e);
                }

                if let Err(e) = storage.cleanup_old_alerts(interval_hours).await {
                    tracing::error!("Auto cleanup alerts failed: {}", e);
                }
            }
        });
    }

    /// Añade evento a los índices
    async fn add_event_to_indices(&self, event: &LogEvent, index: usize) {
        let mut indices = self.event_indices.write().await;

        let severity_key = severity_to_string(&event.severity);
        indices.by_severity.entry(severity_key).or_default().push(index);

        indices.by_source.entry(event.source.clone()).or_default().push(index);

        if let Some(ref ip) = event.source_ip {
            indices.by_source_ip.entry(ip.clone()).or_default().push(index);
        }

        let event_type_key = event_type_to_string(&event.event_type);
        indices.by_event_type.entry(event_type_key).or_default().push(index);
    }

    /// Remueve evento de los índices
    async fn remove_event_from_indices(&self, event: &LogEvent, index: usize) {
        let mut indices = self.event_indices.write().await;

        let severity_key = severity_to_string(&event.severity);
        if let Some(vec) = indices.by_severity.get_mut(&severity_key) {
            vec.retain(|&i| i != index);
        }

        if let Some(vec) = indices.by_source.get_mut(&event.source) {
            vec.retain(|&i| i != index);
        }

        if let Some(ref ip) = event.source_ip {
            if let Some(vec) = indices.by_source_ip.get_mut(ip) {
                vec.retain(|&i| i != index);
            }
        }

        let event_type_key = event_type_to_string(&event.event_type);
        if let Some(vec) = indices.by_event_type.get_mut(&event_type_key) {
            vec.retain(|&i| i != index);
        }
    }

    /// Añade alerta a los índices
    async fn add_alert_to_indices(&self, alert: &SecurityAlert, index: usize) {
        let mut indices = self.alert_indices.write().await;

        let severity_key = severity_to_string(&alert.severity);
        indices.by_severity.entry(severity_key).or_default().push(index);

        if alert.acknowledged {
            indices.acknowledged_alerts.push(index);
        } else {
            indices.active_alerts.push(index);
        }
    }

    /// Remueve alerta de los índices
    async fn remove_alert_from_indices(&self, alert: &SecurityAlert, index: usize) {
        let mut indices = self.alert_indices.write().await;

        let severity_key = severity_to_string(&alert.severity);
        if let Some(vec) = indices.by_severity.get_mut(&severity_key) {
            vec.retain(|&i| i != index);
        }

        if alert.acknowledged {
            indices.acknowledged_alerts.retain(|&i| i != index);
        } else {
            indices.active_alerts.retain(|&i| i != index);
        }
    }

    /// Actualiza índices después de reconocer una alerta
    async fn update_alert_indices_after_acknowledgment(&self, index: usize) {
        let mut indices = self.alert_indices.write().await;

        // Mover de activas a reconocidas
        indices.active_alerts.retain(|&i| i != index);
        indices.acknowledged_alerts.push(index);
    }

    /// Reconstruye índices de eventos
    async fn rebuild_event_indices(&self) {
        let events = self.events.read().await;
        let mut indices = self.event_indices.write().await;

        *indices = EventIndices::default();

        for (index, event) in events.iter().enumerate() {
            let severity_key = severity_to_string(&event.severity);
            indices.by_severity.entry(severity_key).or_default().push(index);

            indices.by_source.entry(event.source.clone()).or_default().push(index);

            if let Some(ref ip) = event.source_ip {
                indices.by_source_ip.entry(ip.clone()).or_default().push(index);
            }

            let event_type_key = event_type_to_string(&event.event_type);
            indices.by_event_type.entry(event_type_key).or_default().push(index);
        }
    }

    /// Reconstruye índices de alertas
    async fn rebuild_alert_indices(&self) {
        let alerts = self.alerts.read().await;
        let mut indices = self.alert_indices.write().await;

        *indices = AlertIndices::default();

        for (index, alert) in alerts.iter().enumerate() {
            let severity_key = severity_to_string(&alert.severity);
            indices.by_severity.entry(severity_key).or_default().push(index);

            if alert.acknowledged {
                indices.acknowledged_alerts.push(index);
            } else {
                indices.active_alerts.push(index);
            }
        }
    }

    /// Obtiene un evento por su ID
    pub async fn get_event_by_id(&self, event_id: &Uuid) -> Result<LogEvent> {
        let events = self.events.read().await;
        
        for event in events.iter() {
            if event.id == *event_id {
                return Ok(event.clone());
            }
        }
        
        Err(anyhow::anyhow!("Event with ID {} not found", event_id))
    }

    /// Obtiene eventos relacionados con un evento específico
    /// Los eventos relacionados se determinan por IP de origen similar y tiempo cercano
    pub async fn get_related_events(&self, event_id: &Uuid, limit: usize) -> Result<Vec<LogEvent>> {
        let events = self.events.read().await;
        
        // Primero encontrar el evento principal
        let target_event = events.iter()
            .find(|e| e.id == *event_id)
            .ok_or_else(|| anyhow::anyhow!("Event with ID {} not found", event_id))?;
        
        let time_window = chrono::Duration::hours(1); // Buscar eventos en +/- 1 hora
        let start_time = target_event.timestamp - time_window;
        let end_time = target_event.timestamp + time_window;
        
        let mut related_events = Vec::new();
        
        for event in events.iter() {
            // No incluir el evento mismo
            if event.id == *event_id {
                continue;
            }
            
            // Verificar si está en la ventana de tiempo
            if event.timestamp < start_time || event.timestamp > end_time {
                continue;
            }
            
            // Considerar relacionado si:
            // 1. Misma IP de origen
            // 2. Mismo tipo de evento
            // 3. Misma fuente
            let is_related = if let (Some(ref target_ip), Some(ref event_ip)) = 
                (&target_event.source_ip, &event.source_ip) {
                target_ip == event_ip
            } else {
                false
            } || target_event.event_type == event.event_type
              || target_event.source == event.source;
            
            if is_related {
                related_events.push(event.clone());
            }
            
            if related_events.len() >= limit {
                break;
            }
        }
        
        // Ordenar por timestamp (más recientes primero)
        related_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        Ok(related_events)
    }
}

/// Convierte Severity a String
fn severity_to_string(severity: &Severity) -> String {
    match severity {
        Severity::Low => "Low".to_string(),
        Severity::Info => "Info".to_string(),
        Severity::Medium => "Medium".to_string(),
        Severity::Warning => "Warning".to_string(),
        Severity::High => "High".to_string(),
        Severity::Critical => "Critical".to_string(),
    }
}

/// Convierte EventType a String
fn event_type_to_string(event_type: &EventType) -> String {
    match event_type {
        EventType::Normal => "Normal".to_string(),
        EventType::SqlInjection => "SqlInjection".to_string(),
        EventType::XssAttempt => "XssAttempt".to_string(),
        EventType::BruteForce => "BruteForce".to_string(),
        EventType::Anomaly => "Anomaly".to_string(),
        EventType::SuspiciousActivity => "SuspiciousActivity".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_retrieve_events() {
        let storage = MemoryStorage::new().await.unwrap();

        let event = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "test".to_string(),
            severity: Severity::Warning,
            source_ip: Some("192.168.1.1".to_string()),
            raw_message: "Test message".to_string(),
            parsed_data: serde_json::json!({"test": "data"}),
            event_type: EventType::Normal,
            iocs: vec!["test_ioc".to_string()],
        };

        storage.store_event(event.clone()).await.unwrap();
        let events = storage.get_recent_events(10).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
    }

    #[tokio::test]
    async fn test_filtered_search() {
        let storage = MemoryStorage::new().await.unwrap();

        let event1 = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "apache".to_string(),
            severity: Severity::Critical,
            source_ip: Some("192.168.1.1".to_string()),
            raw_message: "Critical error".to_string(),
            parsed_data: serde_json::json!({}),
            event_type: EventType::Normal,
            iocs: vec![],
        };

        let event2 = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "nginx".to_string(),
            severity: Severity::Warning,
            source_ip: Some("192.168.1.2".to_string()),
            raw_message: "Warning message".to_string(),
            parsed_data: serde_json::json!({}),
            event_type: EventType::Normal,
            iocs: vec![],
        };

        storage.store_event(event1.clone()).await.unwrap();
        storage.store_event(event2.clone()).await.unwrap();

        // Test filter by severity
        let critical_events = storage.get_events_filtered(
            10, Some(&Severity::Critical), None, None, None
        ).await.unwrap();
        assert_eq!(critical_events.len(), 1);
        assert_eq!(critical_events[0].id, event1.id);

        // Test filter by source
        let nginx_events = storage.get_events_filtered(
            10, None, Some("nginx"), None, None
        ).await.unwrap();
        assert_eq!(nginx_events.len(), 1);
        assert_eq!(nginx_events[0].id, event2.id);
    }

    #[tokio::test]
    async fn test_capacity_limits() {
        let config = MemoryStorageConfig {
            max_events: 2,
            max_alerts: 2,
            ..Default::default()
        };

        let storage = MemoryStorage::with_config(config).await.unwrap();

        // Add more events than capacity
        for i in 0..5 {
            let event = LogEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                source: format!("source_{}", i),
                severity: Severity::Info,
                source_ip: None,
                raw_message: format!("Message {}", i),
                parsed_data: serde_json::json!({}),
                event_type: EventType::Normal,
                iocs: vec![],
            };
            storage.store_event(event).await.unwrap();
        }

        let events = storage.get_recent_events(10).await.unwrap();
        assert_eq!(events.len(), 2); // Should only keep last 2
    }

    #[tokio::test]
    async fn test_alert_acknowledgment() {
        let storage = MemoryStorage::new().await.unwrap();

        let alert = SecurityAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: Severity::Critical,
            title: "Test Alert".to_string(),
            description: "Test Description".to_string(),
            related_events: vec![],
            mitigation_steps: vec![],
            acknowledged: false,
        };

        storage.store_alert(alert.clone()).await.unwrap();

        let active_before = storage.get_active_alerts().await.unwrap();
        assert_eq!(active_before.len(), 1);

        let acknowledged = storage.acknowledge_alert(&alert.id).await.unwrap();
        assert!(acknowledged);

        let active_after = storage.get_active_alerts().await.unwrap();
        assert_eq!(active_after.len(), 0);
    }

    #[tokio::test]
    async fn test_dashboard_stats() {
        let storage = MemoryStorage::new().await.unwrap();

        let stats = storage.get_dashboard_stats().await.unwrap();

        assert!(stats.get("events_per_second").is_some());
        assert!(stats.get("critical_alerts").is_some());
        assert!(stats.get("threat_score").is_some());
        assert!(stats.get("active_sources").is_some());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let storage = MemoryStorage::new().await.unwrap();

        // Add old event
        let old_event = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now() - chrono::Duration::hours(25),
            source: "test".to_string(),
            severity: Severity::Info,
            source_ip: None,
            raw_message: "Old message".to_string(),
            parsed_data: serde_json::json!({}),
            event_type: EventType::Normal,
            iocs: vec![],
        };

        storage.store_event(old_event).await.unwrap();

        let events_before = storage.get_recent_events(10).await.unwrap();
        assert_eq!(events_before.len(), 1);

        let removed = storage.cleanup_old_events(24).await.unwrap();
        assert_eq!(removed, 1);

        let events_after = storage.get_recent_events(10).await.unwrap();
        assert_eq!(events_after.len(), 0);
    }
}