use crate::{LogEvent, SecurityAlert, Severity};
use crate::storage::{MemoryStorage, SqliteStorage};
use anyhow::{Result, Context};
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Tipos de storage disponibles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    Memory,
    Sqlite,
    Hybrid, // Memory + SQLite para backup
}

/// Configuración del Storage Manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub storage_type: StorageType,
    pub sqlite_path: Option<String>,
    pub memory_max_events: Option<usize>,
    pub memory_max_alerts: Option<usize>,
    pub auto_backup: bool,
    pub backup_interval_minutes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::Memory,
            sqlite_path: Some("rustsiem.db".to_string()),
            memory_max_events: Some(100_000),
            memory_max_alerts: Some(10_000),
            auto_backup: false,
            backup_interval_minutes: 30,
        }
    }
}

/// Storage Manager que abstrae diferentes tipos de almacenamiento
#[derive(Clone)]
pub struct StorageManager {
    storage_impl: StorageImplementation,
    config: StorageConfig,
}

/// Implementaciones internas de storage
#[derive(Clone)]
enum StorageImplementation {
    Memory(Arc<MemoryStorage>),
    Sqlite(Arc<SqliteStorage>),
    Hybrid {
        memory: Arc<MemoryStorage>,
        sqlite: Arc<SqliteStorage>,
    },
}

impl StorageManager {
    /// Crea un nuevo StorageManager con configuración por defecto (Memory)
    pub async fn new() -> Result<Self> {
        Self::with_config(StorageConfig::default()).await
    }

    /// Crea un StorageManager con configuración específica
    pub async fn with_config(config: StorageConfig) -> Result<Self> {
        let storage_impl = match config.storage_type {
            StorageType::Memory => {
                let mut memory_config = crate::storage::memory::MemoryStorageConfig::default();
                if let Some(max_events) = config.memory_max_events {
                    memory_config.max_events = max_events;
                }
                if let Some(max_alerts) = config.memory_max_alerts {
                    memory_config.max_alerts = max_alerts;
                }

                let memory_storage = MemoryStorage::with_config(memory_config).await?;
                StorageImplementation::Memory(Arc::new(memory_storage))
            },

            StorageType::Sqlite => {
                let db_path = config.sqlite_path.as_deref().unwrap_or("rustsiem.db");
                let sqlite_storage = SqliteStorage::new(&format!("sqlite:{}", db_path)).await?;
                StorageImplementation::Sqlite(Arc::new(sqlite_storage))
            },

            StorageType::Hybrid => {
                let mut memory_config = crate::storage::memory::MemoryStorageConfig::default();
                if let Some(max_events) = config.memory_max_events {
                    memory_config.max_events = max_events;
                }
                if let Some(max_alerts) = config.memory_max_alerts {
                    memory_config.max_alerts = max_alerts;
                }

                let memory_storage = MemoryStorage::with_config(memory_config).await?;

                let db_path = config.sqlite_path.as_deref().unwrap_or("rustsiem.db");
                let sqlite_storage = SqliteStorage::new(&format!("sqlite:{}", db_path)).await?;

                StorageImplementation::Hybrid {
                    memory: Arc::new(memory_storage),
                    sqlite: Arc::new(sqlite_storage),
                }
            },
        };

        let manager = Self {
            storage_impl,
            config: config.clone(),
        };

        // Iniciar backup automático si está configurado
        if config.auto_backup && matches!(config.storage_type, StorageType::Hybrid) {
            manager.start_backup_task().await;
        }

        tracing::info!("Storage manager initialized with type: {:?}", config.storage_type);
        Ok(manager)
    }

    /// Almacena un evento de log
    pub async fn store_event(&self, event: LogEvent) -> Result<()> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.store_event(event).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.store_event(&event).await
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                // Almacenar en memoria primero (más rápido)
                memory.store_event(event.clone()).await?;

                // Almacenar en SQLite de manera asíncrona
                let sqlite_clone = sqlite.clone();
                let event_clone = event.clone();
                tokio::spawn(async move {
                    if let Err(e) = sqlite_clone.store_event(&event_clone).await {
                        tracing::error!("Failed to store event in SQLite: {}", e);
                    }
                });

                Ok(())
            },
        }
    }

    /// Almacena una alerta de seguridad
    pub async fn store_alert(&self, alert: SecurityAlert) -> Result<()> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.store_alert(alert).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.store_alert(&alert).await
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                // Almacenar en memoria primero
                memory.store_alert(alert.clone()).await?;

                // Almacenar en SQLite de manera asíncrona
                let sqlite_clone = sqlite.clone();
                let alert_clone = alert.clone();
                tokio::spawn(async move {
                    if let Err(e) = sqlite_clone.store_alert(&alert_clone).await {
                        tracing::error!("Failed to store alert in SQLite: {}", e);
                    }
                });

                Ok(())
            },
        }
    }

    /// Obtiene eventos recientes
    pub async fn get_recent_events(&self, limit: usize) -> Result<Vec<LogEvent>> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_recent_events(limit).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_recent_events(limit).await
            },
            StorageImplementation::Hybrid { memory, .. } => {
                // En modo híbrido, priorizar memoria para consultas rápidas
                memory.get_recent_events(limit).await
            },
        }
    }

    /// Obtiene eventos filtrados
    pub async fn get_events_filtered(
        &self,
        limit: usize,
        severity: Option<Severity>,
        source: Option<String>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<LogEvent>> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_events_filtered(
                    limit,
                    severity.as_ref(),
                    source.as_deref(),
                    from,
                    to
                ).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_events_filtered(
                    limit,
                    severity.as_ref(),
                    source.as_deref(),
                    from,
                    to
                ).await
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                // Intentar primero en memoria, luego en SQLite si no hay suficientes resultados
                let memory_results = memory.get_events_filtered(
                    limit,
                    severity.as_ref(),
                    source.as_deref(),
                    from,
                    to
                ).await?;

                if memory_results.len() < limit {
                    // Complementar con datos de SQLite si es necesario
                    let remaining = limit - memory_results.len();
                    let sqlite_results = sqlite.get_events_filtered(
                        remaining,
                        severity.as_ref(),
                        source.as_deref(),
                        from,
                        to
                    ).await?;

                    let mut combined = memory_results;
                    for sqlite_event in sqlite_results {
                        // Evitar duplicados
                        if !combined.iter().any(|e| e.id == sqlite_event.id) {
                            combined.push(sqlite_event);
                        }
                    }

                    // Ordenar por timestamp y limitar
                    combined.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                    combined.truncate(limit);
                    Ok(combined)
                } else {
                    Ok(memory_results)
                }
            },
        }
    }

    /// Obtiene alertas activas
    pub async fn get_active_alerts(&self) -> Result<Vec<SecurityAlert>> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_active_alerts().await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_active_alerts().await
            },
            StorageImplementation::Hybrid { memory, .. } => {
                // En modo híbrido, usar memoria para alertas activas
                memory.get_active_alerts().await
            },
        }
    }

    /// Obtiene todas las alertas
    pub async fn get_all_alerts(&self, limit: Option<usize>) -> Result<Vec<SecurityAlert>> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_all_alerts(limit).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_all_alerts(limit).await
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                // En modo híbrido, combinar resultados de ambos storages
                let memory_alerts = memory.get_all_alerts(None).await?;
                let sqlite_alerts = sqlite.get_all_alerts(None).await?;

                let mut combined = memory_alerts;
                for sqlite_alert in sqlite_alerts {
                    // Evitar duplicados
                    if !combined.iter().any(|a| a.id == sqlite_alert.id) {
                        combined.push(sqlite_alert);
                    }
                }

                // Ordenar por timestamp y aplicar límite
                combined.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                if let Some(limit) = limit {
                    combined.truncate(limit);
                }

                Ok(combined)
            },
        }
    }

    /// Reconoce una alerta
    pub async fn acknowledge_alert(&self, alert_id: Uuid) -> Result<()> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.acknowledge_alert(&alert_id).await?;
                Ok(())
            },
            StorageImplementation::Sqlite(storage) => {
                storage.acknowledge_alert(&alert_id).await?;
                Ok(())
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                // Actualizar en ambos storages
                let memory_result = memory.acknowledge_alert(&alert_id).await;
                let sqlite_result = sqlite.acknowledge_alert(&alert_id).await;

                // Si al menos uno tuvo éxito, considerarlo exitoso
                if memory_result.is_ok() || sqlite_result.is_ok() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Failed to acknowledge alert in both storages"))
                }
            },
        }
    }

    /// Obtiene estadísticas del dashboard
    pub async fn get_dashboard_stats(&self) -> Result<serde_json::Value> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_dashboard_stats().await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_dashboard_stats().await
            },
            StorageImplementation::Hybrid { memory, .. } => {
                // En modo híbrido, usar estadísticas de memoria para velocidad
                memory.get_dashboard_stats().await
            },
        }
    }

    /// Obtiene estadísticas de eventos por severidad
    pub async fn get_events_by_severity(&self) -> Result<serde_json::Value> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_events_by_severity().await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_events_by_severity().await
            },
            StorageImplementation::Hybrid { sqlite, .. } => {
                // Para estadísticas históricas, usar SQLite
                sqlite.get_events_by_severity().await
            },
        }
    }

    /// Obtiene eventos por fuente
    pub async fn get_events_by_source(&self) -> Result<serde_json::Value> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_events_by_source().await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_events_by_source().await
            },
            StorageImplementation::Hybrid { sqlite, .. } => {
                // Para estadísticas históricas, usar SQLite
                sqlite.get_events_by_source().await
            },
        }
    }

    /// Limpia eventos antiguos
    pub async fn cleanup_old_events(&self, days: i64) -> Result<u64> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.cleanup_old_events(days as u64 * 24).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.cleanup_old_events(days).await
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                let memory_cleaned = memory.cleanup_old_events(days as u64 * 24).await?;
                let sqlite_cleaned = sqlite.cleanup_old_events(days).await?;
                Ok(memory_cleaned + sqlite_cleaned)
            },
        }
    }

    /// Limpia alertas reconocidas antiguas
    pub async fn cleanup_old_alerts(&self, days: i64) -> Result<u64> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.cleanup_old_alerts(days as u64 * 24).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.cleanup_old_alerts(days).await
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                let memory_cleaned = memory.cleanup_old_alerts(days as u64 * 24).await?;
                let sqlite_cleaned = sqlite.cleanup_old_alerts(days).await?;
                Ok(memory_cleaned + sqlite_cleaned)
            },
        }
    }

    /// Obtiene información sobre el storage
    pub async fn get_storage_info(&self) -> Result<serde_json::Value> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                let mut info = storage.get_memory_info().await?;
                info["storage_type"] = serde_json::Value::String("Memory".to_string());
                Ok(info)
            },
            StorageImplementation::Sqlite(storage) => {
                let mut info = storage.get_database_info().await?;
                info["storage_type"] = serde_json::Value::String("SQLite".to_string());
                Ok(info)
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                let memory_info = memory.get_memory_info().await?;
                let sqlite_info = sqlite.get_database_info().await?;

                Ok(serde_json::json!({
                    "storage_type": "Hybrid",
                    "memory": memory_info,
                    "sqlite": sqlite_info,
                    "auto_backup": self.config.auto_backup,
                    "backup_interval_minutes": self.config.backup_interval_minutes
                }))
            },
        }
    }

    /// Exporta datos desde memoria a SQLite (para modo híbrido)
    pub async fn backup_memory_to_sqlite(&self) -> Result<(u64, u64)> {
        match &self.storage_impl {
            StorageImplementation::Hybrid { memory, sqlite } => {
                // Exportar eventos
                let events = memory.get_recent_events(usize::MAX).await?;
                let mut events_backed_up = 0u64;

                for event in events {
                    if sqlite.store_event(&event).await.is_ok() {
                        events_backed_up += 1;
                    }
                }

                // Exportar alertas
                let alerts = memory.get_all_alerts(None).await?;
                let mut alerts_backed_up = 0u64;

                for alert in alerts {
                    if sqlite.store_alert(&alert).await.is_ok() {
                        alerts_backed_up += 1;
                    }
                }

                tracing::info!("Backed up {} events and {} alerts to SQLite",
                    events_backed_up, alerts_backed_up);

                Ok((events_backed_up, alerts_backed_up))
            },
            _ => {
                Err(anyhow::anyhow!("Backup is only available in Hybrid mode"))
            },
        }
    }

    /// Importa datos desde SQLite a memoria (para modo híbrido)
    pub async fn restore_sqlite_to_memory(&self, limit: Option<usize>) -> Result<(u64, u64)> {
        match &self.storage_impl {
            StorageImplementation::Hybrid { memory, sqlite } => {
                // Importar eventos
                let events = sqlite.get_recent_events(limit.unwrap_or(10000)).await?;
                let mut events_restored = 0u64;

                for event in events {
                    if memory.store_event(event).await.is_ok() {
                        events_restored += 1;
                    }
                }

                // Importar alertas activas
                let alerts = sqlite.get_active_alerts().await?;
                let mut alerts_restored = 0u64;

                for alert in alerts {
                    if memory.store_alert(alert).await.is_ok() {
                        alerts_restored += 1;
                    }
                }

                tracing::info!("Restored {} events and {} alerts from SQLite",
                    events_restored, alerts_restored);

                Ok((events_restored, alerts_restored))
            },
            _ => {
                Err(anyhow::anyhow!("Restore is only available in Hybrid mode"))
            },
        }
    }

    /// Inicia tarea de backup automático para modo híbrido
    async fn start_backup_task(&self) {
        if let StorageImplementation::Hybrid { .. } = &self.storage_impl {
            let manager = self.clone();
            let interval_minutes = self.config.backup_interval_minutes;

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(
                    tokio::time::Duration::from_secs(interval_minutes * 60)
                );

                loop {
                    interval.tick().await;

                    if let Err(e) = manager.backup_memory_to_sqlite().await {
                        tracing::error!("Auto backup failed: {}", e);
                    } else {
                        tracing::debug!("Auto backup completed successfully");
                    }
                }
            });

            tracing::info!("Started auto backup task with interval: {} minutes", interval_minutes);
        }
    }

    /// Cambia el tipo de storage (requiere reinicio)
    pub async fn migrate_to_storage_type(&self, new_type: StorageType) -> Result<StorageManager> {
        let new_config = StorageConfig {
            storage_type: new_type,
            ..self.config.clone()
        };

        // Crear nuevo storage
        let new_manager = Self::with_config(new_config).await?;

        // Migrar datos si es posible
        match (&self.storage_impl, &new_manager.storage_impl) {
            (StorageImplementation::Memory(old), StorageImplementation::Sqlite(new)) => {
                // Migrar de memoria a SQLite
                let events = old.get_recent_events(usize::MAX).await?;
                let alerts = old.get_all_alerts(None).await?;

                for event in events {
                    new.store_event(&event).await?;
                }

                for alert in alerts {
                    new.store_alert(&alert).await?;
                }

                tracing::info!("Migrated data from Memory to SQLite");
            },

            (StorageImplementation::Sqlite(old), StorageImplementation::Memory(new)) => {
                // Migrar de SQLite a memoria (limitado por capacidad)
                let events = old.get_recent_events(new_manager.config.memory_max_events.unwrap_or(10000)).await?;
                let alerts = old.get_active_alerts().await?;

                for event in events {
                    new.store_event(event).await?;
                }

                for alert in alerts {
                    new.store_alert(alert).await?;
                }

                tracing::info!("Migrated data from SQLite to Memory");
            },

            _ => {
                tracing::warn!("Migration between these storage types is not fully supported");
            }
        }

        Ok(new_manager)
    }

    /// Obtiene configuración actual
    pub fn get_config(&self) -> &StorageConfig {
        &self.config
    }

    /// Obtiene tipo de storage actual
    pub fn get_storage_type(&self) -> &StorageType {
        &self.config.storage_type
    }

    /// Obtiene un evento por su ID
    pub async fn get_event_by_id(&self, event_id: Uuid) -> Result<LogEvent> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_event_by_id(&event_id).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_event_by_id(&event_id).await
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                // Intentar primero en memoria, luego en SQLite
                if let Ok(event) = memory.get_event_by_id(&event_id).await {
                    Ok(event)
                } else {
                    sqlite.get_event_by_id(&event_id).await
                }
            },
        }
    }

    /// Obtiene eventos relacionados con un evento específico
    pub async fn get_related_events(&self, event_id: Uuid, limit: usize) -> Result<Vec<LogEvent>> {
        match &self.storage_impl {
            StorageImplementation::Memory(storage) => {
                storage.get_related_events(&event_id, limit).await
            },
            StorageImplementation::Sqlite(storage) => {
                storage.get_related_events(&event_id, limit).await
            },
            StorageImplementation::Hybrid { memory, sqlite } => {
                // Combinar resultados de ambos storages
                let memory_events = memory.get_related_events(&event_id, limit).await.unwrap_or_default();
                let sqlite_events = sqlite.get_related_events(&event_id, limit).await.unwrap_or_default();
                
                let mut combined = memory_events;
                for sqlite_event in sqlite_events {
                    if !combined.iter().any(|e| e.id == sqlite_event.id) {
                        combined.push(sqlite_event);
                    }
                }
                
                // Ordenar por timestamp y limitar
                combined.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                combined.truncate(limit);
                Ok(combined)
            },
        }
    }
}

/// Utilidades para configuración de storage
pub mod config {
    use super::*;

    /// Crea configuración para storage en memoria optimizado para desarrollo
    pub fn development_memory_config() -> StorageConfig {
        StorageConfig {
            storage_type: StorageType::Memory,
            memory_max_events: Some(10_000),
            memory_max_alerts: Some(1_000),
            auto_backup: false,
            ..Default::default()
        }
    }

    /// Crea configuración para storage SQLite optimizado para producción
    pub fn production_sqlite_config(db_path: &str) -> StorageConfig {
        StorageConfig {
            storage_type: StorageType::Sqlite,
            sqlite_path: Some(db_path.to_string()),
            auto_backup: false,
            ..Default::default()
        }
    }

    /// Crea configuración híbrida para alta performance con persistencia
    pub fn hybrid_config(db_path: &str) -> StorageConfig {
        StorageConfig {
            storage_type: StorageType::Hybrid,
            sqlite_path: Some(db_path.to_string()),
            memory_max_events: Some(50_000),
            memory_max_alerts: Some(5_000),
            auto_backup: true,
            backup_interval_minutes: 15,
        }
    }

    /// Crea configuración desde variables de entorno
    pub fn from_env() -> StorageConfig {
        let storage_type = match std::env::var("RUSTSIEM_STORAGE_TYPE")
            .unwrap_or_else(|_| "memory".to_string())
            .to_lowercase()
            .as_str() {
            "sqlite" => StorageType::Sqlite,
            "hybrid" => StorageType::Hybrid,
            _ => StorageType::Memory,
        };

        StorageConfig {
            storage_type,
            sqlite_path: std::env::var("RUSTSIEM_DB_PATH").ok(),
            memory_max_events: std::env::var("RUSTSIEM_MAX_EVENTS")
                .ok()
                .and_then(|s| s.parse().ok()),
            memory_max_alerts: std::env::var("RUSTSIEM_MAX_ALERTS")
                .ok()
                .and_then(|s| s.parse().ok()),
            auto_backup: std::env::var("RUSTSIEM_AUTO_BACKUP")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            backup_interval_minutes: std::env::var("RUSTSIEM_BACKUP_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_memory_storage_manager() {
        let config = config::development_memory_config();
        let manager = StorageManager::with_config(config).await.unwrap();

        let event = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "test".to_string(),
            severity: Severity::Info,
            source_ip: None,
            raw_message: "Test message".to_string(),
            parsed_data: serde_json::json!({}),
            event_type: crate::EventType::Normal,
            iocs: vec![],
        };

        manager.store_event(event.clone()).await.unwrap();
        let events = manager.get_recent_events(10).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
    }

    #[tokio::test]
    async fn test_sqlite_storage_manager() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = config::production_sqlite_config(&db_path.to_string_lossy());
        let manager = StorageManager::with_config(config).await.unwrap();

        let alert = SecurityAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: Severity::Critical,
            title: "Test Alert".to_string(),
            description: "Test".to_string(),
            related_events: vec![],
            mitigation_steps: vec![],
            acknowledged: false,
        };

        manager.store_alert(alert.clone()).await.unwrap();
        let alerts = manager.get_active_alerts().await.unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].id, alert.id);
    }

    #[tokio::test]
    async fn test_hybrid_storage_manager() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("hybrid.db");
        let config = config::hybrid_config(&db_path.to_string_lossy());
        let manager = StorageManager::with_config(config).await.unwrap();

        let event = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "test".to_string(),
            severity: Severity::Warning,
            source_ip: Some("192.168.1.1".to_string()),
            raw_message: "Hybrid test".to_string(),
            parsed_data: serde_json::json!({"test": true}),
            event_type: crate::EventType::Normal,
            iocs: vec![],
        };

        manager.store_event(event.clone()).await.unwrap();

        // Dar tiempo para el almacenamiento asíncrono
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let events = manager.get_recent_events(10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
    }

    #[tokio::test]
    async fn test_storage_migration() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("migration.db");

        // Crear manager con memoria
        let memory_config = config::development_memory_config();
        let memory_manager = StorageManager::with_config(memory_config).await.unwrap();

        // Agregar datos
        let event = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: "migration_test".to_string(),
            severity: Severity::Info,
            source_ip: None,
            raw_message: "Migration test".to_string(),
            parsed_data: serde_json::json!({}),
            event_type: crate::EventType::Normal,
            iocs: vec![],
        };

        memory_manager.store_event(event.clone()).await.unwrap();

        // Migrar a SQLite
        let sqlite_manager = memory_manager.migrate_to_storage_type(StorageType::Sqlite).await.unwrap();

        // Verificar que los datos se migraron
        let events = sqlite_manager.get_recent_events(10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
    }
}