use crate::{LogEvent, SecurityAlert, Severity, EventType};
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool, Sqlite, migrate::MigrateDatabase};

use uuid::Uuid;
use serde_json;


/// Implementación de storage usando SQLite para persistencia
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    /// Crea una nueva instancia de SqliteStorage
    pub async fn new(database_url: &str) -> Result<Self> {
        // Crear base de datos si no existe
        if !Sqlite::database_exists(database_url).await.unwrap_or(false) {
            Sqlite::create_database(database_url).await
                .context("Failed to create SQLite database")?;
            tracing::info!("Created SQLite database: {}", database_url);
        }

        // Crear pool de conexiones
        let pool = SqlitePool::connect(database_url).await
            .context("Failed to connect to SQLite database")?;

        let storage = Self { pool };

        // Inicializar esquema
        storage.initialize_schema().await?;

        tracing::info!("SQLite storage initialized successfully");
        Ok(storage)
    }

    /// Crea una instancia con archivo por defecto
    pub async fn new_default() -> Result<Self> {
        let db_path = "rustsiem.db";
        let database_url = format!("sqlite:{}", db_path);
        Self::new(&database_url).await
    }

    /// Inicializa el esquema de la base de datos
    async fn initialize_schema(&self) -> Result<()> {
        // Tabla de eventos de log
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS log_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                raw_message TEXT NOT NULL,
                parsed_data TEXT NOT NULL,
                event_type TEXT NOT NULL,
                iocs TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        "#)
            .execute(&self.pool)
            .await
            .context("Failed to create log_events table")?;

        // Tabla de alertas de seguridad
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS security_alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                related_events TEXT NOT NULL,
                mitigation_steps TEXT NOT NULL,
                acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        "#)
            .execute(&self.pool)
            .await
            .context("Failed to create security_alerts table")?;

        // Índices para optimización
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON log_events(timestamp)")
            .execute(&self.pool).await.ok();

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_severity ON log_events(severity)")
            .execute(&self.pool).await.ok();

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_source ON log_events(source)")
            .execute(&self.pool).await.ok();

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON log_events(source_ip)")
            .execute(&self.pool).await.ok();

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp)")
            .execute(&self.pool).await.ok();

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity)")
            .execute(&self.pool).await.ok();

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON security_alerts(acknowledged)")
            .execute(&self.pool).await.ok();

        tracing::debug!("Database schema initialized with indices");
        Ok(())
    }

    /// Almacena un evento de log
    pub async fn store_event(&self, event: &LogEvent) -> Result<()> {
        let iocs_json = serde_json::to_string(&event.iocs)?;
        let parsed_data_json = serde_json::to_string(&event.parsed_data)?;

        sqlx::query(r#"
            INSERT INTO log_events (
                id, timestamp, source, severity, source_ip, 
                raw_message, parsed_data, event_type, iocs
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
            .bind(event.id.to_string())
            .bind(event.timestamp.to_rfc3339())
            .bind(&event.source)
            .bind(severity_to_string(&event.severity))
            .bind(&event.source_ip)
            .bind(&event.raw_message)
            .bind(parsed_data_json)
            .bind(event_type_to_string(&event.event_type))
            .bind(iocs_json)
            .execute(&self.pool)
            .await
            .context("Failed to store log event")?;

        tracing::debug!("Stored log event: {}", event.id);
        Ok(())
    }

    /// Almacena una alerta de seguridad
    pub async fn store_alert(&self, alert: &SecurityAlert) -> Result<()> {
        let related_events_json = serde_json::to_string(&alert.related_events)?;
        let mitigation_steps_json = serde_json::to_string(&alert.mitigation_steps)?;

        sqlx::query(r#"
            INSERT INTO security_alerts (
                id, timestamp, severity, title, description,
                related_events, mitigation_steps, acknowledged
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#)
            .bind(alert.id.to_string())
            .bind(alert.timestamp.to_rfc3339())
            .bind(severity_to_string(&alert.severity))
            .bind(&alert.title)
            .bind(&alert.description)
            .bind(related_events_json)
            .bind(mitigation_steps_json)
            .bind(alert.acknowledged)
            .execute(&self.pool)
            .await
            .context("Failed to store security alert")?;

        tracing::debug!("Stored security alert: {}", alert.id);
        Ok(())
    }

    /// Obtiene eventos recientes
    pub async fn get_recent_events(&self, limit: usize) -> Result<Vec<LogEvent>> {
        let rows = sqlx::query(r#"
            SELECT id, timestamp, source, severity, source_ip, 
                   raw_message, parsed_data, event_type, iocs
            FROM log_events 
            ORDER BY timestamp DESC 
            LIMIT ?
        "#)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch recent events")?;

        let mut events = Vec::new();
        for row in rows {
            if let Ok(event) = self.row_to_log_event(&row) {
                events.push(event);
            }
        }

        Ok(events)
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
        let mut query = "SELECT id, timestamp, source, severity, source_ip, raw_message, parsed_data, event_type, iocs FROM log_events WHERE 1=1".to_string();
        let mut conditions = Vec::new();

        if let Some(sev) = severity {
            query.push_str(" AND severity = ?");
            conditions.push(severity_to_string(sev));
        }

        if let Some(src) = source {
            query.push_str(" AND source = ?");
            conditions.push(src.to_string());
        }

        if let Some(from_time) = from {
            query.push_str(" AND timestamp >= ?");
            conditions.push(from_time.to_rfc3339());
        }

        if let Some(to_time) = to {
            query.push_str(" AND timestamp <= ?");
            conditions.push(to_time.to_rfc3339());
        }

        query.push_str(" ORDER BY timestamp DESC LIMIT ?");

        let mut sqlx_query = sqlx::query(&query);
        for condition in &conditions {
            sqlx_query = sqlx_query.bind(condition);
        }
        sqlx_query = sqlx_query.bind(limit as i64);

        let rows = sqlx_query.fetch_all(&self.pool).await
            .context("Failed to fetch filtered events")?;

        let mut events = Vec::new();
        for row in rows {
            if let Ok(event) = self.row_to_log_event(&row) {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Obtiene alertas activas (no reconocidas)
    pub async fn get_active_alerts(&self) -> Result<Vec<SecurityAlert>> {
        let rows = sqlx::query(r#"
            SELECT id, timestamp, severity, title, description,
                   related_events, mitigation_steps, acknowledged
            FROM security_alerts 
            WHERE acknowledged = FALSE
            ORDER BY timestamp DESC
        "#)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch active alerts")?;

        let mut alerts = Vec::new();
        for row in rows {
            if let Ok(alert) = self.row_to_security_alert(&row) {
                alerts.push(alert);
            }
        }

        Ok(alerts)
    }

    /// Obtiene todas las alertas
    pub async fn get_all_alerts(&self, limit: Option<usize>) -> Result<Vec<SecurityAlert>> {
        let query = if let Some(limit) = limit {
            format!(r#"
                SELECT id, timestamp, severity, title, description,
                       related_events, mitigation_steps, acknowledged
                FROM security_alerts 
                ORDER BY timestamp DESC
                LIMIT {}
            "#, limit)
        } else {
            r#"
                SELECT id, timestamp, severity, title, description,
                       related_events, mitigation_steps, acknowledged
                FROM security_alerts 
                ORDER BY timestamp DESC
            "#.to_string()
        };

        let rows = sqlx::query(&query)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch all alerts")?;

        let mut alerts = Vec::new();
        for row in rows {
            if let Ok(alert) = self.row_to_security_alert(&row) {
                alerts.push(alert);
            }
        }

        Ok(alerts)
    }

    /// Reconoce una alerta
    pub async fn acknowledge_alert(&self, alert_id: &Uuid) -> Result<bool> {
        let result = sqlx::query(r#"
            UPDATE security_alerts 
            SET acknowledged = TRUE, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND acknowledged = FALSE
        "#)
            .bind(alert_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to acknowledge alert")?;

        Ok(result.rows_affected() > 0)
    }

    /// Obtiene estadísticas del dashboard
    pub async fn get_dashboard_stats(&self) -> Result<serde_json::Value> {
        // Contar alertas críticas activas
        let critical_alerts: i64 = sqlx::query_scalar(r#"
            SELECT COUNT(*) FROM security_alerts 
            WHERE severity = 'Critical' AND acknowledged = FALSE
        "#)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        // Contar eventos en la última hora
        let hour_ago = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let events_last_hour: i64 = sqlx::query_scalar(r#"
            SELECT COUNT(*) FROM log_events 
            WHERE timestamp > ?
        "#)
            .bind(hour_ago)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        // Total de eventos y alertas
        let total_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_events")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        let total_alerts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_alerts")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        let acknowledged_alerts: i64 = sqlx::query_scalar(r#"
            SELECT COUNT(*) FROM security_alerts WHERE acknowledged = TRUE
        "#)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        // Contar fuentes únicas activas en las últimas 24 horas
        let day_ago = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let active_sources: i64 = sqlx::query_scalar(r#"
            SELECT COUNT(DISTINCT source) FROM log_events 
            WHERE timestamp > ?
        "#)
            .bind(&day_ago)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        // Calcular score de amenaza basado en alertas recientes
        let recent_alerts: i64 = sqlx::query_scalar(r#"
            SELECT COUNT(*) FROM security_alerts 
            WHERE timestamp > ? AND acknowledged = FALSE
        "#)
            .bind(&day_ago)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

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
            "active_sources": active_sources,
            "total_events": total_events,
            "total_alerts": total_alerts,
            "acknowledged_alerts": acknowledged_alerts
        }))
    }

    /// Obtiene estadísticas de eventos por severidad
    pub async fn get_events_by_severity(&self) -> Result<serde_json::Value> {
        let rows = sqlx::query(r#"
            SELECT severity, COUNT(*) as count
            FROM log_events 
            GROUP BY severity
        "#)
            .fetch_all(&self.pool)
            .await
            .context("Failed to get events by severity")?;

        let mut stats = serde_json::Map::new();
        for row in rows {
            let severity: String = row.get("severity");
            let count: i64 = row.get("count");
            stats.insert(severity, serde_json::Value::Number(count.into()));
        }

        Ok(serde_json::Value::Object(stats))
    }

    /// Obtiene eventos por fuente
    pub async fn get_events_by_source(&self) -> Result<serde_json::Value> {
        let rows = sqlx::query(r#"
            SELECT source, COUNT(*) as count
            FROM log_events 
            GROUP BY source
            ORDER BY count DESC
            LIMIT 10
        "#)
            .fetch_all(&self.pool)
            .await
            .context("Failed to get events by source")?;

        let mut stats = serde_json::Map::new();
        for row in rows {
            let source: String = row.get("source");
            let count: i64 = row.get("count");
            stats.insert(source, serde_json::Value::Number(count.into()));
        }

        Ok(serde_json::Value::Object(stats))
    }

    /// Limpia eventos antiguos
    pub async fn cleanup_old_events(&self, days: i64) -> Result<u64> {
        let cutoff_date = (Utc::now() - chrono::Duration::days(days)).to_rfc3339();

        let result = sqlx::query(r#"
            DELETE FROM log_events 
            WHERE timestamp < ?
        "#)
            .bind(cutoff_date)
            .execute(&self.pool)
            .await
            .context("Failed to cleanup old events")?;

        Ok(result.rows_affected())
    }

    /// Limpia alertas reconocidas antiguas
    pub async fn cleanup_old_alerts(&self, days: i64) -> Result<u64> {
        let cutoff_date = (Utc::now() - chrono::Duration::days(days)).to_rfc3339();

        let result = sqlx::query(r#"
            DELETE FROM security_alerts 
            WHERE acknowledged = TRUE AND updated_at < ?
        "#)
            .bind(cutoff_date)
            .execute(&self.pool)
            .await
            .context("Failed to cleanup old alerts")?;

        Ok(result.rows_affected())
    }

    /// Obtiene información sobre la base de datos
    pub async fn get_database_info(&self) -> Result<serde_json::Value> {
        let events_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_events")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        let alerts_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_alerts")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

        // Obtener tamaño de la base de datos (aproximado)
        let size_info = sqlx::query("PRAGMA page_count; PRAGMA page_size;")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

        Ok(serde_json::json!({
            "events_count": events_count,
            "alerts_count": alerts_count,
            "database_pages": size_info.get(0).map(|r| r.get::<i64, _>(0)).unwrap_or(0),
            "page_size": size_info.get(1).map(|r| r.get::<i64, _>(0)).unwrap_or(0),
        }))
    }

    /// Convierte una fila de base de datos a LogEvent
    fn row_to_log_event(&self, row: &sqlx::sqlite::SqliteRow) -> Result<LogEvent> {
        let id_str: String = row.get("id");
        let timestamp_str: String = row.get("timestamp");
        let severity_str: String = row.get("severity");
        let event_type_str: String = row.get("event_type");
        let parsed_data_str: String = row.get("parsed_data");
        let iocs_str: String = row.get("iocs");

        Ok(LogEvent {
            id: Uuid::parse_str(&id_str)?,
            timestamp: DateTime::parse_from_rfc3339(&timestamp_str)?.with_timezone(&Utc),
            source: row.get("source"),
            severity: string_to_severity(&severity_str)?,
            source_ip: row.get("source_ip"),
            raw_message: row.get("raw_message"),
            parsed_data: serde_json::from_str(&parsed_data_str)?,
            event_type: string_to_event_type(&event_type_str)?,
            iocs: serde_json::from_str(&iocs_str)?,
        })
    }

    /// Convierte una fila de base de datos a SecurityAlert
    fn row_to_security_alert(&self, row: &sqlx::sqlite::SqliteRow) -> Result<SecurityAlert> {
        let id_str: String = row.get("id");
        let timestamp_str: String = row.get("timestamp");
        let severity_str: String = row.get("severity");
        let related_events_str: String = row.get("related_events");
        let mitigation_steps_str: String = row.get("mitigation_steps");

        Ok(SecurityAlert {
            id: Uuid::parse_str(&id_str)?,
            timestamp: DateTime::parse_from_rfc3339(&timestamp_str)?.with_timezone(&Utc),
            severity: string_to_severity(&severity_str)?,
            title: row.get("title"),
            description: row.get("description"),
            related_events: serde_json::from_str(&related_events_str)?,
            mitigation_steps: serde_json::from_str(&mitigation_steps_str)?,
            acknowledged: row.get("acknowledged"),
        })
    }

    /// Obtiene un evento por su ID
    pub async fn get_event_by_id(&self, event_id: &Uuid) -> Result<LogEvent> {
        let row = sqlx::query(r#"
            SELECT id, timestamp, source, severity, source_ip, raw_message, 
                   parsed_data, event_type, iocs, created_at
            FROM log_events
            WHERE id = ?
        "#)
            .bind(event_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query event by ID")?;

        match row {
            Some(row) => self.row_to_log_event(&row),
            None => Err(anyhow::anyhow!("Event with ID {} not found", event_id)),
        }
    }

    /// Obtiene eventos relacionados con un evento específico
    pub async fn get_related_events(&self, event_id: &Uuid, limit: usize) -> Result<Vec<LogEvent>> {
        // Primero obtener el evento principal
        let target_event = self.get_event_by_id(event_id).await?;
        
        // Buscar eventos relacionados en una ventana de tiempo de 1 hora
        let start_time = target_event.timestamp - chrono::Duration::hours(1);
        let end_time = target_event.timestamp + chrono::Duration::hours(1);
        
        let rows = sqlx::query(r#"
            SELECT id, timestamp, source, severity, source_ip, raw_message, 
                   parsed_data, event_type, iocs, created_at
            FROM log_events
            WHERE id != ? 
              AND timestamp BETWEEN ? AND ?
              AND (
                  source_ip = ? OR 
                  source = ? OR 
                  event_type = ?
              )
            ORDER BY timestamp DESC
            LIMIT ?
        "#)
            .bind(event_id.to_string())
            .bind(start_time.to_rfc3339())
            .bind(end_time.to_rfc3339())
            .bind(&target_event.source_ip)
            .bind(&target_event.source)
            .bind(event_type_to_string(&target_event.event_type))
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .context("Failed to query related events")?;

        let mut events = Vec::new();
        for row in rows {
            if let Ok(event) = self.row_to_log_event(&row) {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Cierra el pool de conexiones
    pub async fn close(&self) {
        self.pool.close().await;
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

/// Convierte String a Severity
fn string_to_severity(s: &str) -> Result<Severity> {
    match s {
        "Low" => Ok(Severity::Low),
        "Info" => Ok(Severity::Info),
        "Medium" => Ok(Severity::Medium),
        "Warning" => Ok(Severity::Warning),
        "High" => Ok(Severity::High),
        "Critical" => Ok(Severity::Critical),
        _ => Err(anyhow::anyhow!("Invalid severity: {}", s)),
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

/// Convierte String a EventType
fn string_to_event_type(s: &str) -> Result<EventType> {
    match s {
        "Normal" => Ok(EventType::Normal),
        "SqlInjection" => Ok(EventType::SqlInjection),
        "XssAttempt" => Ok(EventType::XssAttempt),
        "BruteForce" => Ok(EventType::BruteForce),
        "Anomaly" => Ok(EventType::Anomaly),
        "SuspiciousActivity" => Ok(EventType::SuspiciousActivity),
        _ => Err(anyhow::anyhow!("Invalid event type: {}", s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn create_test_storage() -> SqliteStorage {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());
        SqliteStorage::new(&database_url).await.unwrap()
    }

    #[tokio::test]
    async fn test_store_and_retrieve_event() {
        let storage = create_test_storage().await;

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

        storage.store_event(&event).await.unwrap();
        let events = storage.get_recent_events(10).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
        assert_eq!(events[0].source, event.source);
    }

    #[tokio::test]
    async fn test_store_and_retrieve_alert() {
        let storage = create_test_storage().await;

        let alert = SecurityAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: Severity::Critical,
            title: "Test Alert".to_string(),
            description: "Test Description".to_string(),
            related_events: vec![Uuid::new_v4()],
            mitigation_steps: vec!["Step 1".to_string()],
            acknowledged: false,
        };

        storage.store_alert(&alert).await.unwrap();
        let alerts = storage.get_active_alerts().await.unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].id, alert.id);
        assert_eq!(alerts[0].title, alert.title);
    }

    #[tokio::test]
    async fn test_acknowledge_alert() {
        let storage = create_test_storage().await;

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

        storage.store_alert(&alert).await.unwrap();

        let acknowledged = storage.acknowledge_alert(&alert.id).await.unwrap();
        assert!(acknowledged);

        let active_alerts = storage.get_active_alerts().await.unwrap();
        assert_eq!(active_alerts.len(), 0);
    }

    #[tokio::test]
    async fn test_dashboard_stats() {
        let storage = create_test_storage().await;

        let stats = storage.get_dashboard_stats().await.unwrap();

        assert!(stats.get("events_per_second").is_some());
        assert!(stats.get("critical_alerts").is_some());
        assert!(stats.get("threat_score").is_some());
        assert!(stats.get("active_sources").is_some());
    }
}