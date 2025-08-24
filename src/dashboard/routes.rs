use crate::{storage::StorageManager, detector::DetectorEngine, Severity, LogEvent, SecurityAlert};
use anyhow::Result;
use std::sync::Arc;
use warp::{Filter, reply::Reply};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone)]
pub struct DashboardRoutes {
    storage: Arc<StorageManager>,
    detector: Arc<DetectorEngine>,
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub limit: Option<usize>,
    pub severity: Option<Severity>,
    pub source: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub search: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<usize>,
    pub status: Option<String>,
    pub severity: Option<Severity>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
    pub message: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_events: u64,
    pub events_per_second: f64,
    pub critical_alerts: u64,
    pub warning_alerts: u64,
    pub info_alerts: u64,
    pub threat_score: f64,
    pub active_sources: u64,
    pub uptime_seconds: u64,
    pub detection_rate: f64,
    pub false_positive_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct EventDetails {
    pub event: LogEvent,
    pub related_events: Vec<LogEvent>,
    pub detection_results: Vec<DetectionInfo>,
    pub timeline: Vec<TimelineEntry>,
}

#[derive(Debug, Serialize)]
pub struct DetectionInfo {
    pub detector_name: String,
    pub confidence: f64,
    pub risk_score: f64,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub severity: Severity,
}

impl DashboardRoutes {
    pub fn new(storage: Arc<StorageManager>, detector: Arc<DetectorEngine>) -> Self {
        Self { storage, detector }
    }

    /// Ruta para estadísticas del dashboard
    pub fn stats_route(&self) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let storage = self.storage.clone();
        
        warp::path!("api" / "stats")
            .and(warp::get())
            .and_then(move || {
                let storage = storage.clone();
                async move {
                    match Self::get_dashboard_stats(storage).await {
                        Ok(stats) => Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                            success: true,
                            data: stats,
                            message: None,
                            timestamp: Utc::now(),
                        })),
                        Err(e) => {
                            tracing::error!("Error obteniendo estadísticas: {}", e);
                            Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                                success: false,
                                data: serde_json::json!({}),
                                message: Some("Error interno del servidor".to_string()),
                                timestamp: Utc::now(),
                            }))
                        }
                    }
                }
            })
    }

    /// Ruta para obtener eventos con filtros avanzados
    pub fn events_route(&self) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let storage = self.storage.clone();
        
        warp::path!("api" / "events")
            .and(warp::get())
            .and(warp::query::<EventsQuery>())
            .and_then(move |query: EventsQuery| {
                let storage = storage.clone();
                async move {
                    match Self::get_filtered_events(storage, query).await {
                        Ok(events) => Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                            success: true,
                            data: events,
                            message: None,
                            timestamp: Utc::now(),
                        })),
                        Err(e) => {
                            tracing::error!("Error obteniendo eventos: {}", e);
                            Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                                success: false,
                                data: Vec::<LogEvent>::new(),
                                message: Some("Error obteniendo eventos".to_string()),
                                timestamp: Utc::now(),
                            }))
                        }
                    }
                }
            })
    }

    /// Ruta para obtener detalles de un evento específico
    pub fn event_details_route(&self) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let storage = self.storage.clone();
        let detector = self.detector.clone();
        
        warp::path!("api" / "events" / String)
            .and(warp::get())
            .and_then(move |event_id: String| {
                let storage = storage.clone();
                let detector = detector.clone();
                async move {
                    match Self::get_event_details(storage, detector, event_id).await {
                        Ok(details) => Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                            success: true,
                            data: details,
                            message: None,
                            timestamp: Utc::now(),
                        })),
                        Err(e) => {
                            tracing::error!("Error obteniendo detalles del evento: {}", e);
                            Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                                success: false,
                                data: serde_json::json!({}),
                                message: Some("Evento no encontrado".to_string()),
                                timestamp: Utc::now(),
                            }))
                        }
                    }
                }
            })
    }

    /// Ruta para obtener alertas con filtros
    pub fn alerts_route(&self) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let storage = self.storage.clone();
        
        warp::path!("api" / "alerts")
            .and(warp::get())
            .and(warp::query::<AlertsQuery>())
            .and_then(move |query: AlertsQuery| {
                let storage = storage.clone();
                async move {
                    match Self::get_filtered_alerts(storage, query).await {
                        Ok(alerts) => Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                            success: true,
                            data: alerts,
                            message: None,
                            timestamp: Utc::now(),
                        })),
                        Err(e) => {
                            tracing::error!("Error obteniendo alertas: {}", e);
                            Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                                success: false,
                                data: Vec::<SecurityAlert>::new(),
                                message: Some("Error obteniendo alertas".to_string()),
                                timestamp: Utc::now(),
                            }))
                        }
                    }
                }
            })
    }

    /// Ruta para páginas HTML del dashboard
    pub fn dashboard_page() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path::end()
            .and(warp::get())
            .map(|| {
                // Por ahora usamos el HTML inline del server.rs
                warp::reply::with_header(
                    warp::reply::html("Página del dashboard - Ver /api/stats para datos"),
                    "refresh",
                    "5; url=/api/stats"
                )
            })
    }

    /// Ruta para página de eventos
    pub fn events_page() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("events")
            .and(warp::get())
            .map(|| {
                warp::reply::html("Página de eventos - Ver /api/events para datos")
            })
    }

    /// Ruta para página de alertas
    pub fn alerts_page() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path!("alerts")
            .and(warp::get())
            .map(|| {
                warp::reply::html("Página de alertas - Ver /api/alerts para datos")
            })
    }

    /// Obtiene estadísticas del dashboard
    async fn get_dashboard_stats(storage: Arc<StorageManager>) -> Result<DashboardStats> {
        let stats = storage.get_dashboard_stats().await?;
        
        // Extraer valores del JSON
        let total_events = stats.get("total_events").and_then(|v| v.as_u64()).unwrap_or(0);
        let events_per_second = stats.get("events_per_second").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let critical_alerts = stats.get("critical_alerts").and_then(|v| v.as_u64()).unwrap_or(0);
        let warning_alerts = stats.get("warning_alerts").and_then(|v| v.as_u64()).unwrap_or(0);
        let info_alerts = stats.get("info_alerts").and_then(|v| v.as_u64()).unwrap_or(0);
        let threat_score = stats.get("threat_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let active_sources = stats.get("active_sources").and_then(|v| v.as_u64()).unwrap_or(0);
        let uptime_seconds = stats.get("uptime_seconds").and_then(|v| v.as_u64()).unwrap_or(0);
        let detection_rate = stats.get("detection_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let false_positive_rate = stats.get("false_positive_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
        
        Ok(DashboardStats {
            total_events,
            events_per_second,
            critical_alerts,
            warning_alerts,
            info_alerts,
            threat_score,
            active_sources,
            uptime_seconds,
            detection_rate,
            false_positive_rate,
        })
    }

    /// Obtiene eventos filtrados
    async fn get_filtered_events(
        storage: Arc<StorageManager>,
        query: EventsQuery,
    ) -> Result<Vec<LogEvent>> {
        storage.get_events_filtered(
            query.limit.unwrap_or(50),
            query.severity,
            query.source,
            query.from,
            query.to,
        ).await
    }

    /// Obtiene detalles de un evento específico
    async fn get_event_details(
        storage: Arc<StorageManager>,
        detector: Arc<DetectorEngine>,
        event_id: String,
    ) -> Result<EventDetails> {
        let uuid = Uuid::parse_str(&event_id)?;
        let event = storage.get_event_by_id(uuid).await?;
        let related_events = storage.get_related_events(uuid, 10).await?;
        
        // Simular detección para el evento (en producción vendría del detector)
        let detection_results = vec![
            DetectionInfo {
                detector_name: "XSS Detector".to_string(),
                confidence: 0.85,
                risk_score: 7.5,
                details: serde_json::json!({
                    "patterns_matched": ["script_tag", "event_handler"],
                    "payload_analysis": "Possible XSS injection detected"
                }),
            }
        ];
        
        let timeline = vec![
            TimelineEntry {
                timestamp: event.timestamp,
                event_type: "HTTP Request".to_string(),
                description: match &event.source_ip {
                    Some(ip) => format!("Request from {}", ip),
                    None => "Request from unknown source".to_string(),
                },
                severity: Severity::Info,
            }
        ];
        
        Ok(EventDetails {
            event,
            related_events,
            detection_results,
            timeline,
        })
    }

    /// Obtiene alertas filtradas
    async fn get_filtered_alerts(
        storage: Arc<StorageManager>,
        query: AlertsQuery,
    ) -> Result<Vec<SecurityAlert>> {
        // Implementar filtros reales basados en query
        let mut alerts = storage.get_active_alerts().await?;

        // Filtrar por severidad si se especifica
        if let Some(severity) = &query.severity {
            alerts.retain(|alert| alert.severity == *severity);
        }

        // Filtrar por fechas si se especifican
        if let Some(from) = query.from {
            alerts.retain(|alert| alert.timestamp >= from);
        }
        if let Some(to) = query.to {
            alerts.retain(|alert| alert.timestamp <= to);
        }

        // Limitar resultados
        let limit = query.limit.unwrap_or(50);
        alerts.truncate(limit);

        Ok(alerts)
    }
}
