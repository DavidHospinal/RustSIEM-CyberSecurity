use crate::{storage::StorageManager, detector::DetectorEngine, Severity, LogEvent, SecurityAlert};
use anyhow::Result;
use std::sync::Arc;
use warp::Filter;
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

#[derive(Debug, Serialize)]
pub struct EducationalEventDetail {
    pub event: LogEvent,
    pub educational_context: EducationalContext,
    pub threat_intelligence: ThreatIntelligence,
    pub technical_analysis: TechnicalAnalysis,
    pub mitigation_guidance: MitigationGuidance,
    pub real_world_examples: Vec<RealWorldExample>,
    pub related_events: Vec<LogEvent>,
}

#[derive(Debug, Serialize)]
pub struct EducationalContext {
    pub attack_name: String,
    pub attack_description: String,
    pub learning_objectives: Vec<String>,
    pub key_concepts: Vec<String>,
    pub difficulty_level: String,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ThreatIntelligence {
    pub origin_country: String,
    pub threat_level: String,
    pub known_threat_actors: Vec<String>,
    pub common_attack_patterns: Vec<String>,
    pub geographic_context: GeographicThreatContext,
}

#[derive(Debug, Serialize)]
pub struct GeographicThreatContext {
    pub country: String,
    pub country_code: String,
    pub risk_assessment: String,
    pub typical_attack_types: Vec<String>,
    pub known_apt_groups: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TechnicalAnalysis {
    pub attack_vector: String,
    pub payload_analysis: PayloadAnalysis,
    pub vulnerability_details: Option<VulnerabilityDetails>,
    pub iocs: Vec<IoC>,
    pub detection_rules: Vec<DetectionRuleInfo>,
}

#[derive(Debug, Serialize)]
pub struct PayloadAnalysis {
    pub malicious_indicators: Vec<String>,
    pub payload_explanation: String,
    pub encoding_detected: bool,
    pub obfuscation_techniques: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VulnerabilityDetails {
    pub cve_id: Option<String>,
    pub cvss_score: Option<f64>,
    pub description: String,
    pub affected_components: Vec<String>,
    pub exploit_complexity: String,
}

#[derive(Debug, Serialize)]
pub struct IoC {
    pub ioc_type: String,
    pub value: String,
    pub confidence: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct DetectionRuleInfo {
    pub rule_name: String,
    pub confidence: f64,
    pub description: String,
    pub false_positive_rate: String,
}

#[derive(Debug, Serialize)]
pub struct MitigationGuidance {
    pub immediate_actions: Vec<MitigationStep>,
    pub preventive_measures: Vec<MitigationStep>,
    pub long_term_strategies: Vec<MitigationStep>,
}

#[derive(Debug, Serialize)]
pub struct MitigationStep {
    pub action: String,
    pub priority: String,
    pub timeline: String,
    pub tools_required: Vec<String>,
    pub expected_outcome: String,
}

#[derive(Debug, Serialize)]
pub struct RealWorldExample {
    pub incident_name: String,
    pub year: u32,
    pub organization: String,
    pub impact: String,
    pub lessons_learned: String,
    pub prevention_method: String,
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

    /// Ruta para obtener consultas de threat hunting disponibles
    pub fn threat_hunt_queries_route(&self) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let detector = self.detector.clone();
        
        warp::path!("api" / "threat-hunt" / "queries")
            .and(warp::get())
            .and_then(move || {
                let detector = detector.clone();
                async move {
                    let queries = detector.get_available_hunt_queries();
                    Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                        success: true,
                        data: queries,
                        message: None,
                        timestamp: Utc::now(),
                    }))
                }
            })
    }

    /// Ruta para ejecutar una consulta de threat hunting
    pub fn execute_threat_hunt_route(&self) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let detector = self.detector.clone();
        
        warp::path!("api" / "threat-hunt" / "execute" / String)
            .and(warp::post())
            .and_then(move |query_id: String| {
                let detector = detector.clone();
                async move {
                    match detector.execute_threat_hunt(&query_id).await {
                        Ok(result) => Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                            success: true,
                            data: result,
                            message: None,
                            timestamp: Utc::now(),
                        })),
                        Err(e) => {
                            tracing::error!("Error ejecutando threat hunt: {}", e);
                            Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                                success: false,
                                data: serde_json::json!({}),
                                message: Some(format!("Error ejecutando consulta: {}", e)),
                                timestamp: Utc::now(),
                            }))
                        }
                    }
                }
            })
    }

    pub fn event_educational_details_route(&self) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let storage = self.storage.clone();

        warp::path!("api" / "events" / String / "educational")
            .and(warp::get())
            .and_then(move |event_id: String| {
                let storage = storage.clone();
                async move {
                    match Self::get_educational_event_details(storage, event_id).await {
                        Ok(details) => Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                            success: true,
                            data: details,
                            message: None,
                            timestamp: Utc::now(),
                        })),
                        Err(e) => {
                            tracing::error!("Error obteniendo detalles educativos del evento: {}", e);
                            Ok::<warp::reply::Json, warp::Rejection>(warp::reply::json(&ApiResponse {
                                success: false,
                                data: serde_json::json!({}),
                                message: Some("Evento no encontrado o error interno".to_string()),
                                timestamp: Utc::now(),
                            }))
                        }
                    }
                }
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
        _detector: Arc<DetectorEngine>,
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

    /// Obtiene detalles educativos de un evento específico
    async fn get_educational_event_details(
        storage: Arc<StorageManager>,
        event_id: String,
    ) -> Result<EducationalEventDetail> {
        let uuid = Uuid::parse_str(&event_id)?;
        let event = storage.get_event_by_id(uuid).await?;

        let related_events = storage.get_related_events(uuid, 5).await.unwrap_or_default();

        Ok(EducationalEventDetail {
            educational_context: Self::generate_educational_context(&event.event_type),
            threat_intelligence: Self::generate_threat_intelligence(&event),
            technical_analysis: Self::generate_technical_analysis(&event),
            mitigation_guidance: Self::generate_mitigation_guidance(&event.event_type),
            real_world_examples: Self::generate_real_world_examples(&event.event_type),
            event,
            related_events,
        })
    }

    /// Genera contexto educativo basado en el tipo de evento
    fn generate_educational_context(event_type: &crate::EventType) -> EducationalContext {
        use crate::EventType;

        match event_type {
            EventType::SqlInjection => EducationalContext {
                attack_name: "Inyección SQL (SQL Injection)".to_string(),
                attack_description: "La inyección SQL es una técnica de ataque donde código SQL malicioso es insertado en campos de entrada de aplicaciones web para manipular bases de datos. Es una de las vulnerabilidades más peligrosas según OWASP Top 10.".to_string(),
                learning_objectives: vec![
                    "Comprender cómo funcionan las inyecciones SQL y sus diferentes tipos".to_string(),
                    "Identificar patrones comunes de inyección en logs de seguridad".to_string(),
                    "Implementar contramedidas efectivas como prepared statements".to_string(),
                    "Analizar el impacto potencial en confidencialidad e integridad de datos".to_string(),
                ],
                key_concepts: vec![
                    "Prepared Statements y Parameterized Queries".to_string(),
                    "Input Validation y Output Encoding".to_string(),
                    "Principio de Menor Privilegio en Base de Datos".to_string(),
                    "UNION-based, Boolean-based y Time-based SQL Injection".to_string(),
                    "Web Application Firewall (WAF) Rules".to_string(),
                ],
                difficulty_level: "Intermedio-Avanzado".to_string(),
                mitre_tactics: vec!["Initial Access".to_string(), "Exfiltration".to_string()],
                mitre_techniques: vec!["T1190 - Exploit Public-Facing Application".to_string()],
            },
            EventType::XssAttempt => EducationalContext {
                attack_name: "Cross-Site Scripting (XSS)".to_string(),
                attack_description: "XSS permite a atacantes inyectar scripts maliciosos en páginas web. Estos scripts se ejecutan en el navegador de usuarios legítimos, permitiendo robo de cookies, secuestro de sesiones y redirección a sitios maliciosos.".to_string(),
                learning_objectives: vec![
                    "Diferenciar entre XSS Reflejado, Almacenado y basado en DOM".to_string(),
                    "Reconocer payloads XSS comunes en parámetros HTTP".to_string(),
                    "Implementar Content Security Policy (CSP) efectivo".to_string(),
                    "Configurar sanitización de entrada y codificación de salida".to_string(),
                ],
                key_concepts: vec![
                    "Output Encoding y HTML Entity Encoding".to_string(),
                    "Content Security Policy (CSP) Headers".to_string(),
                    "Same-Origin Policy y CORS".to_string(),
                    "DOM Manipulation Attacks".to_string(),
                    "Session Hijacking via XSS".to_string(),
                ],
                difficulty_level: "Intermedio".to_string(),
                mitre_tactics: vec!["Execution".to_string(), "Credential Access".to_string()],
                mitre_techniques: vec!["T1059 - Command and Scripting Interpreter".to_string()],
            },
            EventType::BruteForce => EducationalContext {
                attack_name: "Ataque de Fuerza Bruta".to_string(),
                attack_description: "Los ataques de fuerza bruta usan métodos automatizados para probar sistemáticamente combinaciones de credenciales hasta encontrar las correctas. Son especialmente efectivos contra contraseñas débiles y sistemas sin protecciones adecuadas.".to_string(),
                learning_objectives: vec![
                    "Identificar patrones de ataques de fuerza bruta en logs de autenticación".to_string(),
                    "Configurar rate limiting y políticas de bloqueo de cuentas".to_string(),
                    "Implementar sistemas de detección de anomalías en tiempo real".to_string(),
                    "Establecer políticas de contraseñas seguras y MFA".to_string(),
                ],
                key_concepts: vec![
                    "Rate Limiting y Throttling".to_string(),
                    "Account Lockout Policies y Temporary Bans".to_string(),
                    "Multi-Factor Authentication (MFA)".to_string(),
                    "Password Complexity Requirements".to_string(),
                    "Dictionary vs Brute Force vs Credential Stuffing".to_string(),
                ],
                difficulty_level: "Básico-Intermedio".to_string(),
                mitre_tactics: vec!["Credential Access".to_string(), "Initial Access".to_string()],
                mitre_techniques: vec!["T1110 - Brute Force".to_string(), "T1078 - Valid Accounts".to_string()],
            },
            EventType::Anomaly => EducationalContext {
                attack_name: "Detección de Anomalías con ML".to_string(),
                attack_description: "La detección de anomalías utiliza algoritmos de machine learning para identificar comportamientos inusuales que podrían indicar actividad maliciosa avanzada o ataques desconocidos (zero-day).".to_string(),
                learning_objectives: vec![
                    "Comprender algoritmos de detección de anomalías en ciberseguridad".to_string(),
                    "Interpretar scores de anomalía y establecer umbrales apropiados".to_string(),
                    "Reducir falsos positivos mediante tuning de modelos ML".to_string(),
                    "Correlacionar anomalías con otros indicadores de compromiso".to_string(),
                ],
                key_concepts: vec![
                    "Baseline Establishment y Normal Behavior Profiling".to_string(),
                    "Statistical Outlier Detection".to_string(),
                    "Unsupervised Learning Models".to_string(),
                    "Behavioral Analytics (UEBA)".to_string(),
                    "False Positive vs True Positive Classification".to_string(),
                ],
                difficulty_level: "Avanzado".to_string(),
                mitre_tactics: vec!["Defense Evasion".to_string(), "Discovery".to_string()],
                mitre_techniques: vec!["T1055 - Process Injection".to_string(), "T1083 - File and Directory Discovery".to_string()],
            },
            _ => EducationalContext {
                attack_name: "Evento de Seguridad General".to_string(),
                attack_description: "Este evento representa actividad sospechosa que requiere investigación adicional para determinar su naturaleza y potencial malicioso.".to_string(),
                learning_objectives: vec![
                    "Desarrollar habilidades de investigación de incidentes".to_string(),
                    "Practicar correlación de eventos aparentemente inconexos".to_string(),
                    "Mejorar capacidades de análisis de logs y evidencia digital".to_string(),
                ],
                key_concepts: vec![
                    "Threat Hunting Methodology".to_string(),
                    "Log Analysis Techniques".to_string(),
                    "Incident Investigation Process".to_string(),
                    "Digital Evidence Collection".to_string(),
                ],
                difficulty_level: "Variable".to_string(),
                mitre_tactics: vec!["Various".to_string()],
                mitre_techniques: vec!["Multiple techniques possible".to_string()],
            },
        }
    }

    /// Genera información de inteligencia de amenazas
    fn generate_threat_intelligence(event: &LogEvent) -> ThreatIntelligence {
        let geographic_context = Self::determine_geographic_context(&event.source_ip);

        ThreatIntelligence {
            origin_country: geographic_context.country.clone(),
            threat_level: geographic_context.risk_assessment.clone(),
            known_threat_actors: geographic_context.known_apt_groups.clone(),
            common_attack_patterns: geographic_context.typical_attack_types.clone(),
            geographic_context,
        }
    }

    /// Determina contexto geográfico de la amenaza
    fn determine_geographic_context(source_ip: &Option<String>) -> GeographicThreatContext {
        if let Some(ip) = source_ip {
            if ip.starts_with("1.") || ip.starts_with("27.") || ip.starts_with("223.") {
                return GeographicThreatContext {
                    country: "China".to_string(),
                    country_code: "CN".to_string(),
                    risk_assessment: "Alto - Conocido por actividad APT estatal y ciberespionaje".to_string(),
                    typical_attack_types: vec![
                        "Advanced Persistent Threats (APT)".to_string(),
                        "Espionaje Industrial".to_string(),
                        "Ataques de Fuerza Bruta Masivos".to_string(),
                        "Robo de Propiedad Intelectual".to_string(),
                    ],
                    known_apt_groups: vec![
                        "APT1 (Comment Crew)".to_string(),
                        "APT40 (Leviathan)".to_string(),
                        "Winnti Group".to_string(),
                        "APT41".to_string(),
                    ],
                };
            } else if ip.starts_with("46.") || ip.starts_with("95.") {
                return GeographicThreatContext {
                    country: "Russia".to_string(),
                    country_code: "RU".to_string(),
                    risk_assessment: "Alto - Asociado con cibercriminalidad organizada y operaciones estatales".to_string(),
                    typical_attack_types: vec![
                        "Ransomware-as-a-Service".to_string(),
                        "Banking Trojans".to_string(),
                        "Operaciones de Influencia".to_string(),
                        "Ataques a Infraestructura Crítica".to_string(),
                    ],
                    known_apt_groups: vec![
                        "APT28 (Fancy Bear)".to_string(),
                        "APT29 (Cozy Bear)".to_string(),
                        "Carbanak Group".to_string(),
                        "Evil Corp".to_string(),
                    ],
                };
            } else if ip.starts_with("175.45.176.") {
                return GeographicThreatContext {
                    country: "North Korea".to_string(),
                    country_code: "KP".to_string(),
                    risk_assessment: "Muy Alto - Operaciones dirigidas por el estado para financiamiento y espionaje".to_string(),
                    typical_attack_types: vec![
                        "Cryptocurrency Theft".to_string(),
                        "SWIFT Banking Attacks".to_string(),
                        "Ransomware for Financial Gain".to_string(),
                        "Media and Entertainment Targeting".to_string(),
                    ],
                    known_apt_groups: vec![
                        "Lazarus Group".to_string(),
                        "APT38".to_string(),
                        "Andariel".to_string(),
                        "BlueNoroff".to_string(),
                    ],
                };
            }
        }

        GeographicThreatContext {
            country: "Unknown/Various".to_string(),
            country_code: "XX".to_string(),
            risk_assessment: "Medio - Requiere análisis adicional para determinar origen".to_string(),
            typical_attack_types: vec![
                "Script Kiddies".to_string(),
                "Automated Scanning".to_string(),
                "Opportunistic Attacks".to_string(),
            ],
            known_apt_groups: vec!["Unknown".to_string()],
        }
    }

    /// Genera análisis técnico del evento
    fn generate_technical_analysis(event: &LogEvent) -> TechnicalAnalysis {
        let payload_analysis = Self::analyze_event_payload(event);
        let vulnerability_details = Self::get_vulnerability_details(&event.event_type);
        let iocs = Self::extract_iocs(event);
        let detection_rules = Self::get_triggered_detection_rules(&event.event_type);

        TechnicalAnalysis {
            attack_vector: Self::determine_attack_vector(&event.event_type),
            payload_analysis,
            vulnerability_details,
            iocs,
            detection_rules,
        }
    }

    fn determine_attack_vector(event_type: &crate::EventType) -> String {
        use crate::EventType;

        match event_type {
            EventType::SqlInjection => "Web Application - Input Field SQL Injection via HTTP Parameters".to_string(),
            EventType::XssAttempt => "Web Application - Client-Side Script Injection via User Input".to_string(),
            EventType::BruteForce => "Network Service - Authentication Endpoint Credential Guessing".to_string(),
            EventType::Anomaly => "Multiple Vectors - Behavioral Anomaly Detection Trigger".to_string(),
            _ => "Unknown - Multiple Attack Vectors Possible".to_string(),
        }
    }

    fn analyze_event_payload(event: &LogEvent) -> PayloadAnalysis {
        use crate::EventType;

        let malicious_indicators = match event.event_type {
            EventType::SqlInjection => vec![
                "SQL UNION keyword detected in parameters".to_string(),
                "SQL comment syntax (--) found".to_string(),
                "Single quote manipulation attempt".to_string(),
                "Database function calls detected".to_string(),
            ],
            EventType::XssAttempt => vec![
                "JavaScript <script> tags detected".to_string(),
                "HTML event handlers (onclick, onerror) found".to_string(),
                "URL encoding of malicious scripts".to_string(),
                "DOM manipulation attempts".to_string(),
            ],
            EventType::BruteForce => vec![
                "Repeated authentication failures".to_string(),
                "Common password patterns detected".to_string(),
                "High-frequency requests from single IP".to_string(),
                "Dictionary attack indicators".to_string(),
            ],
            EventType::Anomaly => vec![
                "Statistical deviation from baseline behavior".to_string(),
                "Unusual access patterns detected".to_string(),
                "Abnormal data volume transfer".to_string(),
                "Time-based behavioral anomalies".to_string(),
            ],
            _ => vec!["General suspicious activity indicators".to_string()],
        };

        PayloadAnalysis {
            malicious_indicators,
            payload_explanation: Self::get_payload_explanation(&event.event_type),
            encoding_detected: event.raw_message.contains("encode") || event.raw_message.contains("%"),
            obfuscation_techniques: Self::detect_obfuscation_techniques(&event.raw_message),
        }
    }

    fn get_payload_explanation(event_type: &crate::EventType) -> String {
        use crate::EventType;

        match event_type {
            EventType::SqlInjection => "El payload intenta manipular la consulta SQL original para extraer datos no autorizados o ejecutar comandos administrativos en la base de datos.".to_string(),
            EventType::XssAttempt => "El payload contiene código JavaScript diseñado para ejecutarse en el navegador de la víctima, potencialmente robando cookies o redirigiendo a sitios maliciosos.".to_string(),
            EventType::BruteForce => "Múltiples intentos automatizados de adivinar credenciales válidas usando listas de contraseñas comunes o combinaciones sistemáticas.".to_string(),
            EventType::Anomaly => "Comportamiento estadísticamente anormal que se desvía significativamente de los patrones establecidos de actividad legítima.".to_string(),
            _ => "Patrón de actividad que requiere análisis manual adicional para determinar su naturaleza maliciosa.".to_string(),
        }
    }

    fn detect_obfuscation_techniques(raw_message: &str) -> Vec<String> {
        let mut techniques = Vec::new();

        if raw_message.contains("%") {
            techniques.push("URL Encoding detected".to_string());
        }
        if raw_message.contains("\\x") {
            techniques.push("Hexadecimal encoding detected".to_string());
        }
        if raw_message.contains("base64") || raw_message.contains("btoa") {
            techniques.push("Base64 encoding detected".to_string());
        }
        if raw_message.chars().any(|c| c as u32 > 127) {
            techniques.push("Unicode obfuscation possible".to_string());
        }

        techniques
    }

    fn get_vulnerability_details(event_type: &crate::EventType) -> Option<VulnerabilityDetails> {
        use crate::EventType;

        match event_type {
            EventType::SqlInjection => Some(VulnerabilityDetails {
                cve_id: Some("CWE-89".to_string()),
                cvss_score: Some(8.8),
                description: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')".to_string(),
                affected_components: vec![
                    "Web Applications with Database Connectivity".to_string(),
                    "Database Management Systems".to_string(),
                    "API Endpoints processing user input".to_string(),
                ],
                exploit_complexity: "Low - Widely documented with automated tools available".to_string(),
            }),
            EventType::XssAttempt => Some(VulnerabilityDetails {
                cve_id: Some("CWE-79".to_string()),
                cvss_score: Some(6.1),
                description: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')".to_string(),
                affected_components: vec![
                    "Web Applications with User Input".to_string(),
                    "Web Browsers".to_string(),
                    "Content Management Systems".to_string(),
                ],
                exploit_complexity: "Low - Common vulnerability with many exploitation frameworks".to_string(),
            }),
            EventType::BruteForce => Some(VulnerabilityDetails {
                cve_id: None,
                cvss_score: Some(5.3),
                description: "Weak Authentication Controls allowing systematic credential guessing".to_string(),
                affected_components: vec![
                    "Authentication Systems".to_string(),
                    "Login Endpoints".to_string(),
                    "Remote Access Services".to_string(),
                ],
                exploit_complexity: "Low - Automated tools widely available".to_string(),
            }),
            _ => None,
        }
    }

    fn extract_iocs(event: &LogEvent) -> Vec<IoC> {
        let mut iocs = Vec::new();

        if let Some(ip) = &event.source_ip {
            iocs.push(IoC {
                ioc_type: "IP Address".to_string(),
                value: ip.clone(),
                confidence: "High".to_string(),
                description: "Source IP address of the malicious event".to_string(),
            });
        }

        // Extraer patrones específicos del mensaje raw
        if event.raw_message.contains("UNION") {
            iocs.push(IoC {
                ioc_type: "Attack Pattern".to_string(),
                value: "SQL UNION".to_string(),
                confidence: "High".to_string(),
                description: "SQL injection UNION attack pattern detected".to_string(),
            });
        }

        if event.raw_message.contains("<script>") {
            iocs.push(IoC {
                ioc_type: "Attack Pattern".to_string(),
                value: "<script> tag".to_string(),
                confidence: "High".to_string(),
                description: "XSS script tag injection detected".to_string(),
            });
        }

        iocs
    }

    fn get_triggered_detection_rules(event_type: &crate::EventType) -> Vec<DetectionRuleInfo> {
        use crate::EventType;

        match event_type {
            EventType::SqlInjection => vec![
                DetectionRuleInfo {
                    rule_name: "SQL Injection Pattern Detection".to_string(),
                    confidence: 0.92,
                    description: "Detects common SQL injection patterns in HTTP parameters".to_string(),
                    false_positive_rate: "Low (2-3%)".to_string(),
                },
                DetectionRuleInfo {
                    rule_name: "Database Function Call Detection".to_string(),
                    confidence: 0.85,
                    description: "Identifies suspicious database function calls in user input".to_string(),
                    false_positive_rate: "Medium (5-8%)".to_string(),
                },
            ],
            EventType::XssAttempt => vec![
                DetectionRuleInfo {
                    rule_name: "XSS Script Tag Detection".to_string(),
                    confidence: 0.88,
                    description: "Detects JavaScript tags in user-controlled parameters".to_string(),
                    false_positive_rate: "Low (1-2%)".to_string(),
                },
            ],
            EventType::BruteForce => vec![
                DetectionRuleInfo {
                    rule_name: "Multiple Authentication Failures".to_string(),
                    confidence: 0.94,
                    description: "Detects repeated failed login attempts from single source".to_string(),
                    false_positive_rate: "Very Low (<1%)".to_string(),
                },
            ],
            _ => vec![],
        }
    }

    /// Genera guías de mitigación específicas
    fn generate_mitigation_guidance(event_type: &crate::EventType) -> MitigationGuidance {
        use crate::EventType;

        match event_type {
            EventType::SqlInjection => MitigationGuidance {
                immediate_actions: vec![
                    MitigationStep {
                        action: "Block source IP in firewall".to_string(),
                        priority: "Critical".to_string(),
                        timeline: "Immediate (0-5 minutes)".to_string(),
                        tools_required: vec!["Firewall Management".to_string(), "IP Blocking Tools".to_string()],
                        expected_outcome: "Prevent further attacks from the same source".to_string(),
                    },
                    MitigationStep {
                        action: "Review database logs for unauthorized access".to_string(),
                        priority: "High".to_string(),
                        timeline: "Within 30 minutes".to_string(),
                        tools_required: vec!["Database Logs".to_string(), "Log Analysis Tools".to_string()],
                        expected_outcome: "Identify potential data compromise".to_string(),
                    },
                ],
                preventive_measures: vec![
                    MitigationStep {
                        action: "Implement prepared statements in application code".to_string(),
                        priority: "Critical".to_string(),
                        timeline: "1-2 weeks".to_string(),
                        tools_required: vec!["Development IDE".to_string(), "Code Review Tools".to_string()],
                        expected_outcome: "Eliminate SQL injection vulnerabilities entirely".to_string(),
                    },
                    MitigationStep {
                        action: "Deploy Web Application Firewall (WAF)".to_string(),
                        priority: "High".to_string(),
                        timeline: "24-48 hours".to_string(),
                        tools_required: vec!["WAF Solution".to_string(), "Network Configuration Tools".to_string()],
                        expected_outcome: "Filter malicious requests before reaching application".to_string(),
                    },
                ],
                long_term_strategies: vec![
                    MitigationStep {
                        action: "Implement Secure Development Lifecycle (SDLC)".to_string(),
                        priority: "Medium".to_string(),
                        timeline: "3-6 months".to_string(),
                        tools_required: vec!["SAST Tools".to_string(), "Security Training".to_string(), "Code Review Process".to_string()],
                        expected_outcome: "Prevent security vulnerabilities from reaching production".to_string(),
                    },
                ],
            },
            EventType::XssAttempt => MitigationGuidance {
                immediate_actions: vec![
                    MitigationStep {
                        action: "Enable Content Security Policy (CSP)".to_string(),
                        priority: "High".to_string(),
                        timeline: "Immediate (0-15 minutes)".to_string(),
                        tools_required: vec!["Web Server Configuration".to_string()],
                        expected_outcome: "Prevent script execution from untrusted sources".to_string(),
                    },
                ],
                preventive_measures: vec![
                    MitigationStep {
                        action: "Implement proper output encoding".to_string(),
                        priority: "Critical".to_string(),
                        timeline: "1-3 days".to_string(),
                        tools_required: vec!["Web Framework Libraries".to_string(), "Template Engines".to_string()],
                        expected_outcome: "Neutralize malicious scripts in user input".to_string(),
                    },
                ],
                long_term_strategies: vec![
                    MitigationStep {
                        action: "Regular security testing and code reviews".to_string(),
                        priority: "Medium".to_string(),
                        timeline: "Ongoing".to_string(),
                        tools_required: vec!["DAST Tools".to_string(), "Manual Testing".to_string()],
                        expected_outcome: "Identify and fix XSS vulnerabilities proactively".to_string(),
                    },
                ],
            },
            _ => MitigationGuidance {
                immediate_actions: vec![],
                preventive_measures: vec![],
                long_term_strategies: vec![],
            },
        }
    }

    /// Genera ejemplos del mundo real
    fn generate_real_world_examples(event_type: &crate::EventType) -> Vec<RealWorldExample> {
        use crate::EventType;

        match event_type {
            EventType::SqlInjection => vec![
                RealWorldExample {
                    incident_name: "Equifax Data Breach".to_string(),
                    year: 2017,
                    organization: "Equifax".to_string(),
                    impact: "147 millones de personas afectadas, pérdida de datos personales masiva".to_string(),
                    lessons_learned: "La importancia del patching oportuno y la implementación de defense-in-depth".to_string(),
                    prevention_method: "Prepared statements, input validation, y actualizaciones de seguridad regulares".to_string(),
                },
                RealWorldExample {
                    incident_name: "TalkTalk Cyber Attack".to_string(),
                    year: 2015,
                    organization: "TalkTalk".to_string(),
                    impact: "4 millones de clientes afectados, multa regulatoria de £400,000".to_string(),
                    lessons_learned: "La necesidad de cifrado de datos y validación robusta de input del usuario".to_string(),
                    prevention_method: "WAF implementation, database encryption, y secure coding practices".to_string(),
                },
            ],
            EventType::XssAttempt => vec![
                RealWorldExample {
                    incident_name: "Twitter XSS Worm".to_string(),
                    year: 2010,
                    organization: "Twitter".to_string(),
                    impact: "Propagación viral de contenido malicioso, compromiso de cuentas de usuarios".to_string(),
                    lessons_learned: "La importancia de sanitización de input y Content Security Policy".to_string(),
                    prevention_method: "Output encoding, CSP headers, y input validation estricta".to_string(),
                },
                RealWorldExample {
                    incident_name: "MySpace Samy Worm".to_string(),
                    year: 2005,
                    organization: "MySpace".to_string(),
                    impact: "Más de 1 millón de perfiles infectados en menos de 24 horas".to_string(),
                    lessons_learned: "Las vulnerabilidades XSS pueden tener efectos de propagación masiva".to_string(),
                    prevention_method: "Strict input filtering y proper JavaScript sandboxing".to_string(),
                },
            ],
            _ => vec![],
        }
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
