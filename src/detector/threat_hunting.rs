use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration, Timelike};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{LogEvent, Severity, storage::StorageManager};
use anyhow::Result;

/// Motor de búsqueda proactiva de amenazas (Threat Hunting)
#[derive(Debug, Clone)]
pub struct ThreatHuntingEngine {
    /// Consultas de hunting predefinidas
    hunt_queries: Vec<HuntQuery>,
    /// Indicadores de compromiso (IOCs)
    iocs: Vec<IndicatorOfCompromise>,
    /// Patrones de comportamiento anómalo
    behavior_patterns: Vec<BehaviorPattern>,
}

/// Consulta de threat hunting con criterios específicos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntQuery {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    pub query: String,
    pub indicators: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub hunt_type: HuntType,
    pub confidence_threshold: f64,
    pub time_window_hours: u64,
    pub educational_context: String,
}

/// Tipos de hunting según metodología
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HuntType {
    /// Búsqueda basada en hipótesis específicas
    HypothesisDriven,
    /// Búsqueda basada en IOCs conocidos
    IndicatorBased,
    /// Búsqueda de comportamientos anómalos
    AnomalyBased,
    /// Búsqueda de técnicas específicas de MITRE ATT&CK
    TechniqueBased,
    /// Búsqueda de amenazas persistentes avanzadas
    APTHunting,
}

/// Indicador de compromiso para threat hunting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorOfCompromise {
    pub id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub description: String,
    pub threat_level: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source: String,
    pub related_campaigns: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    EmailAddress,
    UserAgent,
    Payload,
    Certificate,
    Registry,
    Mutex,
}

/// Patrón de comportamiento para detección de anomalías
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern_type: String,
    pub baseline_metrics: HashMap<String, f64>,
    pub anomaly_threshold: f64,
    pub detection_window: Duration,
    pub related_techniques: Vec<String>,
}

/// Resultado de una sesión de threat hunting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntResult {
    pub hunt_id: String,
    pub query_name: String,
    pub execution_time: DateTime<Utc>,
    pub matches_found: u64,
    pub confidence_score: f64,
    pub risk_level: String,
    pub findings: Vec<HuntFinding>,
    pub recommendations: Vec<String>,
    pub false_positive_likelihood: f64,
    pub investigation_priority: u8, // 1-10
}

/// Hallazgo específico de threat hunting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntFinding {
    pub id: String,
    pub finding_type: String,
    pub description: String,
    pub evidence: Vec<LogEvent>,
    pub indicators_matched: Vec<String>,
    pub attack_timeline: Vec<TimelineEvent>,
    pub affected_systems: Vec<String>,
    pub confidence: f64,
    pub severity: Severity,
    pub mitigation_steps: Vec<String>,
    pub educational_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub source_system: String,
    pub indicators: Vec<String>,
}

impl ThreatHuntingEngine {
    /// Crea un nuevo motor de threat hunting con consultas predefinidas
    pub fn new() -> Self {
        Self {
            hunt_queries: Self::load_default_hunt_queries(),
            iocs: Self::load_default_iocs(),
            behavior_patterns: Self::load_default_behavior_patterns(),
        }
    }

    /// Ejecuta una consulta de threat hunting específica
    pub async fn execute_hunt(&self, query_id: &str, storage: &StorageManager) -> Result<HuntResult> {
        let query = self.hunt_queries.iter()
            .find(|q| q.id == query_id)
            .ok_or_else(|| anyhow::anyhow!("Hunt query not found: {}", query_id))?;

        let start_time = Utc::now();
        let time_window = Duration::hours(query.time_window_hours as i64);
        let from_time = start_time - time_window;

        // Ejecutar búsqueda en eventos históricos
        let events = storage.get_events_filtered(
            1000, // limit
            None, // severity
            None, // source
            Some(from_time),
            Some(start_time),
        ).await?;

        let mut findings = Vec::new();
        let matches_found;

        // Analizar eventos según el tipo de hunting
        match query.hunt_type {
            HuntType::IndicatorBased => {
                findings.extend(self.hunt_by_indicators(&events, query)?);
            },
            HuntType::AnomalyBased => {
                findings.extend(self.hunt_by_anomalies(&events, query)?);
            },
            HuntType::TechniqueBased => {
                findings.extend(self.hunt_by_techniques(&events, query)?);
            },
            HuntType::APTHunting => {
                findings.extend(self.hunt_apt_activities(&events, query)?);
            },
            HuntType::HypothesisDriven => {
                findings.extend(self.hunt_by_hypothesis(&events, query)?);
            },
        }

        matches_found = findings.len() as u64;
        let confidence_score = self.calculate_hunt_confidence(&findings);
        let risk_level = self.assess_risk_level(confidence_score);

        Ok(HuntResult {
            hunt_id: Uuid::new_v4().to_string(),
            query_name: query.name.clone(),
            execution_time: start_time,
            matches_found,
            confidence_score,
            risk_level,
            findings,
            recommendations: self.generate_recommendations(query),
            false_positive_likelihood: self.estimate_false_positive_rate(query),
            investigation_priority: self.calculate_priority(confidence_score, &query.severity),
        })
    }

    /// Obtiene todas las consultas de hunting disponibles
    pub fn get_available_hunts(&self) -> Vec<&HuntQuery> {
        self.hunt_queries.iter().collect()
    }

    /// Añade un nuevo indicador de compromiso
    pub fn add_ioc(&mut self, ioc: IndicatorOfCompromise) {
        self.iocs.push(ioc);
    }

    /// Búsqueda basada en indicadores de compromiso
    fn hunt_by_indicators(&self, events: &[LogEvent], query: &HuntQuery) -> Result<Vec<HuntFinding>> {
        let mut findings = Vec::new();

        for event in events {
            let mut matched_indicators = Vec::new();
            
            // Verificar IOCs en el evento
            if let Some(source_ip) = &event.source_ip {
                for ioc in &self.iocs {
                    if matches!(ioc.ioc_type, IocType::IpAddress) && ioc.value == *source_ip {
                        matched_indicators.push(ioc.value.clone());
                    }
                }
            }

            // Verificar IOCs en el contenido del mensaje
            for ioc in &self.iocs {
                match ioc.ioc_type {
                    IocType::Domain | IocType::Url => {
                        if event.raw_message.contains(&ioc.value) {
                            matched_indicators.push(ioc.value.clone());
                        }
                    },
                    IocType::UserAgent => {
                        if event.raw_message.contains("User-Agent") && event.raw_message.contains(&ioc.value) {
                            matched_indicators.push(ioc.value.clone());
                        }
                    },
                    _ => {}
                }
            }

            if !matched_indicators.is_empty() {
                findings.push(HuntFinding {
                    id: Uuid::new_v4().to_string(),
                    finding_type: "IOC Match".to_string(),
                    description: format!("Evento coincide con {} indicadores conocidos de compromiso", matched_indicators.len()),
                    evidence: vec![event.clone()],
                    indicators_matched: matched_indicators,
                    attack_timeline: vec![TimelineEvent {
                        timestamp: event.timestamp,
                        event_type: format!("{:?}", event.event_type),
                        description: event.raw_message.clone(),
                        source_system: event.source.clone(),
                        indicators: query.indicators.clone(),
                    }],
                    affected_systems: vec![event.source.clone()],
                    confidence: 0.8,
                    severity: query.severity.clone(),
                    mitigation_steps: vec![
                        "Aislar sistemas afectados inmediatamente".to_string(),
                        "Analizar tráfico de red relacionado".to_string(),
                        "Verificar integridad de archivos del sistema".to_string(),
                    ],
                    educational_notes: vec![
                        "Los IOCs permiten identificar amenazas conocidas de manera proactiva".to_string(),
                        "La correlación temporal de IOCs puede revelar campañas de atacantes".to_string(),
                    ],
                });
            }
        }

        Ok(findings)
    }

    /// Búsqueda basada en anomalías de comportamiento
    fn hunt_by_anomalies(&self, events: &[LogEvent], _query: &HuntQuery) -> Result<Vec<HuntFinding>> {
        let mut findings = Vec::new();

        // Agrupar eventos por fuente y analizar patrones
        let mut event_counts_by_source = HashMap::new();
        for event in events {
            *event_counts_by_source.entry(&event.source).or_insert(0) += 1;
        }

        // Detectar fuentes con actividad anómala
        for (source, count) in event_counts_by_source {
            if count > 100 {  // Threshold arbitrario para anomalía
                let related_events: Vec<LogEvent> = events.iter()
                    .filter(|e| e.source == *source)
                    .take(5)
                    .cloned()
                    .collect();

                findings.push(HuntFinding {
                    id: Uuid::new_v4().to_string(),
                    finding_type: "Anomalous Activity".to_string(),
                    description: format!("Actividad anómala detectada en {} con {} eventos", source, count),
                    evidence: related_events,
                    indicators_matched: vec!["high_event_volume".to_string()],
                    attack_timeline: vec![],
                    affected_systems: vec![source.clone()],
                    confidence: 0.7,
                    severity: Severity::Warning,
                    mitigation_steps: vec![
                        "Investigar la causa del aumento de actividad".to_string(),
                        "Verificar si es tráfico legítimo o malicioso".to_string(),
                    ],
                    educational_notes: vec![
                        "Las anomalías estadísticas pueden indicar comportamiento malicioso".to_string(),
                        "El análisis temporal ayuda a distinguir anomalías legítimas de ataques".to_string(),
                    ],
                });
            }
        }

        Ok(findings)
    }

    /// Búsqueda basada en técnicas MITRE ATT&CK
    fn hunt_by_techniques(&self, events: &[LogEvent], query: &HuntQuery) -> Result<Vec<HuntFinding>> {
        let mut findings = Vec::new();

        for event in events {
            let mut matched_techniques = Vec::new();

            // Verificar técnicas específicas según el tipo de evento
            for technique in &query.mitre_techniques {
                match technique.as_str() {
                    "T1190" => { // Exploit Public-Facing Application
                        if event.raw_message.contains("HTTP") && 
                           (event.raw_message.contains("UNION") || 
                            event.raw_message.contains("<script>") ||
                            event.raw_message.contains("../")) {
                            matched_techniques.push(technique.clone());
                        }
                    },
                    "T1110" => { // Brute Force
                        if event.raw_message.contains("Failed") && 
                           event.raw_message.contains("login") {
                            matched_techniques.push(technique.clone());
                        }
                    },
                    "T1059" => { // Command and Scripting Interpreter
                        if event.raw_message.contains("<script>") ||
                           event.raw_message.contains("javascript:") {
                            matched_techniques.push(technique.clone());
                        }
                    },
                    _ => {}
                }
            }

            if !matched_techniques.is_empty() {
                findings.push(HuntFinding {
                    id: Uuid::new_v4().to_string(),
                    finding_type: "MITRE Technique Match".to_string(),
                    description: format!("Evento coincide con técnicas MITRE: {}", matched_techniques.join(", ")),
                    evidence: vec![event.clone()],
                    indicators_matched: matched_techniques.clone(),
                    attack_timeline: vec![],
                    affected_systems: vec![event.source.clone()],
                    confidence: 0.75,
                    severity: query.severity.clone(),
                    mitigation_steps: self.get_technique_mitigations(&matched_techniques),
                    educational_notes: vec![
                        "MITRE ATT&CK Framework mapea técnicas reales de atacantes".to_string(),
                        "La identificación de técnicas ayuda a entender la intención del atacante".to_string(),
                    ],
                });
            }
        }

        Ok(findings)
    }

    /// Búsqueda de actividades APT (Advanced Persistent Threat)
    fn hunt_apt_activities(&self, events: &[LogEvent], _query: &HuntQuery) -> Result<Vec<HuntFinding>> {
        let mut findings = Vec::new();

        // Buscar patrones típicos de APT
        let mut suspicious_ips = HashMap::new();
        let mut persistence_indicators = Vec::new();

        for event in events {
            // Detectar IPs con múltiples tipos de actividad (característica de APT)
            if let Some(ip) = &event.source_ip {
                let entry = suspicious_ips.entry(ip.clone()).or_insert(Vec::new());
                entry.push(event.clone());
            }

            // Detectar indicadores de persistencia
            if event.raw_message.contains("cron") || 
               event.raw_message.contains("startup") ||
               event.raw_message.contains("registry") {
                persistence_indicators.push(event.clone());
            }
        }

        // Analizar IPs con actividad diversa
        for (ip, ip_events) in suspicious_ips {
            if ip_events.len() > 20 { // Threshold para considerarlo sospechoso
                let unique_sources: std::collections::HashSet<_> = ip_events.iter()
                    .map(|e| &e.source)
                    .collect();

                if unique_sources.len() > 3 { // IP activa en múltiples sistemas
                    let evidence_sample: Vec<LogEvent> = ip_events.iter()
                        .take(10)
                        .cloned()
                        .collect();
                    
                    findings.push(HuntFinding {
                        id: Uuid::new_v4().to_string(),
                        finding_type: "APT Behavior Pattern".to_string(),
                        description: format!("IP {} muestra actividad característica de APT: {} eventos en {} sistemas", ip, ip_events.len(), unique_sources.len()),
                        evidence: evidence_sample,
                        indicators_matched: vec!["multi_system_access".to_string(), "high_activity_volume".to_string()],
                        attack_timeline: vec![],
                        affected_systems: unique_sources.into_iter().cloned().collect(),
                        confidence: 0.65,
                        severity: Severity::High,
                        mitigation_steps: vec![
                            "Bloquear IP inmediatamente en firewall".to_string(),
                            "Analizar logs históricos para determinar alcance del compromiso".to_string(),
                            "Implementar monitoreo adicional en sistemas afectados".to_string(),
                        ],
                        educational_notes: vec![
                            "Las APTs se caracterizan por actividad prolongada y diversa".to_string(),
                            "Los atacantes APT buscan mantener acceso persistente".to_string(),
                        ],
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Búsqueda basada en hipótesis específicas
    fn hunt_by_hypothesis(&self, events: &[LogEvent], query: &HuntQuery) -> Result<Vec<HuntFinding>> {
        let mut findings = Vec::new();

        // Ejemplo de hipótesis: "Exfiltración de datos durante horarios no laborales"
        if query.name.contains("data_exfiltration") {
            for event in events {
                let hour = event.timestamp.hour();
                
                // Horarios no laborales (21:00 - 07:00)
                if hour >= 21 || hour <= 7 {
                    // Buscar patrones de transferencia de datos
                    if event.raw_message.contains("download") ||
                       event.raw_message.contains("export") ||
                       event.raw_message.len() > 500 { // Requests largos pueden indicar exfiltración
                        
                        findings.push(HuntFinding {
                            id: Uuid::new_v4().to_string(),
                            finding_type: "Data Exfiltration Hypothesis".to_string(),
                            description: "Posible exfiltración de datos durante horarios no laborales".to_string(),
                            evidence: vec![event.clone()],
                            indicators_matched: vec!["off_hours_activity".to_string(), "data_transfer".to_string()],
                            attack_timeline: vec![],
                            affected_systems: vec![event.source.clone()],
                            confidence: 0.6,
                            severity: Severity::High,
                            mitigation_steps: vec![
                                "Verificar autorización para acceso fuera de horario".to_string(),
                                "Analizar volumen de datos transferidos".to_string(),
                                "Revisar credenciales utilizadas".to_string(),
                            ],
                            educational_notes: vec![
                                "La exfiltración suele ocurrir fuera del horario laboral para evitar detección".to_string(),
                                "El análisis temporal es crucial en threat hunting".to_string(),
                            ],
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Calcula la confianza general del hunt
    fn calculate_hunt_confidence(&self, findings: &[HuntFinding]) -> f64 {
        if findings.is_empty() {
            return 0.0;
        }

        let total_confidence: f64 = findings.iter().map(|f| f.confidence).sum();
        total_confidence / findings.len() as f64
    }

    /// Evalúa el nivel de riesgo basado en la confianza
    fn assess_risk_level(&self, confidence: f64) -> String {
        match confidence {
            c if c >= 0.8 => "HIGH".to_string(),
            c if c >= 0.6 => "MEDIUM".to_string(),
            c if c >= 0.4 => "LOW".to_string(),
            _ => "MINIMAL".to_string(),
        }
    }

    /// Genera recomendaciones basadas en la consulta
    fn generate_recommendations(&self, query: &HuntQuery) -> Vec<String> {
        let mut recommendations = vec![
            "Documentar todos los hallazgos para análisis posterior".to_string(),
            "Correlacionar con threat intelligence externa".to_string(),
            "Implementar reglas de detección automática para patrones identificados".to_string(),
        ];

        match query.hunt_type {
            HuntType::IndicatorBased => {
                recommendations.push("Actualizar feeds de IOCs con nuevos indicadores encontrados".to_string());
            },
            HuntType::AnomalyBased => {
                recommendations.push("Ajustar baselines para mejorar detección de anomalías".to_string());
            },
            HuntType::APTHunting => {
                recommendations.push("Extender búsqueda a períodos más largos para detectar persistencia".to_string());
            },
            _ => {}
        }

        recommendations
    }

    /// Estima la probabilidad de falsos positivos
    fn estimate_false_positive_rate(&self, query: &HuntQuery) -> f64 {
        match query.hunt_type {
            HuntType::IndicatorBased => 0.1, // IOCs bien validados
            HuntType::AnomalyBased => 0.3,   // Anomalías pueden ser legítimas
            HuntType::TechniqueBased => 0.2, // Técnicas pueden ser legítimas
            HuntType::APTHunting => 0.25,    // Patrones APT complejos
            HuntType::HypothesisDriven => 0.4, // Hipótesis requieren validación
        }
    }

    /// Calcula prioridad de investigación (1-10)
    fn calculate_priority(&self, confidence: f64, severity: &Severity) -> u8 {
        let base_priority = match severity {
            Severity::Critical => 9,
            Severity::High => 7,
            Severity::Warning => 5,
            Severity::Medium => 4,
            Severity::Info => 2,
            Severity::Low => 1,
        };

        let confidence_bonus = (confidence * 2.0) as u8;
        std::cmp::min(10, base_priority + confidence_bonus)
    }

    /// Obtiene mitigaciones para técnicas específicas
    fn get_technique_mitigations(&self, techniques: &[String]) -> Vec<String> {
        let mut mitigations = Vec::new();

        for technique in techniques {
            match technique.as_str() {
                "T1190" => {
                    mitigations.extend(vec![
                        "Aplicar patches de seguridad inmediatamente".to_string(),
                        "Implementar Web Application Firewall (WAF)".to_string(),
                        "Realizar testing de penetración regular".to_string(),
                    ]);
                },
                "T1110" => {
                    mitigations.extend(vec![
                        "Implementar autenticación multifactor (MFA)".to_string(),
                        "Configurar bloqueo automático de cuentas".to_string(),
                        "Utilizar CAPTCHA después de intentos fallidos".to_string(),
                    ]);
                },
                "T1059" => {
                    mitigations.extend(vec![
                        "Implementar Content Security Policy (CSP)".to_string(),
                        "Sanitizar todas las entradas de usuario".to_string(),
                        "Usar frameworks que escapen automáticamente el output".to_string(),
                    ]);
                },
                _ => {}
            }
        }

        mitigations
    }

    /// Carga consultas de hunting predefinidas
    fn load_default_hunt_queries() -> Vec<HuntQuery> {
        vec![
            HuntQuery {
                id: "hunt_001".to_string(),
                name: "Exfiltración de Datos Fuera de Horario".to_string(),
                description: "Busca actividad sospechosa de transferencia de datos durante horarios no laborales".to_string(),
                category: "Data Exfiltration".to_string(),
                severity: Severity::High,
                query: "SELECT * FROM events WHERE hour >= 21 OR hour <= 7".to_string(),
                indicators: vec!["off_hours_activity".to_string(), "large_data_transfer".to_string()],
                mitre_tactics: vec!["Exfiltration".to_string()],
                mitre_techniques: vec!["T1041".to_string(), "T1005".to_string()],
                hunt_type: HuntType::HypothesisDriven,
                confidence_threshold: 0.6,
                time_window_hours: 72,
                educational_context: "Los atacantes suelen exfiltrar datos fuera del horario laboral para evitar detección. Esta búsqueda identifica patrones de acceso y transferencia anómalos.".to_string(),
            },
            HuntQuery {
                id: "hunt_002".to_string(),
                name: "Actividad APT - Movimiento Lateral".to_string(),
                description: "Detecta patrones de movimiento lateral característicos de APTs".to_string(),
                category: "APT Detection".to_string(),
                severity: Severity::Critical,
                query: "SELECT * FROM events WHERE multiple_systems_accessed".to_string(),
                indicators: vec!["lateral_movement".to_string(), "credential_reuse".to_string()],
                mitre_tactics: vec!["Lateral Movement".to_string(), "Credential Access".to_string()],
                mitre_techniques: vec!["T1078".to_string(), "T1021".to_string()],
                hunt_type: HuntType::APTHunting,
                confidence_threshold: 0.7,
                time_window_hours: 168, // 1 semana
                educational_context: "Las APTs mantienen persistencia moviéndose lateralmente por la red. Buscan acceso a sistemas críticos usando credenciales comprometidas.".to_string(),
            },
            HuntQuery {
                id: "hunt_003".to_string(),
                name: "IOCs de Malware Conocido".to_string(),
                description: "Búsqueda basada en indicadores de compromiso de malware conocido".to_string(),
                category: "IOC Hunting".to_string(),
                severity: Severity::Critical,
                query: "SELECT * FROM events WHERE matches_known_iocs".to_string(),
                indicators: vec!["malware_signature".to_string(), "c2_communication".to_string()],
                mitre_tactics: vec!["Command and Control".to_string()],
                mitre_techniques: vec!["T1071".to_string(), "T1090".to_string()],
                hunt_type: HuntType::IndicatorBased,
                confidence_threshold: 0.8,
                time_window_hours: 24,
                educational_context: "Los IOCs permiten identificar amenazas conocidas. La correlación temporal de múltiples IOCs incrementa la confianza en la detección.".to_string(),
            },
        ]
    }

    /// Carga IOCs predefinidos para hunting
    fn load_default_iocs() -> Vec<IndicatorOfCompromise> {
        vec![
            IndicatorOfCompromise {
                id: "ioc_001".to_string(),
                ioc_type: IocType::IpAddress,
                value: "203.0.113.45".to_string(),
                description: "IP asociada con actividad de botnet Mirai".to_string(),
                threat_level: "HIGH".to_string(),
                first_seen: Utc::now() - Duration::days(30),
                last_seen: Utc::now() - Duration::days(1),
                source: "Threat Intelligence Feed".to_string(),
                related_campaigns: vec!["Mirai Botnet".to_string()],
                mitre_techniques: vec!["T1110".to_string()],
            },
            IndicatorOfCompromise {
                id: "ioc_002".to_string(),
                ioc_type: IocType::Domain,
                value: "malicious-c2.example.com".to_string(),
                description: "Dominio usado como C2 por APT28".to_string(),
                threat_level: "CRITICAL".to_string(),
                first_seen: Utc::now() - Duration::days(60),
                last_seen: Utc::now() - Duration::days(5),
                source: "Government Threat Intel".to_string(),
                related_campaigns: vec!["APT28".to_string(), "Fancy Bear".to_string()],
                mitre_techniques: vec!["T1071".to_string(), "T1105".to_string()],
            },
        ]
    }

    /// Carga patrones de comportamiento predefinidos
    fn load_default_behavior_patterns() -> Vec<BehaviorPattern> {
        vec![
            BehaviorPattern {
                id: "pattern_001".to_string(),
                name: "Actividad de Login Anómala".to_string(),
                description: "Detecta patrones anómalos en intentos de autenticación".to_string(),
                pattern_type: "Authentication".to_string(),
                baseline_metrics: HashMap::from([
                    ("avg_daily_logins".to_string(), 50.0),
                    ("peak_hour_logins".to_string(), 15.0),
                    ("failed_login_rate".to_string(), 0.05),
                ]),
                anomaly_threshold: 3.0, // 3 desviaciones estándar
                detection_window: Duration::hours(1),
                related_techniques: vec!["T1110".to_string(), "T1078".to_string()],
            },
        ]
    }
}

impl Default for ThreatHuntingEngine {
    fn default() -> Self {
        Self::new()
    }
}