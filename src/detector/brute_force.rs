use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

/// Detector especializado en ataques de fuerza bruta
#[derive(Clone)]
pub struct BruteForceDetector {
    patterns: Vec<BruteForcePattern>,
    ip_tracking: Arc<RwLock<HashMap<String, IpAttemptHistory>>>,
    user_tracking: Arc<RwLock<HashMap<String, UserAttemptHistory>>>,
    service_tracking: Arc<RwLock<HashMap<String, ServiceAttemptHistory>>>,
    config: BruteForceConfig,
    failure_keywords: Vec<Regex>,
    success_keywords: Vec<Regex>,
}

/// Configuración del detector de fuerza bruta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceConfig {
    pub max_attempts_per_ip: u32,
    pub max_attempts_per_user: u32,
    pub time_window_minutes: u32,
    pub lockout_duration_minutes: u32,
    pub progressive_delay: bool,
    pub track_successful_after_failed: bool,
    pub min_password_variations: u32,
    pub suspicious_user_agents: Vec<String>,
}

/// Patrón de detección de fuerza bruta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForcePattern {
    pub name: String,
    #[serde(with = "serde_regex")]
    pub regex: Regex,
    pub confidence: f64,
    pub attack_type: BruteForceType,
    pub service: ServiceType,
    pub description: String,
}

/// Tipos de ataques de fuerza bruta
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BruteForceType {
    Credential,
    Authentication,
    Directory,
    Subdomain,
    Parameter,
    Session,
    Api,
    Database,
    FileSystem,
}

/// Tipos de servicios atacados
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServiceType {
    Web,
    Ssh,
    Ftp,
    Database,
    Email,
    Api,
    Generic,
}

/// Historial de intentos por IP
#[derive(Debug, Clone)]
pub struct IpAttemptHistory {
    pub attempts: VecDeque<AttemptRecord>,
    pub total_attempts: u32,
    pub failed_attempts: u32,
    pub successful_attempts: u32,
    pub first_attempt: DateTime<Utc>,
    pub last_attempt: DateTime<Utc>,
    pub is_blocked: bool,
    pub block_until: Option<DateTime<Utc>>,
    pub services_attacked: HashMap<String, u32>,
    pub user_agents: HashMap<String, u32>,
}

/// Historial de intentos por usuario
#[derive(Debug, Clone)]
pub struct UserAttemptHistory {
    pub attempts: VecDeque<AttemptRecord>,
    pub total_attempts: u32,
    pub failed_attempts: u32,
    pub source_ips: HashMap<String, u32>,
    pub first_attempt: DateTime<Utc>,
    pub last_attempt: DateTime<Utc>,
    pub password_variations: Vec<String>,
    pub is_compromised: bool,
}

/// Historial de intentos por servicio
#[derive(Debug, Clone)]
pub struct ServiceAttemptHistory {
    pub attempts: VecDeque<AttemptRecord>,
    pub total_attempts: u32,
    pub unique_ips: u32,
    pub unique_users: u32,
    pub peak_attempts_per_minute: u32,
    pub first_attempt: DateTime<Utc>,
    pub last_attempt: DateTime<Utc>,
}

/// Registro individual de intento
#[derive(Debug, Clone)]
pub struct AttemptRecord {
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub username: Option<String>,
    pub service: String,
    pub is_successful: bool,
    pub user_agent: Option<String>,
    pub response_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub password_hash: Option<String>,
}

/// Resultado del análisis de fuerza bruta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceDetectionResult {
    pub is_detected: bool,
    pub confidence_score: f64,
    pub attack_types: Vec<BruteForceType>,
    pub services_targeted: Vec<ServiceType>,
    pub risk_level: RiskLevel,
    pub ip_analysis: IpAnalysis,
    pub user_analysis: Option<UserAnalysis>,
    pub service_analysis: ServiceAnalysis,
    pub attack_patterns: Vec<String>,
    pub indicators: Vec<AttackIndicator>,
    pub mitigation_suggestions: Vec<String>,
}

/// Análisis específico por IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAnalysis {
    pub source_ip: String,
    pub attempt_count: u32,
    pub failure_rate: f64,
    pub time_span_minutes: i64,
    pub attempts_per_minute: f64,
    pub services_targeted: u32,
    pub users_targeted: u32,
    pub user_agents_used: u32,
    pub is_distributed: bool,
    pub geo_location: Option<String>,
    pub reputation_score: f64,
}

/// Análisis específico por usuario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAnalysis {
    pub username: String,
    pub attempt_count: u32,
    pub source_ips: u32,
    pub password_variations: u32,
    pub is_likely_compromised: bool,
    pub compromise_confidence: f64,
}

/// Análisis específico por servicio
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAnalysis {
    pub service_name: String,
    pub total_attempts: u32,
    pub unique_attackers: u32,
    pub attack_duration_minutes: i64,
    pub peak_rate_per_minute: u32,
    pub is_under_attack: bool,
}

/// Indicadores de ataque
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: RiskLevel,
    pub confidence: f64,
}

/// Nivel de riesgo
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_ip: 10,
            max_attempts_per_user: 5,
            time_window_minutes: 15,
            lockout_duration_minutes: 30,
            progressive_delay: true,
            track_successful_after_failed: true,
            min_password_variations: 3,
            suspicious_user_agents: vec![
                "python-requests".to_string(),
                "curl".to_string(),
                "wget".to_string(),
                "httpie".to_string(),
                "postman".to_string(),
            ],
        }
    }
}

impl BruteForceDetector {
    pub fn new() -> Self {
        Self::with_config(BruteForceConfig::default())
    }

    pub fn with_config(config: BruteForceConfig) -> Self {
        let patterns = Self::initialize_patterns();
        let failure_keywords = Self::initialize_failure_keywords();
        let success_keywords = Self::initialize_success_keywords();

        Self {
            patterns,
            ip_tracking: Arc::new(RwLock::new(HashMap::new())),
            user_tracking: Arc::new(RwLock::new(HashMap::new())),
            service_tracking: Arc::new(RwLock::new(HashMap::new())),
            config,
            failure_keywords,
            success_keywords,
        }
    }

    /// Analiza un evento de log para detectar fuerza bruta
    pub fn analyze_event(&self,
                         source_ip: &str,
                         username: Option<&str>,
                         service: &str,
                         log_message: &str,
                         user_agent: Option<&str>,
                         response_code: Option<u16>,
                         timestamp: DateTime<Utc>
    ) -> Result<BruteForceDetectionResult> {

        // Determinar si el intento fue exitoso o fallido
        let is_successful = self.is_successful_attempt(log_message, response_code);

        // Crear registro del intento
        let attempt = AttemptRecord {
            timestamp,
            source_ip: source_ip.to_string(),
            username: username.map(|u| u.to_string()),
            service: service.to_string(),
            is_successful,
            user_agent: user_agent.map(|ua| ua.to_string()),
            response_code,
            response_time_ms: None,
            password_hash: None,
        };

        // Actualizar historiales
        self.update_ip_history(source_ip, &attempt);
        if let Some(user) = username {
            self.update_user_history(user, &attempt);
        }
        self.update_service_history(service, &attempt);

        // Analizar patrones de ataque
        let mut matched_patterns = Vec::new();
        let mut attack_types = Vec::new();
        let mut services_targeted = Vec::new();

        for pattern in &self.patterns {
            if pattern.regex.is_match(log_message) {
                matched_patterns.push(pattern.name.clone());
                if !attack_types.contains(&pattern.attack_type) {
                    attack_types.push(pattern.attack_type.clone());
                }
                if !services_targeted.contains(&pattern.service) {
                    services_targeted.push(pattern.service.clone());
                }
            }
        }

        // Realizar análisis detallado
        let ip_analysis = self.analyze_ip_behavior(source_ip)?;
        let user_analysis = if let Some(user) = username {
            Some(self.analyze_user_behavior(user)?)
        } else {
            None
        };
        let service_analysis = self.analyze_service_behavior(service)?;

        // Generar indicadores de ataque
        let indicators = self.generate_attack_indicators(&ip_analysis, &user_analysis, &service_analysis);

        // Calcular confidence score
        let confidence_score = self.calculate_confidence_score(&ip_analysis, &user_analysis, &service_analysis, &indicators);

        // Determinar si hay detección
        let is_detected = confidence_score >= 0.3 || ip_analysis.attempt_count >= self.config.max_attempts_per_ip;

        // Determinar nivel de riesgo
        let risk_level = self.determine_risk_level(confidence_score, &ip_analysis, &indicators);

        // Generar sugerencias de mitigación
        let mitigation_suggestions = self.generate_mitigation_suggestions(&attack_types, &ip_analysis, &service_analysis);

        Ok(BruteForceDetectionResult {
            is_detected,
            confidence_score,
            attack_types,
            services_targeted,
            risk_level,
            ip_analysis,
            user_analysis,
            service_analysis,
            attack_patterns: matched_patterns,
            indicators,
            mitigation_suggestions,
        })
    }

    /// Inicializa patrones de detección
    fn initialize_patterns() -> Vec<BruteForcePattern> {
        let mut patterns = Vec::new();

        // Autenticación web fallida
        patterns.push(BruteForcePattern {
            name: "web_auth_failed".to_string(),
            regex: Regex::new(r"(?i)(authentication failed|invalid (password|credentials|login)|access denied|unauthorized|401|403)").unwrap(),
            confidence: 0.8,
            attack_type: BruteForceType::Authentication,
            service: ServiceType::Web,
            description: "Web authentication failure".to_string(),
        });

        // SSH login fallido
        patterns.push(BruteForcePattern {
            name: "ssh_auth_failed".to_string(),
            regex: Regex::new(r"(?i)(ssh.*failed|sshd.*authentication failure|invalid user|refused connect)").unwrap(),
            confidence: 0.9,
            attack_type: BruteForceType::Authentication,
            service: ServiceType::Ssh,
            description: "SSH authentication failure".to_string(),
        });

        // FTP login fallido
        patterns.push(BruteForcePattern {
            name: "ftp_auth_failed".to_string(),
            regex: Regex::new(r"(?i)(ftp.*login failed|ftp.*authentication failed|530 login incorrect)").unwrap(),
            confidence: 0.85,
            attack_type: BruteForceType::Authentication,
            service: ServiceType::Ftp,
            description: "FTP authentication failure".to_string(),
        });

        // Base de datos
        patterns.push(BruteForcePattern {
            name: "database_auth_failed".to_string(),
            regex: Regex::new(r"(?i)(mysql.*access denied|postgresql.*authentication failed|oracle.*invalid username|mssql.*login failed)").unwrap(),
            confidence: 0.9,
            attack_type: BruteForceType::Database,
            service: ServiceType::Database,
            description: "Database authentication failure".to_string(),
        });

        // API authentication
        patterns.push(BruteForcePattern {
            name: "api_auth_failed".to_string(),
            regex: Regex::new(r"(?i)(api.*unauthorized|invalid api key|bearer token|oauth.*failed)").unwrap(),
            confidence: 0.8,
            attack_type: BruteForceType::Api,
            service: ServiceType::Api,
            description: "API authentication failure".to_string(),
        });

        // Directory traversal/enumeration
        patterns.push(BruteForcePattern {
            name: "directory_enumeration".to_string(),
            regex: Regex::new(r"(?i)(404.*not found|403.*forbidden).*(admin|backup|test|dev|staging|config)").unwrap(),
            confidence: 0.7,
            attack_type: BruteForceType::Directory,
            service: ServiceType::Web,
            description: "Directory enumeration attempt".to_string(),
        });

        // Parameter fuzzing
        patterns.push(BruteForcePattern {
            name: "parameter_fuzzing".to_string(),
            regex: Regex::new(r"(?i)(GET|POST).*[\?&](id|user|admin|test|debug)=\d+").unwrap(),
            confidence: 0.6,
            attack_type: BruteForceType::Parameter,
            service: ServiceType::Web,
            description: "Parameter fuzzing detected".to_string(),
        });

        // Session hijacking attempts
        patterns.push(BruteForcePattern {
            name: "session_brute_force".to_string(),
            regex: Regex::new(r"(?i)(session.*invalid|csrf.*failed|sessionid.*not found)").unwrap(),
            confidence: 0.7,
            attack_type: BruteForceType::Session,
            service: ServiceType::Web,
            description: "Session brute force attempt".to_string(),
        });

        patterns
    }

    /// Inicializa palabras clave de fallo
    fn initialize_failure_keywords() -> Vec<Regex> {
        vec![
            Regex::new(r"(?i)\b(failed|failure|invalid|incorrect|denied|unauthorized|forbidden|error|reject)\b").unwrap(),
            Regex::new(r"(?i)\b(wrong|bad|illegal|refused|blocked|banned|suspended)\b").unwrap(),
            Regex::new(r"\b(401|403|404|500|503)\b").unwrap(),
        ]
    }

    /// Inicializa palabras clave de éxito
    fn initialize_success_keywords() -> Vec<Regex> {
        vec![
            Regex::new(r"(?i)\b(success|successful|accepted|authenticated|authorized|logged in|welcome)\b").unwrap(),
            Regex::new(r"(?i)\b(granted|allowed|permitted|approved|valid|correct)\b").unwrap(),
            Regex::new(r"\b(200|201|202|204)\b").unwrap(),
        ]
    }

    /// Determina si un intento fue exitoso
    fn is_successful_attempt(&self, log_message: &str, response_code: Option<u16>) -> bool {
        // Verificar código de respuesta primero
        if let Some(code) = response_code {
            match code {
                200..=299 => return true,
                400..=499 | 500..=599 => return false,
                _ => {}
            }
        }

        // Verificar palabras clave de éxito
        for pattern in &self.success_keywords {
            if pattern.is_match(log_message) {
                return true;
            }
        }

        // Verificar palabras clave de fallo
        for pattern in &self.failure_keywords {
            if pattern.is_match(log_message) {
                return false;
            }
        }

        // Por defecto, asumir fallo si no hay indicadores claros
        false
    }

    /// Actualiza historial por IP
    fn update_ip_history(&self, source_ip: &str, attempt: &AttemptRecord) {
        let mut ip_tracking = self.ip_tracking.write().unwrap();
        let history = ip_tracking.entry(source_ip.to_string()).or_insert_with(|| {
            IpAttemptHistory {
                attempts: VecDeque::new(),
                total_attempts: 0,
                failed_attempts: 0,
                successful_attempts: 0,
                first_attempt: attempt.timestamp,
                last_attempt: attempt.timestamp,
                is_blocked: false,
                block_until: None,
                services_attacked: HashMap::new(),
                user_agents: HashMap::new(),
            }
        });

        // Limpiar intentos antiguos
        let cutoff_time = Utc::now() - Duration::minutes(self.config.time_window_minutes as i64);
        while let Some(front) = history.attempts.front() {
            if front.timestamp < cutoff_time {
                history.attempts.pop_front();
            } else {
                break;
            }
        }

        // Agregar nuevo intento
        history.attempts.push_back(attempt.clone());
        history.total_attempts += 1;
        history.last_attempt = attempt.timestamp;

        if attempt.is_successful {
            history.successful_attempts += 1;
        } else {
            history.failed_attempts += 1;
        }

        // Actualizar servicios atacados
        *history.services_attacked.entry(attempt.service.clone()).or_insert(0) += 1;

        // Actualizar user agents
        if let Some(ua) = &attempt.user_agent {
            *history.user_agents.entry(ua.clone()).or_insert(0) += 1;
        }

        // Verificar si debe ser bloqueada
        if history.failed_attempts >= self.config.max_attempts_per_ip {
            history.is_blocked = true;
            history.block_until = Some(Utc::now() + Duration::minutes(self.config.lockout_duration_minutes as i64));
        }
    }

    /// Actualiza historial por usuario
    fn update_user_history(&self, username: &str, attempt: &AttemptRecord) {
        let mut user_tracking = self.user_tracking.write().unwrap();
        let history = user_tracking.entry(username.to_string()).or_insert_with(|| {
            UserAttemptHistory {
                attempts: VecDeque::new(),
                total_attempts: 0,
                failed_attempts: 0,
                source_ips: HashMap::new(),
                first_attempt: attempt.timestamp,
                last_attempt: attempt.timestamp,
                password_variations: Vec::new(),
                is_compromised: false,
            }
        });

        // Limpiar intentos antiguos
        let cutoff_time = Utc::now() - Duration::minutes(self.config.time_window_minutes as i64);
        while let Some(front) = history.attempts.front() {
            if front.timestamp < cutoff_time {
                history.attempts.pop_front();
            } else {
                break;
            }
        }

        // Agregar nuevo intento
        history.attempts.push_back(attempt.clone());
        history.total_attempts += 1;
        history.last_attempt = attempt.timestamp;

        if !attempt.is_successful {
            history.failed_attempts += 1;
        }

        // Actualizar IPs de origen
        *history.source_ips.entry(attempt.source_ip.clone()).or_insert(0) += 1;

        // Detectar compromiso exitoso después de fallos
        if self.config.track_successful_after_failed &&
            attempt.is_successful &&
            history.failed_attempts > 0 {
            history.is_compromised = true;
        }
    }

    /// Actualiza historial por servicio
    fn update_service_history(&self, service: &str, attempt: &AttemptRecord) {
        let mut service_tracking = self.service_tracking.write().unwrap();
        let history = service_tracking.entry(service.to_string()).or_insert_with(|| {
            ServiceAttemptHistory {
                attempts: VecDeque::new(),
                total_attempts: 0,
                unique_ips: 0,
                unique_users: 0,
                peak_attempts_per_minute: 0,
                first_attempt: attempt.timestamp,
                last_attempt: attempt.timestamp,
            }
        });

        // Limpiar intentos antiguos
        let cutoff_time = Utc::now() - Duration::minutes(self.config.time_window_minutes as i64);
        while let Some(front) = history.attempts.front() {
            if front.timestamp < cutoff_time {
                history.attempts.pop_front();
            } else {
                break;
            }
        }

        // Agregar nuevo intento
        history.attempts.push_back(attempt.clone());
        history.total_attempts += 1;
        history.last_attempt = attempt.timestamp;

        // Calcular métricas únicas
        let mut unique_ips = std::collections::HashSet::new();
        let mut unique_users = std::collections::HashSet::new();

        for att in &history.attempts {
            unique_ips.insert(&att.source_ip);
            if let Some(user) = &att.username {
                unique_users.insert(user);
            }
        }

        history.unique_ips = unique_ips.len() as u32;
        history.unique_users = unique_users.len() as u32;

        // Calcular pico de intentos por minuto
        let now = Utc::now();
        let one_minute_ago = now - Duration::minutes(1);
        let recent_attempts = history.attempts.iter()
            .filter(|att| att.timestamp > one_minute_ago)
            .count() as u32;

        if recent_attempts > history.peak_attempts_per_minute {
            history.peak_attempts_per_minute = recent_attempts;
        }
    }

    /// Analiza comportamiento por IP
    fn analyze_ip_behavior(&self, source_ip: &str) -> Result<IpAnalysis> {
        let ip_tracking = self.ip_tracking.read().unwrap();
        let history = ip_tracking.get(source_ip).cloned().unwrap_or_else(|| {
            IpAttemptHistory {
                attempts: VecDeque::new(),
                total_attempts: 0,
                failed_attempts: 0,
                successful_attempts: 0,
                first_attempt: Utc::now(),
                last_attempt: Utc::now(),
                is_blocked: false,
                block_until: None,
                services_attacked: HashMap::new(),
                user_agents: HashMap::new(),
            }
        });

        let failure_rate = if history.total_attempts > 0 {
            history.failed_attempts as f64 / history.total_attempts as f64
        } else {
            0.0
        };

        let time_span = history.last_attempt.signed_duration_since(history.first_attempt);
        let time_span_minutes = time_span.num_minutes().max(1);
        let attempts_per_minute = history.total_attempts as f64 / time_span_minutes as f64;

        let services_targeted = history.services_attacked.len() as u32;
        let user_agents_used = history.user_agents.len() as u32;

        // Estimar si es un ataque distribuido
        let is_distributed = user_agents_used > 3 || services_targeted > 2;

        // Calcular reputation score (simple heurística)
        let mut reputation_score: f64 = 1.0;
        if failure_rate > 0.8 { reputation_score -= 0.4; }
        if attempts_per_minute > 5.0 { reputation_score -= 0.3; }
        if services_targeted > 3 { reputation_score -= 0.2; }
        if is_distributed { reputation_score -= 0.1; }
        reputation_score = reputation_score.max(0.0);

        Ok(IpAnalysis {
            source_ip: source_ip.to_string(),
            attempt_count: history.total_attempts,
            failure_rate,
            time_span_minutes,
            attempts_per_minute,
            services_targeted,
            users_targeted: history.attempts.iter()
                .filter_map(|a| a.username.as_ref())
                .collect::<std::collections::HashSet<_>>()
                .len() as u32,
            user_agents_used,
            is_distributed,
            geo_location: None, // Podría integrarse con servicio de geolocalización
            reputation_score,
        })
    }

    /// Analiza comportamiento por usuario
    fn analyze_user_behavior(&self, username: &str) -> Result<UserAnalysis> {
        let user_tracking = self.user_tracking.read().unwrap();
        let history = user_tracking.get(username).cloned().unwrap_or_else(|| {
            UserAttemptHistory {
                attempts: VecDeque::new(),
                total_attempts: 0,
                failed_attempts: 0,
                source_ips: HashMap::new(),
                first_attempt: Utc::now(),
                last_attempt: Utc::now(),
                password_variations: Vec::new(),
                is_compromised: false,
            }
        });

        let compromise_confidence = if history.is_compromised {
            0.9
        } else if history.failed_attempts > self.config.max_attempts_per_user {
            0.7
        } else if history.source_ips.len() > 3 {
            0.6
        } else {
            0.0
        };

        Ok(UserAnalysis {
            username: username.to_string(),
            attempt_count: history.total_attempts,
            source_ips: history.source_ips.len() as u32,
            password_variations: history.password_variations.len() as u32,
            is_likely_compromised: history.is_compromised,
            compromise_confidence,
        })
    }

    /// Analiza comportamiento por servicio
    fn analyze_service_behavior(&self, service: &str) -> Result<ServiceAnalysis> {
        let service_tracking = self.service_tracking.read().unwrap();
        let history = service_tracking.get(service).cloned().unwrap_or_else(|| {
            ServiceAttemptHistory {
                attempts: VecDeque::new(),
                total_attempts: 0,
                unique_ips: 0,
                unique_users: 0,
                peak_attempts_per_minute: 0,
                first_attempt: Utc::now(),
                last_attempt: Utc::now(),
            }
        });

        let time_span = history.last_attempt.signed_duration_since(history.first_attempt);
        let attack_duration_minutes = time_span.num_minutes().max(1);

        let is_under_attack = history.peak_attempts_per_minute > 10 ||
            history.unique_ips > 5 ||
            history.total_attempts > 50;

        Ok(ServiceAnalysis {
            service_name: service.to_string(),
            total_attempts: history.total_attempts,
            unique_attackers: history.unique_ips,
            attack_duration_minutes,
            peak_rate_per_minute: history.peak_attempts_per_minute,
            is_under_attack,
        })
    }

    /// Genera indicadores de ataque
    fn generate_attack_indicators(&self, ip_analysis: &IpAnalysis, user_analysis: &Option<UserAnalysis>, service_analysis: &ServiceAnalysis) -> Vec<AttackIndicator> {
        let mut indicators = Vec::new();

        // Indicadores basados en IP
        if ip_analysis.failure_rate > 0.8 {
            indicators.push(AttackIndicator {
                indicator_type: "high_failure_rate".to_string(),
                description: format!("IP {} has {:.1}% failure rate", ip_analysis.source_ip, ip_analysis.failure_rate * 100.0),
                severity: RiskLevel::High,
                confidence: 0.9,
            });
        }

        if ip_analysis.attempts_per_minute > 5.0 {
            indicators.push(AttackIndicator {
                indicator_type: "high_attempt_rate".to_string(),
                description: format!("IP {} attempting {:.1} times per minute", ip_analysis.source_ip, ip_analysis.attempts_per_minute),
                severity: RiskLevel::Medium,
                confidence: 0.8,
            });
        }

        if ip_analysis.services_targeted > 2 {
            indicators.push(AttackIndicator {
                indicator_type: "multiple_services".to_string(),
                description: format!("IP {} targeting {} different services", ip_analysis.source_ip, ip_analysis.services_targeted),
                severity: RiskLevel::High,
                confidence: 0.7,
            });
        }

        if ip_analysis.reputation_score < 0.3 {
            indicators.push(AttackIndicator {
                indicator_type: "low_reputation".to_string(),
                description: format!("IP {} has low reputation score: {:.2}", ip_analysis.source_ip, ip_analysis.reputation_score),
                severity: RiskLevel::Critical,
                confidence: 0.8,
            });
        }

        // Indicadores basados en usuario
        if let Some(user_analysis) = user_analysis {
            if user_analysis.is_likely_compromised {
                indicators.push(AttackIndicator {
                    indicator_type: "account_compromise".to_string(),
                    description: format!("User {} likely compromised", user_analysis.username),
                    severity: RiskLevel::Critical,
                    confidence: user_analysis.compromise_confidence,
                });
            }

            if user_analysis.source_ips > 3 {
                indicators.push(AttackIndicator {
                    indicator_type: "multiple_source_ips".to_string(),
                    description: format!("User {} accessed from {} different IPs", user_analysis.username, user_analysis.source_ips),
                    severity: RiskLevel::Medium,
                    confidence: 0.7,
                });
            }
        }

        // Indicadores basados en servicio
        if service_analysis.is_under_attack {
            indicators.push(AttackIndicator {
                indicator_type: "service_under_attack".to_string(),
                description: format!("Service {} under brute force attack", service_analysis.service_name),
                severity: RiskLevel::High,
                confidence: 0.9,
            });
        }

        if service_analysis.peak_rate_per_minute > 20 {
            indicators.push(AttackIndicator {
                indicator_type: "ddos_like_pattern".to_string(),
                description: format!("Service {} experiencing {} attempts per minute", service_analysis.service_name, service_analysis.peak_rate_per_minute),
                severity: RiskLevel::Critical,
                confidence: 0.8,
            });
        }

        indicators
    }

    /// Calcula el score de confianza general
    fn calculate_confidence_score(&self, ip_analysis: &IpAnalysis, user_analysis: &Option<UserAnalysis>, service_analysis: &ServiceAnalysis, indicators: &[AttackIndicator]) -> f64 {
        let mut score = 0.0;
        let mut factors = 0;

        // Factor de tasa de fallos
        score += ip_analysis.failure_rate * 0.3;
        factors += 1;

        // Factor de frecuencia de intentos
        let attempt_rate_factor = (ip_analysis.attempts_per_minute / 10.0).min(1.0) * 0.25;
        score += attempt_rate_factor;
        factors += 1;

        // Factor de servicios múltiples
        if ip_analysis.services_targeted > 1 {
            score += 0.2;
            factors += 1;
        }

        // Factor de reputación
        score += (1.0 - ip_analysis.reputation_score) * 0.15;
        factors += 1;

        // Factor de usuario comprometido
        if let Some(user_analysis) = user_analysis {
            if user_analysis.is_likely_compromised {
                score += user_analysis.compromise_confidence * 0.3;
                factors += 1;
            }
        }

        // Factor de servicio bajo ataque
        if service_analysis.is_under_attack {
            score += 0.25;
            factors += 1;
        }

        // Factor de indicadores críticos
        let critical_indicators = indicators.iter()
            .filter(|i| i.severity == RiskLevel::Critical)
            .count();

        if critical_indicators > 0 {
            score += (critical_indicators as f64 * 0.1).min(0.3);
            factors += 1;
        }

        // Promedio ponderado
        if factors > 0 {
            (score / factors as f64).min(1.0)
        } else {
            0.0
        }
    }

    /// Determina el nivel de riesgo
    fn determine_risk_level(&self, confidence_score: f64, ip_analysis: &IpAnalysis, indicators: &[AttackIndicator]) -> RiskLevel {
        // Verificar indicadores críticos
        let critical_count = indicators.iter()
            .filter(|i| i.severity == RiskLevel::Critical)
            .count();

        if critical_count > 0 || confidence_score >= 0.9 {
            return RiskLevel::Critical;
        }

        let high_count = indicators.iter()
            .filter(|i| i.severity == RiskLevel::High)
            .count();

        if high_count > 1 || confidence_score >= 0.7 {
            return RiskLevel::High;
        }

        // Factores específicos de alto riesgo
        if ip_analysis.attempt_count >= self.config.max_attempts_per_ip ||
            ip_analysis.attempts_per_minute > 10.0 ||
            ip_analysis.services_targeted > 3 {
            return RiskLevel::High;
        }

        if confidence_score >= 0.4 || ip_analysis.failure_rate > 0.7 {
            return RiskLevel::Medium;
        }

        RiskLevel::Low
    }

    /// Genera sugerencias de mitigación
    fn generate_mitigation_suggestions(&self, attack_types: &[BruteForceType], ip_analysis: &IpAnalysis, service_analysis: &ServiceAnalysis) -> Vec<String> {
        let mut suggestions = Vec::new();

        // Sugerencias generales
        suggestions.push("Implementar rate limiting por IP y usuario".to_string());
        suggestions.push("Configurar account lockout después de intentos fallidos".to_string());
        suggestions.push("Implementar CAPTCHA después de múltiples fallos".to_string());
        suggestions.push("Usar autenticación multi-factor (MFA)".to_string());
        suggestions.push("Monitorear y alertar sobre patrones de fuerza bruta".to_string());

        // Sugerencias específicas por tipo de ataque
        for attack_type in attack_types {
            match attack_type {
                BruteForceType::Authentication => {
                    suggestions.push("Implementar progressive delays en login".to_string());
                    suggestions.push("Usar políticas de contraseñas fuertes".to_string());
                    suggestions.push("Implementar detección de credenciales comprometidas".to_string());
                },
                BruteForceType::Directory => {
                    suggestions.push("Ocultar directorios sensibles del público".to_string());
                    suggestions.push("Implementar autenticación para directorios administrativos".to_string());
                    suggestions.push("Usar custom error pages para ocultar estructura".to_string());
                },
                BruteForceType::Api => {
                    suggestions.push("Implementar API rate limiting estricto".to_string());
                    suggestions.push("Usar API keys con rotación automática".to_string());
                    suggestions.push("Implementar OAuth 2.0 con refresh tokens".to_string());
                },
                BruteForceType::Database => {
                    suggestions.push("Configurar account lockout en base de datos".to_string());
                    suggestions.push("Usar conexiones cifradas para DB".to_string());
                    suggestions.push("Implementar auditoría de acceso a DB".to_string());
                },
                _ => {}
            }
        }

        // Sugerencias basadas en análisis de IP
        if ip_analysis.attempt_count >= self.config.max_attempts_per_ip {
            suggestions.push(format!("Bloquear IP {} inmediatamente", ip_analysis.source_ip));
        }

        if ip_analysis.services_targeted > 2 {
            suggestions.push("Implementar correlación de eventos entre servicios".to_string());
            suggestions.push("Configurar alertas para ataques multi-servicio".to_string());
        }

        if ip_analysis.reputation_score < 0.3 {
            suggestions.push("Consultar listas de reputación de IPs".to_string());
            suggestions.push("Implementar geo-blocking para regiones de alto riesgo".to_string());
        }

        // Sugerencias basadas en análisis de servicio
        if service_analysis.is_under_attack {
            suggestions.push(format!("Activar modo de protección para servicio {}", service_analysis.service_name));
            suggestions.push("Implementar failover automático si disponible".to_string());
        }

        if service_analysis.peak_rate_per_minute > 20 {
            suggestions.push("Implementar DDoS protection/CDN".to_string());
            suggestions.push("Configurar circuit breakers para protección".to_string());
        }

        suggestions.sort();
        suggestions.dedup();
        suggestions
    }

    /// Obtiene estadísticas del detector
    pub fn get_statistics(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();

        let ip_tracking = self.ip_tracking.read().unwrap();
        let user_tracking = self.user_tracking.read().unwrap();
        let service_tracking = self.service_tracking.read().unwrap();

        stats.insert("total_monitored_ips".to_string(), serde_json::Value::Number(ip_tracking.len().into()));
        stats.insert("total_monitored_users".to_string(), serde_json::Value::Number(user_tracking.len().into()));
        stats.insert("total_monitored_services".to_string(), serde_json::Value::Number(service_tracking.len().into()));

        // Estadísticas de IPs
        let blocked_ips = ip_tracking.values()
            .filter(|h| h.is_blocked)
            .count();
        stats.insert("blocked_ips".to_string(), serde_json::Value::Number(blocked_ips.into()));

        let high_risk_ips = ip_tracking.values()
            .filter(|h| h.failed_attempts >= self.config.max_attempts_per_ip / 2)
            .count();
        stats.insert("high_risk_ips".to_string(), serde_json::Value::Number(high_risk_ips.into()));

        // Estadísticas de usuarios
        let compromised_users = user_tracking.values()
            .filter(|h| h.is_compromised)
            .count();
        stats.insert("compromised_users".to_string(), serde_json::Value::Number(compromised_users.into()));

        // Estadísticas de servicios
        let services_under_attack = service_tracking.values()
            .filter(|h| h.peak_attempts_per_minute > 10)
            .count();
        stats.insert("services_under_attack".to_string(), serde_json::Value::Number(services_under_attack.into()));

        // Top IPs atacantes
        let mut top_ips: Vec<_> = ip_tracking.iter()
            .map(|(ip, history)| (ip.clone(), history.total_attempts))
            .collect();
        top_ips.sort_by(|a, b| b.1.cmp(&a.1));
        top_ips.truncate(10);

        let top_ips_json: Vec<serde_json::Value> = top_ips.into_iter()
            .map(|(ip, attempts)| serde_json::json!({
               "ip": ip,
               "attempts": attempts
           }))
            .collect();
        stats.insert("top_attacking_ips".to_string(), serde_json::Value::Array(top_ips_json));

        stats
    }

    /// Limpia historiales antiguos para liberar memoria
    pub fn cleanup_old_records(&self) {
        let cutoff_time = Utc::now() - Duration::hours(24); // Limpiar registros de más de 24 horas

        // Limpiar tracking de IPs
        let mut ip_tracking = self.ip_tracking.write().unwrap();
        ip_tracking.retain(|_, history| {
            history.last_attempt > cutoff_time
        });

        // Limpiar tracking de usuarios
        let mut user_tracking = self.user_tracking.write().unwrap();
        user_tracking.retain(|_, history| {
            history.last_attempt > cutoff_time
        });

        // Limpiar tracking de servicios
        let mut service_tracking = self.service_tracking.write().unwrap();
        service_tracking.retain(|_, history| {
            history.last_attempt > cutoff_time
        });
    }

    /// Verifica si una IP está actualmente bloqueada
    pub fn is_ip_blocked(&self, source_ip: &str) -> bool {
        let ip_tracking = self.ip_tracking.read().unwrap();
        if let Some(history) = ip_tracking.get(source_ip) {
            if history.is_blocked {
                if let Some(block_until) = history.block_until {
                    return Utc::now() < block_until;
                }
                return true;
            }
        }
        false
    }

    /// Desbloquea manualmente una IP
    pub fn unblock_ip(&self, source_ip: &str) -> bool {
        let mut ip_tracking = self.ip_tracking.write().unwrap();
        if let Some(history) = ip_tracking.get_mut(source_ip) {
            history.is_blocked = false;
            history.block_until = None;
            return true;
        }
        false
    }

    /// Exporta datos de tracking para análisis externo
    pub fn export_tracking_data(&self) -> serde_json::Value {
        let ip_tracking = self.ip_tracking.read().unwrap();
        let user_tracking = self.user_tracking.read().unwrap();
        let service_tracking = self.service_tracking.read().unwrap();

        serde_json::json!({
           "export_timestamp": Utc::now(),
           "ip_tracking_count": ip_tracking.len(),
           "user_tracking_count": user_tracking.len(),
           "service_tracking_count": service_tracking.len(),
           "config": self.config
       })
    }
}

impl Default for BruteForceDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Utilidades adicionales para análisis de fuerza bruta
pub mod utils {
    use super::*;

    /// Calcula entropía de contraseñas intentadas
    pub fn calculate_password_entropy(passwords: &[String]) -> f64 {
        if passwords.is_empty() {
            return 0.0;
        }

        let mut char_counts: HashMap<char, usize> = HashMap::new();
        let mut total_chars = 0;

        for password in passwords {
            for ch in password.chars() {
                *char_counts.entry(ch).or_insert(0) += 1;
                total_chars += 1;
            }
        }

        if total_chars == 0 {
            return 0.0;
        }

        let mut entropy = 0.0;
        for &count in char_counts.values() {
            let probability = count as f64 / total_chars as f64;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    /// Detecta patrones en nombres de usuario atacados
    pub fn analyze_username_patterns(usernames: &[String]) -> Vec<String> {
        let mut patterns = Vec::new();

        // Detectar usernames comunes
        let common_usernames = ["admin", "administrator", "root", "user", "test", "guest"];
        for common in &common_usernames {
            if usernames.iter().any(|u| u.to_lowercase().contains(common)) {
                patterns.push(format!("common_username_{}", common));
            }
        }

        // Detectar patrones secuenciales
        let mut sorted_usernames = usernames.to_vec();
        sorted_usernames.sort();

        for window in sorted_usernames.windows(3) {
            if window[0].len() == window[1].len() && window[1].len() == window[2].len() {
                if let (Ok(n1), Ok(n2), Ok(n3)) = (
                    window[0].parse::<i32>(),
                    window[1].parse::<i32>(),
                    window[2].parse::<i32>()
                ) {
                    if n2 == n1 + 1 && n3 == n2 + 1 {
                        patterns.push("sequential_numeric_usernames".to_string());
                        break;
                    }
                }
            }
        }

        patterns
    }

    /// Calcula score de sofisticación del ataque
    pub fn calculate_attack_sophistication(ip_analysis: &IpAnalysis, indicators: &[AttackIndicator]) -> f64 {
        let mut sophistication: f64 = 0.0;

        // Factores que aumentan sofisticación
        if ip_analysis.user_agents_used > 3 {
            sophistication += 0.2; // Rotating user agents
        }

        if ip_analysis.services_targeted > 2 {
            sophistication += 0.3; // Multi-service attack
        }

        if ip_analysis.attempts_per_minute < 2.0 && ip_analysis.attempt_count > 20 {
            sophistication += 0.2; // Slow and persistent
        }

        let critical_indicators = indicators.iter()
            .filter(|i| i.severity == RiskLevel::Critical)
            .count();

        if critical_indicators > 2 {
            sophistication += 0.3; // Multiple attack vectors
        }

        sophistication.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_brute_force_detection() {
        let detector = BruteForceDetector::new();
        let now = Utc::now();

        // Simular múltiples intentos fallidos
        for i in 0..5 {
            let result = detector.analyze_event(
                "192.168.1.100",
                Some("admin"),
                "web_login",
                "Authentication failed for user admin",
                Some("Mozilla/5.0"),
                Some(401),
                now + Duration::seconds(i * 10)
            ).unwrap();

            if i == 4 { // Último intento debería ser detectado
                assert!(result.is_detected);
                assert!(result.confidence_score > 0.5);
            }
        }
    }

    #[test]
    fn test_successful_login_after_failures() {
        let detector = BruteForceDetector::new();
        let now = Utc::now();

        // Intentos fallidos
        for i in 0..3 {
            detector.analyze_event(
                "192.168.1.100",
                Some("testuser"),
                "web_login",
                "Invalid password",
                Some("curl/7.0"),
                Some(401),
                now + Duration::seconds(i * 5)
            ).unwrap();
        }

        // Intento exitoso
        let result = detector.analyze_event(
            "192.168.1.100",
            Some("testuser"),
            "web_login",
            "Login successful",
            Some("curl/7.0"),
            Some(200),
            now + Duration::seconds(20)
        ).unwrap();

        assert!(result.is_detected);
        if let Some(user_analysis) = &result.user_analysis {
            assert!(user_analysis.is_likely_compromised);
        }
    }

    #[test]
    fn test_multi_service_attack() {
        let detector = BruteForceDetector::new();
        let now = Utc::now();

        let services = ["ssh", "ftp", "web_login"];

        for (i, service) in services.iter().enumerate() {
            detector.analyze_event(
                "10.0.0.50",
                Some("root"),
                service,
                "Authentication failed",
                Some("python-requests/2.0"),
                None,
                now + Duration::seconds(i as i64 * 30)
            ).unwrap();
        }

        let result = detector.analyze_event(
            "10.0.0.50",
            Some("admin"),
            "database",
            "Login failed",
            Some("python-requests/2.0"),
            None,
            now + Duration::seconds(120)
        ).unwrap();

        assert!(result.is_detected);
        assert!(result.ip_analysis.services_targeted >= 3);
        assert_eq!(result.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_ip_blocking() {
        let detector = BruteForceDetector::new();
        let now = Utc::now();

        // Superar el límite de intentos
        for i in 0..15 {
            detector.analyze_event(
                "192.168.1.200",
                Some("user"),
                "web",
                "Login failed",
                None,
                Some(403),
                now + Duration::seconds(i * 2)
            ).unwrap();
        }

        assert!(detector.is_ip_blocked("192.168.1.200"));

        // Desbloquear manualmente
        assert!(detector.unblock_ip("192.168.1.200"));
        assert!(!detector.is_ip_blocked("192.168.1.200"));
    }

    #[test]
    fn test_statistics_generation() {
        let detector = BruteForceDetector::new();
        let now = Utc::now();

        // Generar algunos eventos
        detector.analyze_event(
            "192.168.1.100",
            Some("admin"),
            "web",
            "Failed login",
            None,
            Some(401),
            now
        ).unwrap();

        let stats = detector.get_statistics();

        assert!(stats.contains_key("total_monitored_ips"));
        assert!(stats.contains_key("total_monitored_users"));
        assert!(stats.contains_key("total_monitored_services"));
    }

    #[test]
    fn test_password_entropy_calculation() {
        let passwords = vec![
            "password123".to_string(),
            "admin".to_string(),
            "12345".to_string(),
            "qwerty".to_string(),
        ];

        let entropy = utils::calculate_password_entropy(&passwords);
        assert!(entropy > 0.0);
    }

    #[test]
    fn test_username_pattern_detection() {
        let usernames = vec![
            "admin".to_string(),
            "administrator".to_string(),
            "root".to_string(),
            "user1".to_string(),
            "user2".to_string(),
            "user3".to_string(),
        ];

        let patterns = utils::analyze_username_patterns(&usernames);
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains("common_username")));
    }
}