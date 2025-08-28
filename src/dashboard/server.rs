use crate::{storage::StorageManager, detector::DetectorEngine, Severity};
use anyhow::Result;
use std::sync::Arc;
use warp::Filter;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};


#[derive(Clone)]
pub struct DashboardServer {
    storage: Arc<StorageManager>,
    detector: Arc<DetectorEngine>,
    port: u16,
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub limit: Option<usize>,
    pub severity: Option<Severity>,
    pub source: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
    pub message: Option<String>,
}

impl DashboardServer {
    pub async fn new(
        storage: Arc<StorageManager>,
        detector: Arc<DetectorEngine>,
        port: u16,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            detector,
            port,
        })
    }

    pub fn serve(&self) -> Result<()> {
        // Ruta para archivos estáticos (CSS, JS)
        let static_files = warp::path("static")
            .and(warp::fs::dir("src/dashboard/static"));

        // Ruta para el favicon
        let favicon = warp::path("favicon.ico")
            .map(|| {
                warp::reply::with_header(
                    warp::reply::with_status("", warp::http::StatusCode::NOT_FOUND),
                    "content-type",
                    "image/x-icon"
                )
            });

        // API endpoint para estadísticas del dashboard
        let stats = warp::path("api")
            .and(warp::path("stats"))
            .and(warp::get())
            .map(move || {
                // Datos simulados mejorados para coincidir con el frontend
                let response = ApiResponse {
                    success: true,
                    data: serde_json::json!({
                        "events_per_second": 2.85 + (rand::random::<f64>() * 2.0),
                        "critical_alerts": 3,
                        "warning_alerts": 7,
                        "info_alerts": 15,
                        "threat_score": 7.3,
                        "active_sources": 12,
                        "uptime_seconds": 86400 + (rand::random::<u64>() % 3600),
                        "detection_rate": 94.5,
                        "false_positive_rate": 2.1,
                        "total_events": 125847 + (rand::random::<u64>() % 1000)
                    }),
                    message: None,
                };
                warp::reply::json(&response)
            });

        // API endpoint para obtener eventos
        let events = warp::path("api")
            .and(warp::path("events"))
            .and(warp::get())
            .and(warp::query::<EventsQuery>())
            .map(move |query: EventsQuery| {
                // Generar eventos simulados basados en el query
                let limit = query.limit.unwrap_or(50);
                let events: Vec<serde_json::Value> = (0..std::cmp::min(limit, 100))
                    .map(|i| {
                        let severities = ["critical", "high", "medium", "low", "info"];
                        let sources = ["Apache", "Nginx", "SSH", "MySQL", "Firewall"];
                        let event_types = ["HTTP Request", "Login Attempt", "File Access", "SQL Query", "Network Connection"];

                        let now = chrono::Utc::now();
                        let timestamp = now - chrono::Duration::minutes(i as i64 * 5);

                        serde_json::json!({
                            "id": format!("event-{}", i + 1),
                            "timestamp": timestamp.to_rfc3339(),
                            "severity": severities[i % severities.len()],
                            "source": sources[i % sources.len()],
                            "event_type": event_types[i % event_types.len()],
                            "description": format!("Simulated security event #{}", i + 1),
                            "source_ip": format!("192.168.{}.{}",
                                (i % 255) + 1,
                                ((i * 7) % 255) + 1
                            )
                        })
                    })
                    .collect();

                let response = ApiResponse {
                    success: true,
                    data: events,
                    message: None,
                };
                warp::reply::json(&response)
            });

        // API endpoint para obtener alertas activas
        let alerts = warp::path("api")
            .and(warp::path("alerts"))
            .and(warp::get())
            .map(move || {
                // Generar alertas simuladas
                let alert_types = ["SQL Injection", "XSS Attack", "Brute Force", "DDoS", "Malware"];
                let severities = ["critical", "warning", "info"];
                let statuses = ["active", "acknowledged"];

                let alerts: Vec<serde_json::Value> = (0..10)
                    .map(|i| {
                        let now = chrono::Utc::now();
                        let timestamp = now - chrono::Duration::minutes(i as i64 * 15);

                        serde_json::json!({
                            "id": format!("alert-{}", i + 1),
                            "timestamp": timestamp.to_rfc3339(),
                            "severity": severities[i % severities.len()],
                            "alert_type": alert_types[i % alert_types.len()],
                            "description": format!("Security alert #{}: {}", i + 1, alert_types[i % alert_types.len()]),
                            "status": statuses[i % statuses.len()],
                            "source_ip": format!("10.0.{}.{}",
                                (i % 255) + 1,
                                ((i * 13) % 255) + 1
                            )
                        })
                    })
                    .collect();

                let response = ApiResponse {
                    success: true,
                    data: alerts,
                    message: None,
                };
                warp::reply::json(&response)
            });

        // API endpoint para detalles de evento específico
        let event_details = warp::path("api")
            .and(warp::path("events"))
            .and(warp::path::param::<String>())
            .and(warp::get())
            .map(|event_id: String| {
                let response = ApiResponse {
                    success: true,
                    data: serde_json::json!({
                        "id": event_id,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "severity": "high",
                        "source": "Apache",
                        "event_type": "HTTP Request",
                        "description": "Detailed event information",
                        "source_ip": "192.168.1.100",
                        "details": {
                            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                            "request_uri": "/api/users/1 OR 1=1",
                            "http_method": "GET",
                            "response_code": 200,
                            "payload_size": 1024
                        }
                    }),
                    message: None,
                };
                warp::reply::json(&response)
            });

        // API endpoint educativo para detalles extendidos del evento
        let event_educational_details = warp::path("api")
            .and(warp::path("events"))
            .and(warp::path::param::<String>())
            .and(warp::path("educational"))
            .and(warp::get())
            .map(|event_id: String| {
                // Extraer el número del event_id (ej: "event-1" -> 1)
                let event_number: usize = event_id
                    .strip_prefix("event-")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                
                // Usar los MISMOS datos que el endpoint general de eventos
                let i = event_number - 1; // Convertir a índice (0-based)
                let severities = ["critical", "high", "medium", "low", "info"];
                let sources = ["Apache", "Nginx", "SSH", "MySQL", "Firewall"];
                let event_types = ["HTTP Request", "Login Attempt", "File Access", "SQL Query", "Network Connection"];
                
                let now = chrono::Utc::now();
                let timestamp = now - chrono::Duration::minutes(i as i64 * 5);
                
                let severity = severities[i % severities.len()];
                let source = sources[i % sources.len()];
                let event_type = event_types[i % event_types.len()];
                let source_ip = format!("192.168.{}.{}", (i % 255) + 1, ((i * 7) % 255) + 1);

                let data = serde_json::json!({
                    "event": {
                        "id": event_id,
                        "timestamp": timestamp.to_rfc3339(),
                        "severity": severity,
                        "source": source,
                        "event_type": event_type,
                        "description": format!("Simulated security event #{}", event_number),
                        "source_ip": source_ip,
                        "raw_message": format!("{} - - [27/Aug/2025:19:30:00 +0000] \"GET /api/endpoint HTTP/1.1\" 200 - \"Mozilla/5.0\"", source_ip)
                    },
                    "educational_context": Self::get_educational_context_for_event_type(event_type),
                    "technical_analysis": Self::get_technical_analysis_for_event_type(event_type, &source_ip),
                    "threat_intelligence": Self::get_threat_intelligence_for_event_type(event_type, severity),
                    "mitigation_guidance": Self::get_mitigation_guidance_for_event_type(event_type, severity),
                    "real_world_examples": [
                        {"title": "Brecha por SQLi en empresa X", "description": "Inyección SQL permitió acceso a datos sensibles.", "year": 2017, "impact": "Datos de clientes expuestos", "organization": "Empresa X", "source_url": "https://example.com/caso-sqli"}
                    ]
                });

                let response = ApiResponse { success: true, data, message: None };
                warp::reply::json(&response)
            });

        // Página principal del dashboard - servir el index.html actualizado
        let index = warp::path::end()
            .and(warp::get())
            .map(|| {
                // Leer el archivo index.html desde static/
                match std::fs::read_to_string("src/dashboard/static/index.html") {
                    Ok(html_content) => {
                        warp::reply::with_header(
                            warp::reply::html(html_content),
                            "Cache-Control",
                            "no-cache"
                        )
                    }
                    Err(_) => {
                        // Fallback al HTML básico si no encuentra el archivo
                        warp::reply::with_header(
                            warp::reply::html(get_fallback_html()),
                            "Cache-Control",
                            "no-cache"
                        )
                    }
                }
            });

        // Rutas para páginas específicas (opcional, para navegación directa)
        let events_page = warp::path("events")
            .and(warp::get())
            .map(|| {
                match std::fs::read_to_string("src/dashboard/static/index.html") {
                    Ok(html_content) => warp::reply::html(html_content),
                    Err(_) => warp::reply::html(get_fallback_html())
                }
            });

        let alerts_page = warp::path("alerts")
            .and(warp::get())
            .map(|| {
                match std::fs::read_to_string("src/dashboard/static/index.html") {
                    Ok(html_content) => warp::reply::html(html_content),
                    Err(_) => warp::reply::html(get_fallback_html())
                }
            });

        // WebSocket endpoint para eventos en tiempo real (opcional)
        let ws_events = warp::path("ws")
            .and(warp::path("events"))
            .and(warp::ws())
            .map(|ws: warp::ws::Ws| {
                ws.on_upgrade(|websocket| {
                    // Implementar lógica de WebSocket aquí
                    handle_websocket(websocket)
                })
            });

        // CORS headers para desarrollo
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type", "authorization"])
            .allow_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"]);

        // Combinar todas las rutas (las más específicas primero)
        let routes = index
            .or(events_page)
            .or(alerts_page)
            .or(static_files)
            .or(favicon)
            .or(stats)
            .or(event_educational_details)  // Mover antes de events y event_details
            .or(event_details)
            .or(events)
            .or(alerts)
            .or(ws_events)
            .with(cors)
            .with(warp::log("rustsiem"));

        // Logging de inicio
        tracing::info!("🛡️ RustSIEM Dashboard iniciado en http://localhost:{}", self.port);
        tracing::info!("📊 Dashboard principal: http://localhost:{}/", self.port);
        tracing::info!("📋 Página de eventos: http://localhost:{}/events", self.port);
        tracing::info!("⚠️ Página de alertas: http://localhost:{}/alerts", self.port);
        tracing::info!("🔌 API endpoints disponibles:");
        tracing::info!("   GET /api/stats - Estadísticas del sistema");
        tracing::info!("   GET /api/events - Lista de eventos");
        tracing::info!("   GET /api/events/<id> - Detalles de evento");
        tracing::info!("   GET /api/alerts - Alertas activas");
        tracing::info!("   WS /ws/events - Stream de eventos en tiempo real");

        // Iniciar servidor
        let server = warp::serve(routes)
            .run(([127, 0, 0, 1], self.port));

        tokio::spawn(server);
        Ok(())
    }
}

// Función para manejar conexiones WebSocket
async fn handle_websocket(websocket: warp::ws::WebSocket) {
    use futures::{SinkExt, StreamExt};
    use tokio::time::{interval, Duration};

    let (mut ws_tx, mut ws_rx) = websocket.split();

    // Crear un intervalo para enviar eventos simulados
    let mut interval = interval(Duration::from_secs(3));

    // Tarea para enviar eventos periódicos
    let send_task = tokio::spawn(async move {
        loop {
            interval.tick().await;

            let event = serde_json::json!({
                "type": "event",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "severity": "INFO",
                "description": "Simulated real-time event",
                "source": "WebSocket"
            });

            if let Err(_) = ws_tx.send(warp::ws::Message::text(event.to_string())).await {
                break;
            }
        }
    });

    // Tarea para manejar mensajes entrantes
    let receive_task = tokio::spawn(async move {
        while let Some(result) = ws_rx.next().await {
            match result {
                Ok(msg) => {
                    if msg.is_text() {
                        tracing::debug!("Mensaje WebSocket recibido: {:?}", msg.to_str());
                    }
                }
                Err(e) => {
                    tracing::error!("Error WebSocket: {:?}", e);
                    break;
                }
            }
        }
    });

    // Esperar a que termine cualquiera de las dos tareas
    tokio::select! {
        _ = send_task => {},
        _ = receive_task => {},
    }
}

// HTML de fallback en caso de que no se encuentren los archivos estáticos
fn get_fallback_html() -> String {
    r#"
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RustSIEM Dashboard - Setup Required</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                color: #f1f5f9;
                margin: 0;
                padding: 40px 20px;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .setup-container {
                background: rgba(30, 41, 59, 0.8);
                border-radius: 16px;
                border: 1px solid rgba(148, 163, 184, 0.2);
                backdrop-filter: blur(20px);
                padding: 40px;
                max-width: 600px;
                text-align: center;
            }
            .setup-title {
                font-size: 2.5rem;
                color: #38bdf8;
                margin-bottom: 16px;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 12px;
            }
            .setup-description {
                color: #94a3b8;
                line-height: 1.6;
                margin-bottom: 32px;
            }
            .setup-steps {
                text-align: left;
                background: rgba(15, 23, 42, 0.5);
                padding: 24px;
                border-radius: 12px;
                margin: 24px 0;
            }
            .setup-steps h3 {
                color: #38bdf8;
                margin-bottom: 16px;
            }
            .setup-steps ol {
                color: #cbd5e1;
                line-height: 1.8;
            }
            .setup-steps code {
                background: rgba(0, 0, 0, 0.3);
                padding: 2px 8px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                color: #fbbf24;
            }
            .api-info {
                background: rgba(16, 185, 129, 0.1);
                border: 1px solid rgba(16, 185, 129, 0.3);
                border-radius: 8px;
                padding: 16px;
                margin-top: 24px;
            }
            .api-link {
                color: #38bdf8;
                text-decoration: none;
                font-weight: 600;
                margin: 0 8px;
            }
            .api-link:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="setup-container">
            <h1 class="setup-title">
                🛡️ RustSIEM Dashboard
            </h1>
            <p class="setup-description">
                El dashboard está funcionando, pero necesita los archivos estáticos del frontend.
            </p>

            <div class="setup-steps">
                <h3>📝 Pasos para completar la configuración:</h3>
                <ol>
                    <li>Copia el archivo <code>index.html</code> a <code>src/dashboard/static/</code></li>
                    <li>Copia el archivo <code>style.css</code> a <code>src/dashboard/static/</code></li>
                    <li>Copia el archivo <code>script.js</code> a <code>src/dashboard/static/</code></li>
                    <li>Recarga esta página</li>
                </ol>
            </div>

            <div class="api-info">
                <strong>✅ Las APIs están funcionando:</strong><br>
                <a href="/api/stats" class="api-link">Estadísticas</a>
                <a href="/api/events" class="api-link">Eventos</a>
                <a href="/api/alerts" class="api-link">Alertas</a>
            </div>
        </div>
    </body>
    </html>
    "#.to_string()
}

impl DashboardServer {
    /// Genera contexto educativo específico para cada tipo de evento
    fn get_educational_context_for_event_type(event_type: &str) -> serde_json::Value {
        match event_type {
            "HTTP Request" => serde_json::json!({
                "attack_name": "Solicitud HTTP Sospechosa",
                "attack_description": "Una solicitud HTTP es la forma en que un navegador web o aplicación se comunica con un servidor. Si bien las solicitudes HTTP normales son legítimas, pueden ser utilizadas por atacantes para explotar vulnerabilidades web.",
                "difficulty_level": "Básico",
                "learning_objectives": [
                    "Identificar patrones anómalos en solicitudes HTTP",
                    "Comprender los componentes de una solicitud HTTP",
                    "Reconocer indicadores de ataques web comunes"
                ],
                "key_concepts": [
                    "Métodos HTTP (GET, POST, PUT, DELETE)",
                    "Headers HTTP y User-Agents",
                    "Parámetros y payload de solicitudes"
                ],
                "mitre_tactics": ["Initial Access", "Discovery"],
                "mitre_techniques": ["T1190 Exploit Public-Facing Application", "T1595 Active Scanning"]
            }),
            
            "Login Attempt" => serde_json::json!({
                "attack_name": "Intento de Inicio de Sesión",
                "attack_description": "Los intentos de inicio de sesión son normales en cualquier sistema, pero múltiples intentos fallidos pueden indicar un ataque de fuerza bruta donde el atacante intenta adivinar credenciales válidas.",
                "difficulty_level": "Intermedio",
                "learning_objectives": [
                    "Detectar patrones de fuerza bruta",
                    "Implementar controles de tasa de intentos",
                    "Configurar alertas de seguridad apropiadas"
                ],
                "key_concepts": [
                    "Autenticación y autorización",
                    "Análisis de patrones temporales",
                    "Gestión de credenciales"
                ],
                "mitre_tactics": ["Credential Access", "Initial Access"],
                "mitre_techniques": ["T1110 Brute Force", "T1078 Valid Accounts"]
            }),

            "File Access" => serde_json::json!({
                "attack_name": "Acceso a Archivos",
                "attack_description": "El acceso a archivos es una operación normal, pero puede indicar intentos de acceso no autorizado, escalamiento de privilegios o exfiltración de datos cuando ocurre en archivos sensibles.",
                "difficulty_level": "Intermedio",
                "learning_objectives": [
                    "Monitorear accesos a archivos críticos",
                    "Implementar controles de acceso granulares",
                    "Detectar patrones de exfiltración"
                ],
                "key_concepts": [
                    "Permisos de archivos y directorios",
                    "Auditoría de acceso",
                    "Principio de menor privilegio"
                ],
                "mitre_tactics": ["Collection", "Exfiltration"],
                "mitre_techniques": ["T1005 Data from Local System", "T1083 File and Directory Discovery"]
            }),

            "SQL Query" => serde_json::json!({
                "attack_name": "Consulta SQL",
                "attack_description": "Las consultas SQL son normales en aplicaciones que usan bases de datos, pero pueden ser explotadas mediante inyección SQL para acceder a datos no autorizados o manipular la base de datos.",
                "difficulty_level": "Avanzado",
                "learning_objectives": [
                    "Identificar patrones de inyección SQL",
                    "Implementar consultas preparadas",
                    "Configurar logging de consultas sospechosas"
                ],
                "key_concepts": [
                    "Sanitización de entrada",
                    "Prepared statements",
                    "Principios de least privilege en DB"
                ],
                "mitre_tactics": ["Initial Access", "Discovery"],
                "mitre_techniques": ["T1190 Exploit Public-Facing Application", "T1213 Data from Information Repositories"]
            }),

            "Network Connection" => serde_json::json!({
                "attack_name": "Conexión de Red",
                "attack_description": "Las conexiones de red son fundamentales para la comunicación, pero conexiones no autorizadas pueden indicar malware, comando y control (C2), o intentos de acceso no autorizado.",
                "difficulty_level": "Intermedio",
                "learning_objectives": [
                    "Monitorear conexiones salientes inusuales",
                    "Identificar tráfico de comando y control",
                    "Implementar segmentación de red"
                ],
                "key_concepts": [
                    "Análisis de tráfico de red",
                    "Firewalls y segmentación",
                    "Detección de beaconing"
                ],
                "mitre_tactics": ["Command and Control", "Exfiltration"],
                "mitre_techniques": ["T1071 Application Layer Protocol", "T1041 Exfiltration Over C2 Channel"]
            }),

            _ => serde_json::json!({
                "attack_name": event_type,
                "attack_description": "Evento de seguridad detectado en el sistema que requiere análisis para determinar su naturaleza y nivel de riesgo.",
                "difficulty_level": "Intermedio",
                "learning_objectives": [
                    "Analizar el contexto del evento",
                    "Evaluar el nivel de riesgo",
                    "Implementar contramedidas apropiadas"
                ],
                "key_concepts": [
                    "Análisis de logs",
                    "Correlación de eventos",
                    "Respuesta a incidentes"
                ],
                "mitre_tactics": ["Discovery", "Collection"],
                "mitre_techniques": ["T1083 File and Directory Discovery", "T1005 Data from Local System"]
            })
        }
    }

    /// Genera análisis técnico específico para cada tipo de evento
    fn get_technical_analysis_for_event_type(event_type: &str, source_ip: &str) -> serde_json::Value {
        match event_type {
            "HTTP Request" => serde_json::json!({
                "attack_vector": "Solicitud HTTP potencialmente maliciosa a través de navegador web o herramientas automatizadas",
                "payload_analysis": {
                    "payload_explanation": "La solicitud HTTP puede contener parámetros maliciosos, headers manipulados o patrones de reconocimiento.",
                    "malicious_indicators": [
                        "Patrones de inyección en parámetros",
                        "User-Agents anómalos o automatizados",
                        "Headers de solicitud inusuales"
                    ],
                    "obfuscation_techniques": ["URL encoding", "Double encoding", "Unicode normalization"]
                },
                "vulnerability_details": {
                    "cve_id": "CWE-20",
                    "cvss_score": 6.5,
                    "description": "Validación inadecuada de entrada en aplicación web",
                    "exploit_complexity": "Media",
                    "affected_components": ["Aplicación web", "Servidor HTTP"]
                },
                "iocs": [
                    {"ioc_type": "IP", "value": source_ip, "confidence": "Medium", "description": "Origen de solicitud HTTP sospechosa"},
                    {"ioc_type": "URL", "value": "/api/endpoint", "confidence": "Low", "description": "Endpoint accedido"}
                ],
                "detection_rules": [
                    {"rule_name": "Suspicious HTTP Pattern", "description": "Detecta patrones HTTP anómalos", "confidence": 0.75, "false_positive_rate": "Media"},
                    {"rule_name": "Web Scanner Detection", "description": "Identifica herramientas de escaneo web", "confidence": 0.68, "false_positive_rate": "Baja"}
                ]
            }),

            "Login Attempt" => serde_json::json!({
                "attack_vector": "Intento de autenticación a través de formularios web o APIs",
                "payload_analysis": {
                    "payload_explanation": "Credenciales proporcionadas para autenticación que pueden ser parte de un ataque de fuerza bruta.",
                    "malicious_indicators": [
                        "Múltiples intentos fallidos",
                        "Patrones de nombres de usuario comunes",
                        "Velocidad de intentos anormalmente alta"
                    ],
                    "obfuscation_techniques": ["Credential stuffing", "Password spraying", "Rate limiting evasion"]
                },
                "vulnerability_details": {
                    "cve_id": "CWE-307",
                    "cvss_score": 5.3,
                    "description": "Ausencia de protección contra fuerza bruta",
                    "exploit_complexity": "Baja",
                    "affected_components": ["Sistema de autenticación", "Base de datos de usuarios"]
                },
                "iocs": [
                    {"ioc_type": "IP", "value": source_ip, "confidence": "High", "description": "Origen de múltiples intentos de login"},
                    {"ioc_type": "Pattern", "value": "failed_login", "confidence": "High", "description": "Patrón de intentos fallidos"}
                ],
                "detection_rules": [
                    {"rule_name": "Brute Force Detection", "description": "Detecta múltiples intentos de login", "confidence": 0.85, "false_positive_rate": "Baja"},
                    {"rule_name": "Credential Stuffing", "description": "Identifica uso de credenciales comprometidas", "confidence": 0.72, "false_positive_rate": "Media"}
                ]
            }),

            "File Access" => serde_json::json!({
                "attack_vector": "Acceso a sistema de archivos a través de aplicación o protocolo de red",
                "payload_analysis": {
                    "payload_explanation": "Operación de lectura/escritura en archivos que puede indicar exfiltración o modificación no autorizada.",
                    "malicious_indicators": [
                        "Acceso a archivos sensibles",
                        "Patrones de traversal de directorios",
                        "Operaciones de archivos masivas"
                    ],
                    "obfuscation_techniques": ["Path traversal", "Symlink exploitation", "NTFS alternate data streams"]
                },
                "vulnerability_details": {
                    "cve_id": "CWE-22",
                    "cvss_score": 7.2,
                    "description": "Traversal de rutas permite acceso no autorizado a archivos",
                    "exploit_complexity": "Media",
                    "affected_components": ["Sistema de archivos", "Controles de acceso"]
                },
                "iocs": [
                    {"ioc_type": "IP", "value": source_ip, "confidence": "Medium", "description": "Origen de acceso a archivos"},
                    {"ioc_type": "File", "value": "/sensitive/data", "confidence": "High", "description": "Archivo sensible accedido"}
                ],
                "detection_rules": [
                    {"rule_name": "File Access Monitoring", "description": "Monitorea acceso a archivos críticos", "confidence": 0.78, "false_positive_rate": "Media"},
                    {"rule_name": "Directory Traversal", "description": "Detecta intentos de traversal", "confidence": 0.82, "false_positive_rate": "Baja"}
                ]
            }),

            "SQL Query" => serde_json::json!({
                "attack_vector": "Consulta a base de datos a través de aplicación web o acceso directo",
                "payload_analysis": {
                    "payload_explanation": "Consulta SQL que puede contener código malicioso para extraer o manipular datos de la base de datos.",
                    "malicious_indicators": [
                        "Uso de UNION SELECT",
                        "Comentarios SQL (-- o /*)",
                        "Funciones del sistema de DB"
                    ],
                    "obfuscation_techniques": ["SQL encoding", "Case alternation", "Whitespace manipulation"]
                },
                "vulnerability_details": {
                    "cve_id": "CWE-89",
                    "cvss_score": 9.1,
                    "description": "Inyección SQL permite manipulación de base de datos",
                    "exploit_complexity": "Baja",
                    "affected_components": ["Base de datos", "Capa de aplicación"]
                },
                "iocs": [
                    {"ioc_type": "IP", "value": source_ip, "confidence": "High", "description": "Origen de inyección SQL"},
                    {"ioc_type": "Query", "value": "UNION SELECT", "confidence": "High", "description": "Patrón de inyección detectado"}
                ],
                "detection_rules": [
                    {"rule_name": "SQL Injection Detection", "description": "Detecta patrones de inyección SQL", "confidence": 0.92, "false_positive_rate": "Baja"},
                    {"rule_name": "Database Enumeration", "description": "Identifica intentos de enumeración", "confidence": 0.76, "false_positive_rate": "Media"}
                ]
            }),

            "Network Connection" => serde_json::json!({
                "attack_vector": "Conexión de red entrante o saliente no autorizada",
                "payload_analysis": {
                    "payload_explanation": "Tráfico de red que puede indicar comunicación con servidores de comando y control o exfiltración de datos.",
                    "malicious_indicators": [
                        "Conexiones a IPs sospechosas",
                        "Tráfico cifrado inusual",
                        "Patrones de beaconing regulares"
                    ],
                    "obfuscation_techniques": ["Domain fronting", "DNS tunneling", "Traffic encryption"]
                },
                "vulnerability_details": {
                    "cve_id": "CWE-200",
                    "cvss_score": 6.8,
                    "description": "Exposición de información a través de conexiones no controladas",
                    "exploit_complexity": "Media",
                    "affected_components": ["Firewall", "Segmentación de red"]
                },
                "iocs": [
                    {"ioc_type": "IP", "value": source_ip, "confidence": "High", "description": "IP de origen de conexión sospechosa"},
                    {"ioc_type": "Domain", "value": "suspicious-domain.com", "confidence": "Medium", "description": "Dominio de destino sospechoso"}
                ],
                "detection_rules": [
                    {"rule_name": "Suspicious Network Connection", "description": "Detecta conexiones anómalas", "confidence": 0.73, "false_positive_rate": "Media"},
                    {"rule_name": "C2 Beaconing", "description": "Identifica patrones de beaconing", "confidence": 0.81, "false_positive_rate": "Baja"}
                ]
            }),

            _ => serde_json::json!({
                "attack_vector": "Vector de ataque no clasificado que requiere análisis manual",
                "payload_analysis": {
                    "payload_explanation": "El evento detectado contiene indicadores que requieren análisis para determinar su naturaleza maliciosa.",
                    "malicious_indicators": [
                        "Comportamiento anómalo detectado",
                        "Patrón no reconocido",
                        "Actividad fuera de horarios normales"
                    ],
                    "obfuscation_techniques": ["Técnicas no identificadas"]
                },
                "vulnerability_details": {
                    "cve_id": "CWE-200",
                    "cvss_score": 5.0,
                    "description": "Evento de seguridad que requiere clasificación",
                    "exploit_complexity": "Desconocida",
                    "affected_components": ["Sistema general"]
                },
                "iocs": [
                    {"ioc_type": "IP", "value": source_ip, "confidence": "Medium", "description": "Origen del evento"}
                ],
                "detection_rules": [
                    {"rule_name": "Generic Event Detection", "description": "Detecta eventos no clasificados", "confidence": 0.60, "false_positive_rate": "Alta"}
                ]
            })
        }
    }

    /// Genera inteligencia de amenazas específica para cada tipo de evento
    fn get_threat_intelligence_for_event_type(event_type: &str, severity: &str) -> serde_json::Value {
        let threat_level = match severity {
            "critical" => "CRITICAL",
            "high" => "HIGH", 
            "medium" => "MEDIUM",
            "low" => "LOW",
            _ => "INFO"
        };

        match event_type {
            "HTTP Request" => serde_json::json!({
                "threat_level": threat_level,
                "origin_country": "Global",
                "common_attack_patterns": [
                    "Escaneo de vulnerabilidades web",
                    "Reconocimiento de aplicaciones",
                    "Ataques automatizados"
                ],
                "geographic_context": {
                    "country": "Global",
                    "country_code": "GL",
                    "risk_assessment": "Actividad común de reconocimiento web observada globalmente",
                    "typical_attack_types": ["Web Scanning", "Directory Brute Force", "Technology Detection"],
                    "known_apt_groups": ["Script Kiddies", "Automated Scanners"]
                }
            }),
            
            "Login Attempt" => serde_json::json!({
                "threat_level": threat_level,
                "origin_country": "Unknown",
                "common_attack_patterns": [
                    "Fuerza bruta de credenciales",
                    "Credential stuffing",
                    "Password spraying"
                ],
                "geographic_context": {
                    "country": "Global", 
                    "country_code": "GL",
                    "risk_assessment": "Ataques de fuerza bruta son comunes desde botnets distribuidas",
                    "typical_attack_types": ["Brute Force", "Credential Stuffing", "Account Takeover"],
                    "known_apt_groups": ["Cybercriminal groups", "APT1", "FIN7"]
                }
            }),

            "File Access" => serde_json::json!({
                "threat_level": threat_level,
                "origin_country": "Internal/External",
                "common_attack_patterns": [
                    "Exfiltración de datos",
                    "Escalamiento de privilegios",
                    "Reconnaissance interno"
                ],
                "geographic_context": {
                    "country": "Mixed",
                    "country_code": "XX",
                    "risk_assessment": "Acceso a archivos puede ser interno o externo, requiere análisis contextual",
                    "typical_attack_types": ["Data Exfiltration", "Privilege Escalation", "Lateral Movement"],
                    "known_apt_groups": ["APT28", "Carbanak", "Lazarus"]
                }
            }),

            "SQL Query" => serde_json::json!({
                "threat_level": threat_level,
                "origin_country": "Global",
                "common_attack_patterns": [
                    "Inyección SQL",
                    "Enumeración de base de datos",
                    "Extracción de esquemas"
                ],
                "geographic_context": {
                    "country": "Global",
                    "country_code": "GL", 
                    "risk_assessment": "Ataques SQL injection son comunes desde múltiples regiones",
                    "typical_attack_types": ["SQL Injection", "Database Enumeration", "Data Extraction"],
                    "known_apt_groups": ["Various cybercriminal groups", "APT40", "FIN8"]
                }
            }),

            "Network Connection" => serde_json::json!({
                "threat_level": threat_level,
                "origin_country": "External",
                "common_attack_patterns": [
                    "Comando y control (C2)",
                    "Exfiltración de datos", 
                    "Comunicación con botnets"
                ],
                "geographic_context": {
                    "country": "Unknown",
                    "country_code": "XX",
                    "risk_assessment": "Conexiones de red no autorizadas pueden indicar compromiso del sistema",
                    "typical_attack_types": ["C2 Communication", "Data Exfiltration", "Botnet Activity"],
                    "known_apt_groups": ["APT29", "Lazarus", "FIN12"]
                }
            }),

            _ => serde_json::json!({
                "threat_level": threat_level,
                "origin_country": "Unknown",
                "common_attack_patterns": [
                    "Actividad no clasificada",
                    "Comportamiento anómalo"
                ],
                "geographic_context": {
                    "country": "Unknown",
                    "country_code": "XX", 
                    "risk_assessment": "Evento requiere análisis adicional para determinar nivel de amenaza",
                    "typical_attack_types": ["Unknown"],
                    "known_apt_groups": ["Unknown"]
                }
            })
        }
    }

    /// Genera guías de mitigación específicas para cada tipo de evento
    fn get_mitigation_guidance_for_event_type(event_type: &str, severity: &str) -> serde_json::Value {
        match event_type {
            "HTTP Request" => serde_json::json!({
                "immediate_actions": [
                    {"action": "Revisar logs del servidor web", "priority": "MEDIA", "timeline": "< 30min", "tools_required": ["Log analyzer"], "expected_outcome": "Identificar patrones de ataque"},
                    {"action": "Verificar WAF rules", "priority": "MEDIA", "timeline": "< 1h", "tools_required": ["WAF"], "expected_outcome": "Asegurar filtrado adecuado"}
                ],
                "preventive_measures": [
                    {"action": "Implementar rate limiting", "priority": "MEDIA", "timeline": "Corto plazo", "tools_required": ["Load balancer", "WAF"], "expected_outcome": "Prevenir ataques automatizados"},
                    {"action": "Configurar validación de entrada", "priority": "ALTA", "timeline": "Corto plazo", "tools_required": ["Framework web"], "expected_outcome": "Filtrar solicitudes maliciosas"}
                ],
                "long_term_strategies": [
                    {"action": "Implementar OWASP security headers", "priority": "MEDIA", "timeline": "Mensual", "tools_required": ["Servidor web"], "expected_outcome": "Hardening de aplicación web"},
                    {"action": "Auditorías de seguridad web regulares", "priority": "MEDIA", "timeline": "Trimestral", "tools_required": ["Scanner web"], "expected_outcome": "Detección de vulnerabilidades"}
                ]
            }),

            "Login Attempt" => serde_json::json!({
                "immediate_actions": [
                    {"action": "Bloquear IP tras múltiples fallos", "priority": "ALTA", "timeline": "Inmediato", "tools_required": ["Firewall", "IPS"], "expected_outcome": "Detener ataque en curso"},
                    {"action": "Revisar cuentas comprometidas", "priority": "ALTA", "timeline": "< 1h", "tools_required": ["Sistema de usuarios"], "expected_outcome": "Identificar cuentas en riesgo"}
                ],
                "preventive_measures": [
                    {"action": "Implementar CAPTCHA", "priority": "MEDIA", "timeline": "Corto plazo", "tools_required": ["Framework web"], "expected_outcome": "Prevenir ataques automatizados"},
                    {"action": "Configurar 2FA obligatorio", "priority": "ALTA", "timeline": "Corto plazo", "tools_required": ["Sistema de auth"], "expected_outcome": "Fortalecer autenticación"}
                ],
                "long_term_strategies": [
                    {"action": "Monitoreo continuo de credenciales", "priority": "ALTA", "timeline": "Continuo", "tools_required": ["SIEM"], "expected_outcome": "Detección temprana de compromiso"},
                    {"action": "Políticas de contraseñas robustas", "priority": "MEDIA", "timeline": "Mensual", "tools_required": ["Active Directory"], "expected_outcome": "Reducir éxito de ataques"}
                ]
            }),

            "File Access" => serde_json::json!({
                "immediate_actions": [
                    {"action": "Revisar permisos de archivo", "priority": "ALTA", "timeline": "< 1h", "tools_required": ["Sistema operativo"], "expected_outcome": "Verificar acceso autorizado"},
                    {"action": "Analizar contexto de acceso", "priority": "MEDIA", "timeline": "< 2h", "tools_required": ["Audit logs"], "expected_outcome": "Determinar legitimidad"}
                ],
                "preventive_measures": [
                    {"action": "Implementar principio de menor privilegio", "priority": "ALTA", "timeline": "Corto plazo", "tools_required": ["Sistema de permisos"], "expected_outcome": "Limitar acceso no autorizado"},
                    {"action": "Configurar monitoring de archivos críticos", "priority": "MEDIA", "timeline": "Corto plazo", "tools_required": ["File integrity monitor"], "expected_outcome": "Detección de cambios no autorizados"}
                ],
                "long_term_strategies": [
                    {"action": "Auditorías de permisos regulares", "priority": "MEDIA", "timeline": "Mensual", "tools_required": ["Access review tools"], "expected_outcome": "Mantenimiento de accesos apropiados"},
                    {"action": "Implementar DLP (Data Loss Prevention)", "priority": "ALTA", "timeline": "Trimestral", "tools_required": ["DLP solution"], "expected_outcome": "Prevenir exfiltración"}
                ]
            }),

            "SQL Query" => serde_json::json!({
                "immediate_actions": [
                    {"action": "Bloquear IP en WAF/Firewall", "priority": "CRÍTICA", "timeline": "Inmediato", "tools_required": ["WAF", "Firewall"], "expected_outcome": "Detener inyección SQL"},
                    {"action": "Revisar logs de base de datos", "priority": "ALTA", "timeline": "< 30min", "tools_required": ["DB logs"], "expected_outcome": "Evaluar impacto de inyección"}
                ],
                "preventive_measures": [
                    {"action": "Implementar prepared statements", "priority": "CRÍTICA", "timeline": "Inmediato", "tools_required": ["ORM", "Framework"], "expected_outcome": "Eliminar vulnerabilidad de inyección"},
                    {"action": "Configurar WAF rules para SQL", "priority": "ALTA", "timeline": "< 4h", "tools_required": ["WAF"], "expected_outcome": "Filtrar ataques SQL"}
                ],
                "long_term_strategies": [
                    {"action": "Auditorías de código regulares", "priority": "ALTA", "timeline": "Mensual", "tools_required": ["SAST tools"], "expected_outcome": "Identificar vulnerabilidades SQL"},
                    {"action": "Capacitación en secure coding", "priority": "MEDIA", "timeline": "Trimestral", "tools_required": ["Training platform"], "expected_outcome": "Prevenir introducción de vulnerabilidades"}
                ]
            }),

            "Network Connection" => serde_json::json!({
                "immediate_actions": [
                    {"action": "Analizar tráfico de red", "priority": "ALTA", "timeline": "< 1h", "tools_required": ["Network monitor"], "expected_outcome": "Identificar comunicación maliciosa"},
                    {"action": "Bloquear comunicación sospechosa", "priority": "ALTA", "timeline": "< 30min", "tools_required": ["Firewall"], "expected_outcome": "Cortar comunicación C2"}
                ],
                "preventive_measures": [
                    {"action": "Implementar segmentación de red", "priority": "ALTA", "timeline": "Corto plazo", "tools_required": ["Network equipment"], "expected_outcome": "Limitar propagación lateral"},
                    {"action": "Configurar monitoring de conexiones", "priority": "MEDIA", "timeline": "Corto plazo", "tools_required": ["Network monitor"], "expected_outcome": "Detección temprana de anomalías"}
                ],
                "long_term_strategies": [
                    {"action": "Zero Trust Network Architecture", "priority": "ALTA", "timeline": "Largo plazo", "tools_required": ["Security framework"], "expected_outcome": "Verificación continua de confianza"},
                    {"action": "Threat hunting proactivo", "priority": "MEDIA", "timeline": "Continuo", "tools_required": ["Threat hunting tools"], "expected_outcome": "Identificación de amenazas avanzadas"}
                ]
            }),

            _ => serde_json::json!({
                "immediate_actions": [
                    {"action": "Investigar evento desconocido", "priority": "MEDIA", "timeline": "< 2h", "tools_required": ["Analysis tools"], "expected_outcome": "Clasificar tipo de evento"},
                    {"action": "Revisar contexto del sistema", "priority": "MEDIA", "timeline": "< 1h", "tools_required": ["System logs"], "expected_outcome": "Entender origen del evento"}
                ],
                "preventive_measures": [
                    {"action": "Mejorar reglas de detección", "priority": "MEDIA", "timeline": "Corto plazo", "tools_required": ["SIEM"], "expected_outcome": "Mejor clasificación de eventos"},
                    {"action": "Implementar monitoring adicional", "priority": "BAJA", "timeline": "Medio plazo", "tools_required": ["Monitoring tools"], "expected_outcome": "Mayor visibilidad"}
                ],
                "long_term_strategies": [
                    {"action": "Revisión de arquitectura de seguridad", "priority": "BAJA", "timeline": "Largo plazo", "tools_required": ["Security review"], "expected_outcome": "Mejora de postura de seguridad"}
                ]
            })
        }
    }
}