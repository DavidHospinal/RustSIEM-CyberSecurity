use crate::{storage::StorageManager, detector::DetectorEngine, Severity};
use anyhow::Result;
use std::sync::Arc;
use warp::Filter;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::path::PathBuf;

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

        // Combinar todas las rutas
        let routes = index
            .or(events_page)
            .or(alerts_page)
            .or(static_files)
            .or(favicon)
            .or(stats)
            .or(events)
            .or(event_details)
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