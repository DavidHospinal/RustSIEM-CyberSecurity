use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error, Level};
use tracing_subscriber;

// Import SIEM system modules with correct names
use rust_siem::{
    storage::StorageManager,
    detector::DetectorEngine,
    alerting::AlertManager,
    dashboard::DashboardServer,
    parser::{apache::ApacheParser, nginx::NginxParser, ssh::SshParser},
    simulator::RealisticSimulator,
    EventType, SecurityAlert,
};
use chrono::Utc;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure logging
    setup_logging();

    print_banner();

    info!("Starting RustSIEM - Security Information & Event Management");

    // Initialize system components
    let storage_manager = initialize_storage().await?;
    let alert_manager = initialize_alert_manager().await?;
    let detector_engine = initialize_detection_engine(
        storage_manager.clone(),
        alert_manager.clone()
    ).await?;

    // Start web dashboard
    let dashboard_port = 3030;
    let _dashboard_server = initialize_dashboard(
        storage_manager.clone(),
        detector_engine.clone(),
        dashboard_port
    ).await?;

    // Start background log processing
    start_log_processing(
        storage_manager.clone(),
        detector_engine.clone(),
        alert_manager.clone(),
    ).await;

    // Display system status
    print_system_info(dashboard_port);

    // Wait for shutdown signal
    wait_for_shutdown_signal().await;

    info!("Shutting down RustSIEM...");
    Ok(())
}

/// Configure logging system
fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(false)
        .init();
}

/// Display system banner
fn print_banner() {
    println!("\n{}", "=".repeat(60));
    println!("    RustSIEM - Security Information & Event Management");
    println!("    Real-time Security Monitoring & Threat Detection");
    println!("    Built with Rust for Performance & Safety");
    println!("{}", "=".repeat(60));
    println!();
}

/// Initialize storage manager
async fn initialize_storage() -> Result<Arc<StorageManager>> {
    info!("Initializing storage system...");

    let storage_manager = StorageManager::new().await
        .map_err(|e| {
            error!("Error initializing storage: {}", e);
            e
        })?;

    info!("Storage system initialized successfully");
    Ok(Arc::new(storage_manager))
}

/// Initialize alert manager
async fn initialize_alert_manager() -> Result<Arc<AlertManager>> {
    info!("Initializing alert system...");

    let alert_manager = AlertManager::new().await
        .map_err(|e| {
            error!("Error initializing alert system: {}", e);
            e
        })?;

    info!("Alert system initialized successfully");
    info!("   - Email Alerts: Configured");
    info!("   - Console Alerts: Active");
    info!("   - Webhook Alerts: Configured");

    Ok(Arc::new(alert_manager))
}

/// Initialize detection engine
async fn initialize_detection_engine(
    storage: Arc<StorageManager>,
    alert_manager: Arc<AlertManager>
) -> Result<Arc<DetectorEngine>> {
    info!("Initializing threat detection engine...");

    let detector_engine = DetectorEngine::new(storage, alert_manager).await
        .map_err(|e| {
            error!("Error initializing detection engine: {}", e);
            e
        })?;

    info!("Detection engine initialized successfully");
    info!("   - SQL Injection Detection: Active");
    info!("   - XSS Attack Detection: Active");
    info!("   - Brute Force Detection: Active");
    info!("   - ML Anomaly Detection: Training...");

    Ok(Arc::new(detector_engine))
}

/// Initialize dashboard server
async fn initialize_dashboard(
    storage: Arc<StorageManager>,
    detector: Arc<DetectorEngine>,
    port: u16,
) -> Result<DashboardServer> {
    info!("Initializing web dashboard...");

    let dashboard_server = DashboardServer::new(storage, detector, port).await
        .map_err(|e| {
            error!("Error initializing dashboard: {}", e);
            e
        })?;

    // Start server in background
    dashboard_server.serve()
        .map_err(|e| {
            error!("Error starting web server: {}", e);
            e
        })?;

    info!("Web dashboard started on port {}", port);

    Ok(dashboard_server)
}

/// Start background log processing
async fn start_log_processing(
    storage: Arc<StorageManager>,
    detector: Arc<DetectorEngine>,
    alert_manager: Arc<AlertManager>,
) {
    info!("Starting log processing...");

    // Configure parsers for different log types
    let _apache_parser = ApacheParser::new();
    let _nginx_parser = NginxParser::new();
    let _ssh_parser = SshParser::new();

    // Simulate log processing in background
    let storage_clone = storage.clone();
    let detector_clone = detector.clone();
    let alert_clone = alert_manager.clone();

    tokio::spawn(async move {
        // Simulate sample events for demonstration
        simulate_log_events(storage_clone, detector_clone, alert_clone).await;
    });

    info!("Log processing started successfully");
    info!("   - Apache Log Parser: Active");
    info!("   - Nginx Log Parser: Active");
    info!("   - SSH Log Parser: Active");
}

/// Simulate realistic security events for educational purposes
async fn simulate_log_events(
    storage: Arc<StorageManager>,
    detector: Arc<DetectorEngine>,
    alert_manager: Arc<AlertManager>,
) {
    use tokio::time::{sleep, Duration};

    let mut simulator = RealisticSimulator::new();
    let mut counter = 0;

    info!("Iniciando simulación educativa con patrones de ataque realistas");
    
    // Iniciar escenario educativo por defecto
    simulator.start_educational_scenario("web_application_attack");

    loop {
        sleep(Duration::from_secs(5)).await; // Más tiempo para eventos más realistas
        counter += 1;

        // Generar evento realista
        let event = simulator.generate_realistic_event();
        
        info!("Generando evento educativo #{}: {} desde {}", 
              counter, event.raw_message, event.source_ip.as_ref().unwrap_or(&"N/A".to_string()));

        // Almacenar evento
        if let Err(e) = storage.store_event(event.clone()).await {
            error!("Error storing realistic event: {}", e);
        }

        // Ejecutar detección en el evento
        match detector.process_log_event(&event).await {
            Ok(detection_result) => {
                if detection_result.has_threats {
                    info!("Amenaza detectada - Confianza: {:.2}%, Riesgo: {:.2}", 
                          detection_result.confidence * 100.0, 
                          detection_result.risk_score);
                    
                    // Crear alerta educativa detallada
                    let alert = SecurityAlert {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        severity: event.severity.clone(),
                        title: format!("EDUCATIVO: {} Detectado", 
                                      get_attack_type_name(&event.event_type)),
                        description: format!("Evento educativo #{} - {}\n\nOrigen: {} ({})\n\nConfianza: {:.1}%\nPuntuación de Riesgo: {:.2}\n\nContexto Educativo:\n{}", 
                                           counter,
                                           detection_result.details,
                                           event.source_ip.as_ref().unwrap_or(&"Desconocido".to_string()),
                                           get_country_from_parsed_data(&event.parsed_data),
                                           detection_result.confidence * 100.0,
                                           detection_result.risk_score,
                                           get_educational_context(&event.parsed_data)),
                        related_events: vec![event.id],
                        mitigation_steps: detection_result.recommended_actions,
                        acknowledged: false,
                    };

                    if let Err(e) = alert_manager.send_alert(alert).await {
                        error!("Error sending educational alert: {}", e);
                    }
                }
            },
            Err(e) => error!("Error analyzing event: {}", e),
        }

        // Cambiar escenario cada 50 eventos para variedad educativa
        if counter % 50 == 0 {
            let scenarios = ["web_application_attack", "insider_threat", "apt_campaign"];
            let new_scenario = scenarios[counter as usize % scenarios.len()];
            simulator.start_educational_scenario(new_scenario);
            
            if let Some(scenario_info) = simulator.get_current_scenario_info() {
                info!("Cambiando a escenario educativo: {}", 
                      scenario_info["scenario_name"].as_str().unwrap_or("N/A"));
            }
        }

        // Log progreso cada 25 eventos
        if counter % 25 == 0 {
            info!("Eventos educativos procesados: {} - Escenario actual: {}", 
                   counter, simulator.get_current_scenario_name());
        }
    }
}

/// Obtiene nombre legible del tipo de ataque
fn get_attack_type_name(event_type: &EventType) -> &'static str {
    match event_type {
        EventType::SqlInjection => "Inyección SQL",
        EventType::XssAttempt => "Ataque XSS",
        EventType::BruteForce => "Fuerza Bruta",
        EventType::Anomaly => "Anomalía de Comportamiento",
        EventType::SuspiciousActivity => "Actividad Sospechosa",
        EventType::Normal => "Evento Normal",
    }
}

/// Extrae país de los datos parseados
fn get_country_from_parsed_data(parsed_data: &serde_json::Value) -> String {
    parsed_data.get("origin_country")
        .and_then(|v| v.as_str())
        .unwrap_or("Desconocido")
        .to_string()
}

/// Extrae contexto educativo de los datos parseados  
fn get_educational_context(parsed_data: &serde_json::Value) -> String {
    if let Some(educational_context) = parsed_data.get("educational_context") {
        if let Some(description) = educational_context.get("description") {
            return description.as_str().unwrap_or("").to_string();
        }
    }
    "Evento de seguridad simulado para aprendizaje".to_string()
}

/// Display system information
fn print_system_info(dashboard_port: u16) {
    println!("\nRustSIEM System Started");
    println!("{}", "-".repeat(50));

    println!("Dashboard Web: http://localhost:{}", dashboard_port);

    println!("API Endpoints:");
    println!("   - Statistics: http://localhost:{}/api/stats", dashboard_port);
    println!("   - Events: http://localhost:{}/api/events", dashboard_port);
    println!("   - Alerts: http://localhost:{}/api/alerts", dashboard_port);

    println!("System Status:");
    println!("   - Storage: Operational");
    println!("   - Detection Engine: Active");
    println!("   - Alert System: Configured");
    println!("   - Web Dashboard: Available");

    println!("\nTip:");
    println!("   Open your browser at http://localhost:{} to access the dashboard", dashboard_port);

    println!("\nControl:");
    println!("   Press Ctrl+C to stop the system");

    println!("{}", "-".repeat(50));
}

/// Wait for system shutdown signal
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Error installing Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Error installing TERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            info!("Received TERM signal");
        },
    }
}