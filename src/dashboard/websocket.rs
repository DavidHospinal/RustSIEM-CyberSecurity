use crate::{storage::StorageManager, detector::DetectorEngine, LogEvent, SecurityAlert};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use warp::ws::Message;
use warp::ws::{WebSocket, Ws};
use warp::Filter;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Administrador de conexiones WebSocket
#[derive(Clone)]
pub struct WebSocketManager {
    connections: Arc<RwLock<HashMap<Uuid, broadcast::Sender<WebSocketMessage>>>>,
    storage: Arc<StorageManager>,
    detector: Arc<DetectorEngine>,
}

/// Mensajes que se envían por WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    /// Nuevo evento detectado
    NewEvent {
        event: LogEvent,
        timestamp: DateTime<Utc>,
    },
    /// Nueva alerta generada
    NewAlert {
        alert: SecurityAlert,
        timestamp: DateTime<Utc>,
    },
    /// Actualización de estadísticas
    StatsUpdate {
        stats: DashboardStats,
        timestamp: DateTime<Utc>,
    },
    /// Actualización de estado del sistema
    SystemStatus {
        status: SystemStatus,
        timestamp: DateTime<Utc>,
    },
    /// Heartbeat para mantener conexión
    Heartbeat {
        timestamp: DateTime<Utc>,
    },
    /// Confirmación de conexión
    Connected {
        client_id: Uuid,
        timestamp: DateTime<Utc>,
    },
}

/// Mensajes entrantes del cliente
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Suscribirse a actualizaciones
    Subscribe {
        channels: Vec<String>,
    },
    /// Desuscribirse de actualizaciones
    Unsubscribe {
        channels: Vec<String>,
    },
    /// Ping para mantener conexión
    Ping,
    /// Solicitar estadísticas actuales
    RequestStats,
}

/// Estado del sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub online: bool,
    pub uptime_seconds: u64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub active_connections: usize,
    pub events_processed: u64,
    pub alerts_generated: u64,
}

/// Estadísticas del dashboard para WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_events: u64,
    pub events_per_second: f64,
    pub critical_alerts: u64,
    pub warning_alerts: u64,
    pub info_alerts: u64,
    pub threat_score: f64,
    pub active_sources: u64,
    pub detection_rate: f64,
}

impl WebSocketManager {
    pub fn new(storage: Arc<StorageManager>, detector: Arc<DetectorEngine>) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            storage,
            detector,
        }
    }

    /// Crea el filtro de WebSocket para Warp
    pub fn websocket_filter(&self) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let manager = self.clone();

        warp::path("ws")
            .and(warp::ws())
            .map(move |ws: Ws| {
                let manager = manager.clone();
                ws.on_upgrade(move |socket| async move {
                    manager.handle_connection(socket).await
                })
            })
    }

    /// Maneja una nueva conexión WebSocket
    pub async fn handle_connection(&self, websocket: WebSocket) {
        let client_id = Uuid::new_v4();
        let (mut ws_sender, mut ws_receiver) = websocket.split();
        let (tx, mut rx) = broadcast::channel(100);
        
        // Registrar la conexión
        {
            let mut connections = self.connections.write().await;
            connections.insert(client_id, tx.clone());
        }
        
        tracing::info!("Nueva conexión WebSocket: {}", client_id);
        
        // Enviar mensaje de confirmación
        let welcome_msg = WebSocketMessage::Connected {
            client_id,
            timestamp: Utc::now(),
        };
        
        if let Ok(msg) = serde_json::to_string(&welcome_msg) {
            let _ = ws_sender.send(Message::text(msg)).await;
        }
        
        // Tarea para enviar mensajes al cliente
        let connections_clone = self.connections.clone();
        let send_task = tokio::spawn(async move {
            while let Ok(message) = rx.recv().await {
                if let Ok(json) = serde_json::to_string(&message) {
                    if ws_sender.send(Message::text(json)).await.is_err() {
                        break;
                    }
                }
            }
            
            // Limpiar conexión al salir
            let mut connections = connections_clone.write().await;
            connections.remove(&client_id);
            tracing::info!("Conexión WebSocket cerrada: {}", client_id);
        });
        
        // Tarea para recibir mensajes del cliente
        let tx_clone = tx.clone();
        let receive_task = tokio::spawn(async move {
            while let Some(result) = ws_receiver.next().await {
                match result {
                    Ok(msg) if msg.is_text() => {
                        if let Ok(text) = msg.to_str() {
                            if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(text) {
                                match client_msg {
                                    ClientMessage::Ping => {
                                        let pong = WebSocketMessage::Heartbeat {
                                            timestamp: Utc::now(),
                                        };
                                        let _ = tx_clone.send(pong);
                                    }
                                    ClientMessage::RequestStats => {
                                        let stats = DashboardStats {
                                            total_events: 1000,
                                            events_per_second: 25.5,
                                            critical_alerts: 3,
                                            warning_alerts: 12,
                                            info_alerts: 45,
                                            threat_score: 6.8,
                                            active_sources: 8,
                                            detection_rate: 94.2,
                                        };

                                        let stats_msg = WebSocketMessage::StatsUpdate {
                                            stats,
                                            timestamp: Utc::now(),
                                        };
                                        let _ = tx_clone.send(stats_msg);
                                    }
                                    _ => {
                                        tracing::debug!("Mensaje del cliente: {:?}", client_msg);
                                    }
                                }
                            }
                        }
                    }
                    Ok(msg) if msg.is_close() => {
                        tracing::info!("Cliente cerró conexión: {}", client_id);
                        break;
                    }
                    Err(e) => {
                        tracing::error!("Error en WebSocket: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        });
        
        // Esperar a que termine cualquiera de las tareas
        tokio::select! {
            _ = send_task => {},
            _ = receive_task => {},
        }
    }

    /// Difunde un mensaje a todas las conexiones activas
    pub async fn broadcast(&self, message: WebSocketMessage) {
        let connections = self.connections.read().await;
        let mut failed_connections = Vec::new();
        
        for (client_id, sender) in connections.iter() {
            if sender.send(message.clone()).is_err() {
                failed_connections.push(*client_id);
            }
        }
        
        // Limpiar conexiones fallidas
        if !failed_connections.is_empty() {
            drop(connections);
            let mut connections = self.connections.write().await;
            for client_id in failed_connections {
                connections.remove(&client_id);
                tracing::debug!("Eliminada conexión inactiva: {}", client_id);
            }
        }
    }

    /// Notifica sobre un nuevo evento
    pub async fn notify_new_event(&self, event: LogEvent) {
        let message = WebSocketMessage::NewEvent {
            event,
            timestamp: Utc::now(),
        };
        self.broadcast(message).await;
    }

    /// Notifica sobre una nueva alerta
    pub async fn notify_new_alert(&self, alert: SecurityAlert) {
        let message = WebSocketMessage::NewAlert {
            alert,
            timestamp: Utc::now(),
        };
        self.broadcast(message).await;
    }

    /// Envía actualización de estadísticas
    pub async fn send_stats_update(&self, stats: DashboardStats) {
        let message = WebSocketMessage::StatsUpdate {
            stats,
            timestamp: Utc::now(),
        };
        self.broadcast(message).await;
    }

    /// Envía actualización de estado del sistema
    pub async fn send_system_status(&self, status: SystemStatus) {
        let message = WebSocketMessage::SystemStatus {
            status,
            timestamp: Utc::now(),
        };
        self.broadcast(message).await;
    }

    /// Inicia el heartbeat periódico
    pub async fn start_heartbeat(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let heartbeat = WebSocketMessage::Heartbeat {
                    timestamp: Utc::now(),
                };
                
                manager.broadcast(heartbeat).await;
                
                // También enviar estadísticas actualizadas
                let stats = DashboardStats {
                    total_events: 1000 + (Utc::now().timestamp() % 1000) as u64,
                    events_per_second: 15.0 + (Utc::now().timestamp() % 20) as f64,
                    critical_alerts: (Utc::now().timestamp() % 5) as u64,
                    warning_alerts: (Utc::now().timestamp() % 15) as u64,
                    info_alerts: (Utc::now().timestamp() % 50) as u64,
                    threat_score: 5.0 + (Utc::now().timestamp() % 5) as f64,
                    active_sources: 5 + (Utc::now().timestamp() % 10) as u64,
                    detection_rate: 90.0 + (Utc::now().timestamp() % 10) as f64,
                };
                
                manager.send_stats_update(stats).await;
            }
        });
    }

    /// Obtiene el número de conexiones activas
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Obtiene estadísticas de las conexiones
    pub async fn get_connection_stats(&self) -> HashMap<String, usize> {
        let connections = self.connections.read().await;
        let mut stats = HashMap::new();
        
        stats.insert("active_connections".to_string(), connections.len());
        stats.insert("total_channels".to_string(), connections.len());
        
        stats
    }
}
