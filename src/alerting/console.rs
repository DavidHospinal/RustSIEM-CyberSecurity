use crate::SecurityAlert;
use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Alertador que envía notificaciones a la consola
pub struct ConsoleAlerter {
    config: ConsoleAlerterConfig,
    statistics: Arc<RwLock<ConsoleStatistics>>,
}

/// Configuración del alertador de consola
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleAlerterConfig {
    pub enabled: bool,
    pub use_colors: bool,
    pub show_timestamp: bool,
    pub show_severity_icons: bool,
    pub max_description_length: usize,
    pub include_mitigation_steps: bool,
    pub format_style: ConsoleFormat,
    pub minimum_severity: ConsoleSeverityFilter,
}

/// Estilos de formato para la consola
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsoleFormat {
    Compact,
    Detailed,
    Json,
    Table,
}

/// Filtro de severidad para consola
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ConsoleSeverityFilter {
    Info,
    Warning,
    Critical,
}

/// Estadísticas del alertador de consola
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsoleStatistics {
    pub alerts_sent: u64,
    pub alerts_failed: u64,
    pub last_alert_time: Option<DateTime<Utc>>,
    pub alerts_by_severity: std::collections::HashMap<String, u64>,
}

impl Default for ConsoleAlerterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_colors: true,
            show_timestamp: true,
            show_severity_icons: true,
            max_description_length: 500,
            include_mitigation_steps: true,
            format_style: ConsoleFormat::Detailed,
            minimum_severity: ConsoleSeverityFilter::Info,
        }
    }
}

impl Default for ConsoleStatistics {
    fn default() -> Self {
        Self {
            alerts_sent: 0,
            alerts_failed: 0,
            last_alert_time: None,
            alerts_by_severity: std::collections::HashMap::new(),
        }
    }
}

impl ConsoleAlerter {
    pub fn new() -> Self {
        Self::with_config(ConsoleAlerterConfig::default())
    }

    pub fn with_config(config: ConsoleAlerterConfig) -> Self {
        Self {
            config,
            statistics: Arc::new(RwLock::new(ConsoleStatistics::default())),
        }
    }

    /// Envía alerta a la consola
    pub async fn send_alert(&self, alert: &SecurityAlert) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Verificar filtro de severidad
        if !self.should_send_alert(alert) {
            return Ok(());
        }

        let result = match self.config.format_style {
            ConsoleFormat::Compact => self.send_compact_alert(alert).await,
            ConsoleFormat::Detailed => self.send_detailed_alert(alert).await,
            ConsoleFormat::Json => self.send_json_alert(alert).await,
            ConsoleFormat::Table => self.send_table_alert(alert).await,
        };

        // Actualizar estadísticas
        let mut stats = self.statistics.write().await;
        match result {
            Ok(()) => {
                stats.alerts_sent += 1;
                stats.last_alert_time = Some(Utc::now());
                let severity_key = format!("{:?}", alert.severity);
                *stats.alerts_by_severity.entry(severity_key).or_insert(0) += 1;
            },
            Err(_) => {
                stats.alerts_failed += 1;
            }
        }

        result
    }

    /// Verifica si debe enviar la alerta según filtros
    fn should_send_alert(&self, alert: &SecurityAlert) -> bool {
        let alert_severity_level = match alert.severity {
            crate::Severity::Low => 0,
            crate::Severity::Info => 1,
            crate::Severity::Medium => 2,
            crate::Severity::Warning => 3,
            crate::Severity::High => 4,
            crate::Severity::Critical => 5,
        };

        let min_severity_level = match self.config.minimum_severity {
            ConsoleSeverityFilter::Info => 0,
            ConsoleSeverityFilter::Warning => 1,
            ConsoleSeverityFilter::Critical => 2,
        };

        alert_severity_level >= min_severity_level
    }

    /// Envía alerta en formato compacto
    async fn send_compact_alert(&self, alert: &SecurityAlert) -> Result<()> {
        let mut output = String::new();

        // Icono de severidad
        if self.config.show_severity_icons {
            let icon = self.get_severity_icon(&alert.severity);
            output.push_str(&icon);
            output.push(' ');
        }

        // Timestamp
        if self.config.show_timestamp {
            let timestamp = alert.timestamp.format("%H:%M:%S").to_string();
            if self.config.use_colors {
                output.push_str(&timestamp.dimmed().to_string());
            } else {
                output.push_str(&timestamp);
            }
            output.push_str(" | ");
        }

        // Título con color
        if self.config.use_colors {
            let colored_title = self.colorize_by_severity(&alert.title, &alert.severity);
            output.push_str(&colored_title);
        } else {
            output.push_str(&alert.title);
        }

        // Descripción truncada
        let description = self.truncate_description(&alert.description);
        if !description.is_empty() {
            output.push_str(" - ");
            if self.config.use_colors {
                output.push_str(&description.dimmed().to_string());
            } else {
                output.push_str(&description);
            }
        }

        println!("{}", output);
        io::stdout().flush()?;
        Ok(())
    }

    /// Envía alerta en formato detallado
    async fn send_detailed_alert(&self, alert: &SecurityAlert) -> Result<()> {
        let separator = if self.config.use_colors {
            "═".repeat(80).bright_blue().to_string()
        } else {
            "═".repeat(80)
        };

        println!("{}", separator);

        // Header con icono y timestamp
        let mut header = String::new();
        if self.config.show_severity_icons {
            header.push_str(&self.get_severity_icon(&alert.severity));
            header.push(' ');
        }

        let severity_text = format!("{:?}", alert.severity).to_uppercase();
        if self.config.use_colors {
            header.push_str(&self.colorize_by_severity(&severity_text, &alert.severity));
        } else {
            header.push_str(&severity_text);
        }

        header.push_str(" SECURITY ALERT");

        if self.config.show_timestamp {
            let timestamp = alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            if self.config.use_colors {
                header.push_str(&format!(" | {}", timestamp.dimmed()));
            } else {
                header.push_str(&format!(" | {}", timestamp));
            }
        }

        println!("{}", header);
        println!();

        // ID de alerta
        if self.config.use_colors {
            println!("{}: {}", "Alert ID".bold(), alert.id);
        } else {
            println!("Alert ID: {}", alert.id);
        }

        // Título
        if self.config.use_colors {
            println!("{}: {}", "Title".bold(), self.colorize_by_severity(&alert.title, &alert.severity));
        } else {
            println!("Title: {}", alert.title);
        }

        // Descripción
        if self.config.use_colors {
            println!("{}: {}", "Description".bold(), alert.description.dimmed());
        } else {
            println!("Description: {}", alert.description);
        }

        // Eventos relacionados
        if !alert.related_events.is_empty() {
            if self.config.use_colors {
                println!("{}: {} events", "Related Events".bold(), alert.related_events.len());
            } else {
                println!("Related Events: {} events", alert.related_events.len());
            }

            for (i, event_id) in alert.related_events.iter().take(3).enumerate() {
                if self.config.use_colors {
                    println!("  {}. {}", i + 1, event_id.to_string().dimmed());
                } else {
                    println!("  {}. {}", i + 1, event_id);
                }
            }

            if alert.related_events.len() > 3 {
                let remaining = alert.related_events.len() - 3;
                if self.config.use_colors {
                    println!("  ... and {} more", remaining.to_string().dimmed());
                } else {
                    println!("  ... and {} more", remaining);
                }
            }
        }

        // Pasos de mitigación
        if self.config.include_mitigation_steps && !alert.mitigation_steps.is_empty() {
            println!();
            if self.config.use_colors {
                println!("{}: ", "Recommended Actions".bold().green());
            } else {
                println!("Recommended Actions:");
            }

            for (i, step) in alert.mitigation_steps.iter().enumerate() {
                if self.config.use_colors {
                    println!("  {}. {}", i + 1, step.green());
                } else {
                    println!("  {}. {}", i + 1, step);
                }
            }
        }

        // Estado de acknowledgment
        println!();
        let ack_status = if alert.acknowledged { "YES" } else { "NO" };
        if self.config.use_colors {
            let colored_status = if alert.acknowledged {
                ack_status.green()
            } else {
                ack_status.red()
            };
            println!("{}: {}", "Acknowledged".bold(), colored_status);
        } else {
            println!("Acknowledged: {}", ack_status);
        }

        println!("{}", separator);
        println!();

        io::stdout().flush()?;
        Ok(())
    }

    /// Envía alerta en formato JSON
    async fn send_json_alert(&self, alert: &SecurityAlert) -> Result<()> {
        let json_output = serde_json::to_string_pretty(alert)?;

        if self.config.use_colors {
            // Colorear JSON básico
            let colored_json = self.colorize_json(&json_output);
            println!("{}", colored_json);
        } else {
            println!("{}", json_output);
        }

        io::stdout().flush()?;
        Ok(())
    }

    /// Envía alerta en formato tabla
    async fn send_table_alert(&self, alert: &SecurityAlert) -> Result<()> {
        let table_width = 80;
        let border = if self.config.use_colors {
            "─".repeat(table_width).bright_blue().to_string()
        } else {
            "─".repeat(table_width)
        };

        println!("┌{}┐", border);

        // Header
        let header = format!("{:^width$}", "SECURITY ALERT", width = table_width - 2);
        if self.config.use_colors {
            println!("│ {} │", header.bold().on_red());
        } else {
            println!("│ {} │", header);
        }

        println!("├{}┤", border);

        // Campos de la tabla
        self.print_table_row("Alert ID", &alert.id.to_string(), table_width);
        self.print_table_row("Severity", &format!("{:?}", alert.severity), table_width);
        self.print_table_row("Timestamp", &alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(), table_width);
        self.print_table_row("Title", &alert.title, table_width);

        // Descripción (multilinea si es necesaria)
        let description = self.truncate_description(&alert.description);
        self.print_table_row("Description", &description, table_width);

        self.print_table_row("Related Events", &alert.related_events.len().to_string(), table_width);
        self.print_table_row("Acknowledged", &if alert.acknowledged { "Yes" } else { "No" }, table_width);

        println!("└{}┘", border);
        println!();

        io::stdout().flush()?;
        Ok(())
    }

    /// Imprime una fila de tabla
    fn print_table_row(&self, label: &str, value: &str, table_width: usize) {
        let max_value_length = table_width - label.len() - 5; // 5 para "│ : │"
        let truncated_value = if value.len() > max_value_length {
            format!("{}...", &value[..max_value_length.saturating_sub(3)])
        } else {
            value.to_string()
        };

        if self.config.use_colors {
            println!("│ {}: {:<width$} │",
                     label.bold(),
                     truncated_value,
                     width = table_width - label.len() - 5
            );
        } else {
            println!("│ {}: {:<width$} │",
                     label,
                     truncated_value,
                     width = table_width - label.len() - 5
            );
        }
    }

    /// Obtiene icono de severidad
    fn get_severity_icon(&self, severity: &crate::Severity) -> String {
        match severity {
            crate::Severity::Low => {
                if self.config.use_colors {
                    "🔵".bright_blue().to_string()
                } else {
                    "🔵".to_string()
                }
            },
            crate::Severity::Info => {
                if self.config.use_colors {
                    "ℹ".blue().to_string()
                } else {
                    "ℹ".to_string()
                }
            },
            crate::Severity::Medium => {
                if self.config.use_colors {
                    "🔶".bright_yellow().to_string()
                } else {
                    "🔶".to_string()
                }
            },
            crate::Severity::Warning => {
                if self.config.use_colors {
                    "⚠".yellow().to_string()
                } else {
                    "⚠".to_string()
                }
            },
            crate::Severity::High => {
                if self.config.use_colors {
                    "🔴".red().to_string()
                } else {
                    "🔴".to_string()
                }
            },
            crate::Severity::Critical => {
                if self.config.use_colors {
                    "🚨".red().bold().to_string()
                } else {
                    "🚨".to_string()
                }
            },
        }
    }

    /// Coloriza texto según severidad
    fn colorize_by_severity(&self, text: &str, severity: &crate::Severity) -> String {
        if !self.config.use_colors {
            return text.to_string();
        }

        match severity {
            crate::Severity::Low => text.bright_blue().to_string(),
            crate::Severity::Info => text.blue().to_string(),
            crate::Severity::Medium => text.bright_yellow().to_string(),
            crate::Severity::Warning => text.yellow().to_string(),
            crate::Severity::High => text.red().to_string(),
            crate::Severity::Critical => text.red().bold().to_string(),
        }
    }

    /// Trunca descripción si es muy larga
    fn truncate_description(&self, description: &str) -> String {
        if description.len() <= self.config.max_description_length {
            description.to_string()
        } else {
            let truncated = &description[..self.config.max_description_length.saturating_sub(3)];
            format!("{}...", truncated)
        }
    }

    /// Coloriza JSON básico
    fn colorize_json(&self, json: &str) -> String {
        if !self.config.use_colors {
            return json.to_string();
        }

        let mut result = String::new();
        let mut in_string = false;
        let mut escape_next = false;
        let chars: Vec<char> = json.chars().collect();

        for i in 0..chars.len() {
            let ch = chars[i];

            if escape_next {
                result.push(ch);
                escape_next = false;
                continue;
            }

            match ch {
                '\\' if in_string => {
                    escape_next = true;
                    result.push(ch);
                },
                '"' => {
                    in_string = !in_string;
                    if in_string {
                        result.push_str(&ch.to_string().green().to_string());
                    } else {
                        result.push_str(&ch.to_string().green().to_string());
                    }
                },
                _ if in_string => {
                    result.push_str(&ch.to_string().green().to_string());
                },
                '{' | '}' | '[' | ']' => {
                    result.push_str(&ch.to_string().bright_blue().to_string());
                },
                ':' | ',' => {
                    result.push_str(&ch.to_string().white().to_string());
                },
                _ if ch.is_numeric() => {
                    result.push_str(&ch.to_string().cyan().to_string());
                },
                _ => {
                    result.push(ch);
                }
            }
        }

        result
    }

    /// Envía mensaje de prueba
    pub async fn send_test_alert(&self) -> Result<()> {
        let test_alert = SecurityAlert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: crate::Severity::Warning,
            title: "Test Alert - Console Alerter".to_string(),
            description: "This is a test alert to verify console alerter functionality. If you can see this message, the console alerter is working correctly.".to_string(),
            related_events: vec![uuid::Uuid::new_v4()],
            mitigation_steps: vec![
                "This is a test - no action required".to_string(),
                "Verify alert formatting and colors".to_string(),
            ],
            acknowledged: false,
        };

        self.send_alert(&test_alert).await
    }

    /// Obtiene estadísticas del alertador
    pub async fn get_statistics(&self) -> ConsoleStatistics {
        self.statistics.read().await.clone()
    }

    /// Resetea estadísticas
    pub async fn reset_statistics(&self) {
        let mut stats = self.statistics.write().await;
        *stats = ConsoleStatistics::default();
    }

    /// Actualiza configuración
    pub fn update_config(&mut self, new_config: ConsoleAlerterConfig) {
        self.config = new_config;
    }

    /// Obtiene configuración actual
    pub fn get_config(&self) -> &ConsoleAlerterConfig {
        &self.config
    }

    /// Envía resumen de alertas
    pub async fn send_summary(&self, alerts: &[SecurityAlert]) -> Result<()> {
        if alerts.is_empty() {
            if self.config.use_colors {
                println!("{}", "No alerts to summarize".dimmed());
            } else {
                println!("No alerts to summarize");
            }
            return Ok(());
        }

        let separator = if self.config.use_colors {
            "═".repeat(60).bright_cyan().to_string()
        } else {
            "═".repeat(60)
        };

        println!("{}", separator);

        let header = format!("ALERT SUMMARY - {} ALERTS", alerts.len());
        if self.config.use_colors {
            println!("{}", header.bold().cyan());
        } else {
            println!("{}", header);
        }

        println!("{}", separator);

        // Contar por severidad
        let mut severity_counts = std::collections::HashMap::new();
        for alert in alerts {
            *severity_counts.entry(format!("{:?}", alert.severity)).or_insert(0) += 1;
        }

        // Mostrar conteos
        for (severity, count) in &severity_counts {
            if self.config.use_colors {
                println!("  {}: {}", severity.bold(), count);
            } else {
                println!("  {}: {}", severity, count);
            }
        }

        println!();

        // Mostrar últimas alertas (máximo 5)
        if self.config.use_colors {
            println!("{}", "Recent Alerts:".bold());
        } else {
            println!("Recent Alerts:");
        }

        for (i, alert) in alerts.iter().rev().take(5).enumerate() {
            let time = alert.timestamp.format("%H:%M:%S").to_string();
            let severity_icon = self.get_severity_icon(&alert.severity);

            if self.config.use_colors {
                println!("  {}. {} {} {} - {}",
                         i + 1,
                         time.dimmed(),
                         severity_icon,
                         self.colorize_by_severity(&format!("{:?}", alert.severity), &alert.severity),
                         alert.title.dimmed()
                );
            } else {
                println!("  {}. {} {} {:?} - {}",
                         i + 1, time, severity_icon, alert.severity, alert.title
                );
            }
        }

        if alerts.len() > 5 {
            let remaining = alerts.len() - 5;
            if self.config.use_colors {
                println!("  ... and {} more alerts", remaining.to_string().dimmed());
            } else {
                println!("  ... and {} more alerts", remaining);
            }
        }

        println!("{}", separator);
        println!();

        io::stdout().flush()?;
        Ok(())
    }

    /// Envía banner de inicio del sistema
    pub async fn send_startup_banner(&self, version: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let banner = format!(
            r#"
 ╭─────────────────────────────────────────────────────────────╮
 │                        RustSIEM v{}                        │
 │                  Security Monitoring System                 │
 ╰─────────────────────────────────────────────────────────────╯
            "#, version
        );

        if self.config.use_colors {
            println!("{}", banner.bright_green().bold());
            println!("{}", "Console Alerter: ACTIVE".green());
            println!("{}", format!("Format: {:?}", self.config.format_style).dimmed());
            println!("{}", format!("Colors: {}", if self.config.use_colors { "Enabled" } else { "Disabled" }).dimmed());
        } else {
            println!("{}", banner);
            println!("Console Alerter: ACTIVE");
            println!("Format: {:?}", self.config.format_style);
            println!("Colors: {}", if self.config.use_colors { "Enabled" } else { "Disabled" });
        }

        println!();
        io::stdout().flush()?;
        Ok(())
    }

    /// Envía mensaje de shutdown
    pub async fn send_shutdown_message(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let stats = self.get_statistics().await;

        if self.config.use_colors {
            println!("{}", "RustSIEM Console Alerter - Shutting Down".red().bold());
            println!("{}", format!("Total alerts sent: {}", stats.alerts_sent).dimmed());
            if stats.alerts_failed > 0 {
                println!("{}", format!("Failed alerts: {}", stats.alerts_failed).yellow());
            }
        } else {
            println!("RustSIEM Console Alerter - Shutting Down");
            println!("Total alerts sent: {}", stats.alerts_sent);
            if stats.alerts_failed > 0 {
                println!("Failed alerts: {}", stats.alerts_failed);
            }
        }

        println!();
        io::stdout().flush()?;
        Ok(())
    }
}

impl Default for ConsoleAlerter {
    fn default() -> Self {
        Self::new()
    }
}

/// Utilidades para el alertador de consola
pub mod utils {
    use super::*;

    /// Crea un alertador de consola optimizado para debugging
    pub fn create_debug_alerter() -> ConsoleAlerter {
        let config = ConsoleAlerterConfig {
            enabled: true,
            use_colors: true,
            show_timestamp: true,
            show_severity_icons: true,
            max_description_length: 1000,
            include_mitigation_steps: true,
            format_style: ConsoleFormat::Detailed,
            minimum_severity: ConsoleSeverityFilter::Info,
        };

        ConsoleAlerter::with_config(config)
    }

    /// Crea un alertador de consola optimizado para producción
    pub fn create_production_alerter() -> ConsoleAlerter {
        let config = ConsoleAlerterConfig {
            enabled: true,
            use_colors: false, // Mejor para logs de producción
            show_timestamp: true,
            show_severity_icons: false,
            max_description_length: 200,
            include_mitigation_steps: false,
            format_style: ConsoleFormat::Json, // Mejor para parsing automático
            minimum_severity: ConsoleSeverityFilter::Warning,
        };

        ConsoleAlerter::with_config(config)
    }

    /// Crea un alertador de consola compacto para monitoreo
    pub fn create_monitoring_alerter() -> ConsoleAlerter {
        let config = ConsoleAlerterConfig {
            enabled: true,
            use_colors: true,
            show_timestamp: true,
            show_severity_icons: true,
            max_description_length: 100,
            include_mitigation_steps: false,
            format_style: ConsoleFormat::Compact,
            minimum_severity: ConsoleSeverityFilter::Warning,
        };

        ConsoleAlerter::with_config(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_alert() -> SecurityAlert {
        SecurityAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: crate::Severity::Critical,
            title: "Test Security Alert".to_string(),
            description: "This is a test security alert for unit testing purposes. It contains enough text to test truncation functionality.".to_string(),
            related_events: vec![Uuid::new_v4(), Uuid::new_v4()],
            mitigation_steps: vec![
                "Take immediate action".to_string(),
                "Review security logs".to_string(),
                "Contact security team".to_string(),
            ],
            acknowledged: false,
        }
    }

    #[tokio::test]
    async fn test_console_alerter_creation() {
        let alerter = ConsoleAlerter::new();
        assert!(alerter.config.enabled);
        assert_eq!(alerter.config.format_style, ConsoleFormat::Detailed);
    }

    #[tokio::test]
    async fn test_send_alert_detailed() {
        let alerter = ConsoleAlerter::new();
        let alert = create_test_alert();

        // Este test principalmente verifica que no hay errores en el envío
        let result = alerter.send_alert(&alert).await;
        assert!(result.is_ok());

        let stats = alerter.get_statistics().await;
        assert_eq!(stats.alerts_sent, 1);
        assert_eq!(stats.alerts_failed, 0);
    }

    #[tokio::test]
    async fn test_send_alert_compact() {
        let mut config = ConsoleAlerterConfig::default();
        config.format_style = ConsoleFormat::Compact;

        let alerter = ConsoleAlerter::with_config(config);
        let alert = create_test_alert();

        let result = alerter.send_alert(&alert).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_alert_json() {
        let mut config = ConsoleAlerterConfig::default();
        config.format_style = ConsoleFormat::Json;

        let alerter = ConsoleAlerter::with_config(config);
        let alert = create_test_alert();

        let result = alerter.send_alert(&alert).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_alert_table() {
        let mut config = ConsoleAlerterConfig::default();
        config.format_style = ConsoleFormat::Table;

        let alerter = ConsoleAlerter::with_config(config);
        let alert = create_test_alert();

        let result = alerter.send_alert(&alert).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_severity_filtering() {
        let mut config = ConsoleAlerterConfig::default();
        config.minimum_severity = ConsoleSeverityFilter::Critical;

        let alerter = ConsoleAlerter::with_config(config);

        // Alerta de warning no debería enviarse
        let mut warning_alert = create_test_alert();
        warning_alert.severity = crate::Severity::Warning;

        let result = alerter.send_alert(&warning_alert).await;
        assert!(result.is_ok());

        let stats = alerter.get_statistics().await;
        assert_eq!(stats.alerts_sent, 0); // No se envió porque no cumple el filtro

        // Alerta crítica sí debería enviarse
        let critical_alert = create_test_alert();
        let result = alerter.send_alert(&critical_alert).await;
        assert!(result.is_ok());

        let stats = alerter.get_statistics().await;
        assert_eq!(stats.alerts_sent, 1); // Esta sí se envió
    }

    #[tokio::test]
    async fn test_disabled_alerter() {
        let mut config = ConsoleAlerterConfig::default();
        config.enabled = false;

        let alerter = ConsoleAlerter::with_config(config);
        let alert = create_test_alert();

        let result = alerter.send_alert(&alert).await;
        assert!(result.is_ok());

        let stats = alerter.get_statistics().await;
        assert_eq!(stats.alerts_sent, 0); // No se envió porque está deshabilitado
    }

    #[tokio::test]
    async fn test_description_truncation() {
        let mut config = ConsoleAlerterConfig::default();
        config.max_description_length = 50;

        let alerter = ConsoleAlerter::with_config(config);

        let long_description = "This is a very long description that should be truncated because it exceeds the maximum length configured for the alerter.";
        let truncated = alerter.truncate_description(long_description);
        assert!(truncated.len() <= 50);
        assert!(truncated.ends_with("..."));
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let alerter = ConsoleAlerter::new();
        let alert1 = create_test_alert();
        let mut alert2 = create_test_alert();
        alert2.severity = crate::Severity::Warning;

        // Enviar varias alertas
        alerter.send_alert(&alert1).await.unwrap();
        alerter.send_alert(&alert2).await.unwrap();

        let stats = alerter.get_statistics().await;
        assert_eq!(stats.alerts_sent, 2);
        assert!(stats.last_alert_time.is_some());
        assert_eq!(stats.alerts_by_severity.get("Critical"), Some(&1));
        assert_eq!(stats.alerts_by_severity.get("Warning"), Some(&1));
    }

    #[tokio::test]
    async fn test_send_summary() {
        let alerter = ConsoleAlerter::new();
        let alerts = vec![create_test_alert(), create_test_alert()];

        let result = alerter.send_summary(&alerts).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_test_alert() {
        let alerter = ConsoleAlerter::new();
        let result = alerter.send_test_alert().await;
        assert!(result.is_ok());

        let stats = alerter.get_statistics().await;
        assert_eq!(stats.alerts_sent, 1);
    }

    #[tokio::test]
    async fn test_utility_alerters() {
        let debug_alerter = utils::create_debug_alerter();
        assert!(debug_alerter.config.use_colors);
        assert_eq!(debug_alerter.config.format_style, ConsoleFormat::Detailed);

        let prod_alerter = utils::create_production_alerter();
        assert!(!prod_alerter.config.use_colors);
        assert_eq!(prod_alerter.config.format_style, ConsoleFormat::Json);

        let monitor_alerter = utils::create_monitoring_alerter();
        assert_eq!(monitor_alerter.config.format_style, ConsoleFormat::Compact);
        assert_eq!(monitor_alerter.config.minimum_severity, ConsoleSeverityFilter::Warning);
    }

    #[tokio::test]
    async fn test_startup_and_shutdown_messages() {
        let alerter = ConsoleAlerter::new();

        let startup_result = alerter.send_startup_banner("1.0.0").await;
        assert!(startup_result.is_ok());

        let shutdown_result = alerter.send_shutdown_message().await;
        assert!(shutdown_result.is_ok());
    }

    #[test]
    fn test_severity_icon_generation() {
        let alerter = ConsoleAlerter::new();

        let info_icon = alerter.get_severity_icon(&crate::Severity::Info);
        assert!(!info_icon.is_empty());

        let warning_icon = alerter.get_severity_icon(&crate::Severity::Warning);
        assert!(!warning_icon.is_empty());

        let critical_icon = alerter.get_severity_icon(&crate::Severity::Critical);
        assert!(!critical_icon.is_empty());
    }

    #[test]
    fn test_colorization() {
        let alerter = ConsoleAlerter::new();

        let text = "Test text";
        let colored = alerter.colorize_by_severity(text, &crate::Severity::Critical);

        // Con colores habilitados, el texto debería ser diferente
        if alerter.config.use_colors {
            assert_ne!(colored, text);
        } else {
            assert_eq!(colored, text);
        }
    }

    #[test]
    fn test_config_update() {
        let mut alerter = ConsoleAlerter::new();

        let new_config = ConsoleAlerterConfig {
            enabled: false,
            use_colors: false,
            show_timestamp: false,
            show_severity_icons: false,
            max_description_length: 100,
            include_mitigation_steps: false,
            format_style: ConsoleFormat::Compact,
            minimum_severity: ConsoleSeverityFilter::Critical,
        };

        alerter.update_config(new_config.clone());
        assert_eq!(alerter.get_config().enabled, false);
        assert_eq!(alerter.get_config().format_style, ConsoleFormat::Compact);
    }
}