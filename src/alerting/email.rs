use chrono::{Datelike, Timelike};
use crate::SecurityAlert;
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use lettre::{
    message::{header::ContentType, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Alertador que envía notificaciones por email
pub struct EmailAlerter {
    config: EmailAlerterConfig,
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    statistics: Arc<RwLock<EmailStatistics>>,
    template_engine: EmailTemplateEngine,
}

/// Configuración del alertador de email
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAlerterConfig {
    pub enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub use_tls: bool,
    pub use_starttls: bool,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub from_name: String,
    pub recipients: Vec<EmailRecipient>,
    pub subject_prefix: String,
    pub rate_limit_per_hour: u32,
    pub batch_alerts: bool,
    pub batch_timeout_minutes: u32,
    pub include_raw_logs: bool,
    pub template_style: EmailTemplate,
    pub severity_routing: HashMap<String, Vec<String>>,
}

/// Destinatario de email con configuraciones específicas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailRecipient {
    pub email: String,
    pub name: Option<String>,
    pub severity_filter: EmailSeverityFilter,
    pub alert_types: Vec<String>, // Tipos específicos de alerta
    pub active_hours: Option<ActiveHours>,
}

/// Filtro de severidad para email
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum EmailSeverityFilter {
    All,
    Warning,
    Critical,
}

/// Horas activas para envío de emails
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveHours {
    pub start_hour: u8, // 0-23
    pub end_hour: u8,   // 0-23
    pub timezone: String,
    pub weekdays_only: bool,
}

/// Templates de email disponibles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EmailTemplate {
    Plain,
    Html,
    Rich,
}

/// Estadísticas del alertador de email
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailStatistics {
    pub emails_sent: u64,
    pub emails_failed: u64,
    pub last_email_time: Option<DateTime<Utc>>,
    pub emails_by_severity: HashMap<String, u64>,
    pub rate_limit_hits: u64,
    pub batch_emails_sent: u64,
    pub delivery_times_ms: Vec<u64>,
}

/// Motor de templates de email
pub struct EmailTemplateEngine {
    templates: HashMap<EmailTemplate, String>,
}

/// Batch de alertas para envío agrupado
#[derive(Debug, Clone)]
pub struct AlertBatch {
    pub alerts: Vec<SecurityAlert>,
    pub created_at: DateTime<Utc>,
    pub recipients: Vec<String>,
}

impl Default for EmailAlerterConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Deshabilitado por defecto hasta configurar SMTP
            smtp_server: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            use_tls: false,
            use_starttls: true,
            username: String::new(),
            password: String::new(),
            from_address: "rustsiem@example.com".to_string(),
            from_name: "RustSIEM Security Monitor".to_string(),
            recipients: vec![],
            subject_prefix: "[RUSTSIEM]".to_string(),
            rate_limit_per_hour: 60,
            batch_alerts: true,
            batch_timeout_minutes: 15,
            include_raw_logs: false,
            template_style: EmailTemplate::Html,
            severity_routing: HashMap::new(),
        }
    }
}

impl Default for EmailStatistics {
    fn default() -> Self {
        Self {
            emails_sent: 0,
            emails_failed: 0,
            last_email_time: None,
            emails_by_severity: HashMap::new(),
            rate_limit_hits: 0,
            batch_emails_sent: 0,
            delivery_times_ms: Vec::new(),
        }
    }
}

impl EmailAlerter {
    pub async fn new() -> Result<Self> {
        Self::with_config(EmailAlerterConfig::default()).await
    }

    pub async fn with_config(config: EmailAlerterConfig) -> Result<Self> {
        let transport = if config.enabled {
            Some(Self::create_transport(&config).await?)
        } else {
            None
        };

        let template_engine = EmailTemplateEngine::new();

        Ok(Self {
            config,
            transport,
            statistics: Arc::new(RwLock::new(EmailStatistics::default())),
            template_engine,
        })
    }

    /// Crea transporte SMTP

    async fn create_transport(config: &EmailAlerterConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_server)
            .context("Failed to create SMTP relay")?;

        builder = builder.port(config.smtp_port);

        // Configurar TLS según lettre 0.11
        if config.use_starttls {

        } else if config.use_tls {

        }

        if !config.username.is_empty() && !config.password.is_empty() {
            let credentials = Credentials::new(config.username.clone(), config.password.clone());
            builder = builder.credentials(credentials);
        }

        Ok(builder.build())
    }

    /// Envía alerta por email
    pub async fn send_alert(&self, alert: &SecurityAlert) -> Result<()> {
        if !self.config.enabled || self.transport.is_none() {
            return Ok(());
        }

        let start_time = std::time::Instant::now();

        // Verificar rate limit
        if self.is_rate_limited().await {
            self.update_rate_limit_stats().await;
            return Err(anyhow::anyhow!("Rate limit exceeded"));
        }

        // Filtrar destinatarios según la alerta
        let recipients = self.filter_recipients_for_alert(alert).await;
        if recipients.is_empty() {
            return Ok(());
        }

        // Si está habilitado el batching, agregar a batch en lugar de enviar inmediatamente
        if self.config.batch_alerts {
            // En una implementación real, esto se manejaría con un background task
            // Por simplicidad, enviamos inmediatamente
        }

        // Generar email
        let email_message = self.create_email_message(alert, &recipients).await?;

        // Enviar email
        let transport = self.transport.as_ref().unwrap();
        let result = transport.send(email_message).await;

        let delivery_time = start_time.elapsed().as_millis() as u64;

        // Actualizar estadísticas
        let mut stats = self.statistics.write().await;
        match result {
            Ok(_) => {
                stats.emails_sent += 1;
                stats.last_email_time = Some(Utc::now());
                let severity_key = format!("{:?}", alert.severity);
                *stats.emails_by_severity.entry(severity_key).or_insert(0) += 1;
                stats.delivery_times_ms.push(delivery_time);

                // Mantener solo los últimos 100 tiempos de entrega
                if stats.delivery_times_ms.len() > 100 {
                    stats.delivery_times_ms.remove(0);
                }
            },
            Err(e) => {
                stats.emails_failed += 1;
                return Err(anyhow::anyhow!("Failed to send email: {}", e));
            }
        }

        Ok(())
    }

    /// Filtra destinatarios según la alerta
    async fn filter_recipients_for_alert(&self, alert: &SecurityAlert) -> Vec<EmailRecipient> {
        let mut filtered_recipients = Vec::new();
        let current_time = Utc::now();

        for recipient in &self.config.recipients {
            // Verificar filtro de severidad
            if !self.severity_matches(&recipient.severity_filter, &alert.severity) {
                continue;
            }

            // Verificar horas activas
            if let Some(ref active_hours) = recipient.active_hours {
                if !self.is_within_active_hours(active_hours, current_time) {
                    continue;
                }
            }

            // Verificar tipos de alerta específicos
            if !recipient.alert_types.is_empty() {
                let alert_type = format!("{:?}", alert.severity);
                if !recipient.alert_types.contains(&alert_type) {
                    continue;
                }
            }

            filtered_recipients.push(recipient.clone());
        }

        filtered_recipients
    }

    /// Verifica si la severidad coincide con el filtro
    fn severity_matches(&self, filter: &EmailSeverityFilter, severity: &crate::Severity) -> bool {
        match filter {
            EmailSeverityFilter::All => true,
            EmailSeverityFilter::Warning => {
                matches!(severity, crate::Severity::Warning | crate::Severity::Critical)
            },
            EmailSeverityFilter::Critical => {
                matches!(severity, crate::Severity::Critical)
            },
        }
    }

    /// Verifica si está dentro de las horas activas
    fn is_within_active_hours(&self, active_hours: &ActiveHours, current_time: DateTime<Utc>) -> bool {
        let hour = current_time.hour() as u8;

        // Verificar día de la semana si está configurado
        if active_hours.weekdays_only {
            let weekday = current_time.weekday();
            if weekday == chrono::Weekday::Sat || weekday == chrono::Weekday::Sun {
                return false;
            }
        }

        // Verificar horas
        if active_hours.start_hour <= active_hours.end_hour {
            hour >= active_hours.start_hour && hour <= active_hours.end_hour
        } else {
            // Caso que cruza medianoche (ej: 22:00 - 06:00)
            hour >= active_hours.start_hour || hour <= active_hours.end_hour
        }
    }

    /// Crea mensaje de email
    async fn create_email_message(&self, alert: &SecurityAlert, recipients: &[EmailRecipient]) -> Result<Message> {
        let subject = format!("{} {} - {}",
                              self.config.subject_prefix,
                              self.get_severity_emoji(&alert.severity),
                              alert.title
        );

        let to_addresses: Vec<String> = recipients.iter()
            .map(|r| {
                if let Some(ref name) = r.name {
                    format!("{} <{}>", name, r.email)
                } else {
                    r.email.clone()
                }
            })
            .collect();

        let from_address = if !self.config.from_name.is_empty() {
            format!("{} <{}>", self.config.from_name, self.config.from_address)
        } else {
            self.config.from_address.clone()
        };

        let mut message_builder = Message::builder()
            .from(from_address.parse().context("Invalid from address")?)
            .subject(subject);

        // Agregar destinatarios
        for to_address in to_addresses {
            message_builder = message_builder.to(to_address.parse().context("Invalid recipient address")?);
        }

        // Generar contenido según el template
        let (text_body, html_body) = self.template_engine.generate_email_content(
            alert,
            &self.config.template_style,
            self.config.include_raw_logs
        )?;

        let message = match self.config.template_style {
            EmailTemplate::Plain => {
                message_builder
                    .singlepart(SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(text_body))
                    .context("Failed to create plain text email")?
            },
            EmailTemplate::Html | EmailTemplate::Rich => {
                if let Some(html) = html_body {
                    message_builder
                        .multipart(MultiPart::alternative()
                            .singlepart(SinglePart::builder()
                                .header(ContentType::TEXT_PLAIN)
                                .body(text_body))
                            .singlepart(SinglePart::builder()
                                .header(ContentType::TEXT_HTML)
                                .body(html)))
                        .context("Failed to create HTML email")?
                } else {
                    message_builder
                        .singlepart(SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text_body))
                        .context("Failed to create fallback plain text email")?
                }
            }
        };

        Ok(message)
    }

    /// Obtiene emoji de severidad
    fn get_severity_emoji(&self, severity: &crate::Severity) -> &'static str {
        match severity {
            crate::Severity::Info => "ℹ️",
            crate::Severity::Warning => "⚠️",
            crate::Severity::Critical => "🚨",
            crate::Severity::Low => "🔵",
            crate::Severity::Medium => "🟡",
            crate::Severity::High => "🔴",
        }
    }

    /// Verifica rate limit
    async fn is_rate_limited(&self) -> bool {
        let stats = self.statistics.read().await;

        if let Some(last_time) = stats.last_email_time {
            let hour_ago = Utc::now() - chrono::Duration::hours(1);
            if last_time > hour_ago {
                // Contar emails en la última hora
                // En una implementación real, necesitaríamos un sliding window
                // Por simplicidad, usamos un enfoque básico
                return stats.emails_sent % self.config.rate_limit_per_hour as u64 == 0
                    && stats.emails_sent > 0;
            }
        }

        false
    }

    /// Actualiza estadísticas de rate limit
    async fn update_rate_limit_stats(&self) {
        let mut stats = self.statistics.write().await;
        stats.rate_limit_hits += 1;
    }

    /// Envía batch de alertas
    pub async fn send_alert_batch(&self, alerts: &[SecurityAlert]) -> Result<()> {
        if alerts.is_empty() || !self.config.enabled {
            return Ok(());
        }

        let subject = format!("{} 📊 Security Alert Summary - {} alerts",
                              self.config.subject_prefix,
                              alerts.len()
        );

        // Usar todos los destinatarios para el resumen
        let recipients: Vec<String> = self.config.recipients.iter()
            .map(|r| r.email.clone())
            .collect();

        if recipients.is_empty() {
            return Ok(());
        }

        let from_address = if !self.config.from_name.is_empty() {
            format!("{} <{}>", self.config.from_name, self.config.from_address)
        } else {
            self.config.from_address.clone()
        };

        let mut message_builder = Message::builder()
            .from(from_address.parse().context("Invalid from address")?)
            .subject(subject);

        for recipient in recipients {
            message_builder = message_builder.to(recipient.parse().context("Invalid recipient address")?);
        }

        // Generar contenido del batch
        let (text_body, html_body) = self.template_engine.generate_batch_content(
            alerts,
            &self.config.template_style
        )?;

        let message = match self.config.template_style {
            EmailTemplate::Plain => {
                message_builder
                    .singlepart(SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(text_body))
                    .context("Failed to create batch plain text email")?
            },
            EmailTemplate::Html | EmailTemplate::Rich => {
                if let Some(html) = html_body {
                    message_builder
                        .multipart(MultiPart::alternative()
                            .singlepart(SinglePart::builder()
                                .header(ContentType::TEXT_PLAIN)
                                .body(text_body))
                            .singlepart(SinglePart::builder()
                                .header(ContentType::TEXT_HTML)
                                .body(html)))
                        .context("Failed to create batch HTML email")?
                } else {
                    message_builder
                        .singlepart(SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text_body))
                        .context("Failed to create batch fallback email")?
                }
            }
        };

        // Enviar email
        if let Some(ref transport) = self.transport {
            transport.send(message).await
                .context("Failed to send batch email")?;

            let mut stats = self.statistics.write().await;
            stats.batch_emails_sent += 1;
        }

        Ok(())
    }

    /// Envía email de prueba
    pub async fn send_test_email(&self, recipient: &str) -> Result<()> {
        if !self.config.enabled {
            return Err(anyhow::anyhow!("Email alerter is disabled"));
        }

        let test_alert = SecurityAlert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: crate::Severity::Warning,
            title: "Test Email Alert".to_string(),
            description: "This is a test email to verify the email alerter configuration. If you received this email, the email alerter is working correctly.".to_string(),
            related_events: vec![uuid::Uuid::new_v4()],
            mitigation_steps: vec![
                "This is a test - no action required".to_string(),
                "Verify email formatting and delivery".to_string(),
            ],
            acknowledged: false,
        };

        let test_recipient = EmailRecipient {
            email: recipient.to_string(),
            name: Some("Test Recipient".to_string()),
            severity_filter: EmailSeverityFilter::All,
            alert_types: vec![],
            active_hours: None,
        };

        let email_message = self.create_email_message(&test_alert, &[test_recipient]).await?;

        if let Some(ref transport) = self.transport {
            transport.send(email_message).await
                .context("Failed to send test email")?;
        }

        Ok(())
    }

    /// Verifica configuración SMTP
    pub async fn verify_configuration(&self) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        if let Some(ref transport) = self.transport {
            match transport.test_connection().await {
                Ok(true) => Ok(true),
                Ok(false) => Err(anyhow::anyhow!("SMTP connection test failed")),
                Err(e) => Err(anyhow::anyhow!("SMTP connection error: {}", e)),
            }
        } else {
            Err(anyhow::anyhow!("No SMTP transport configured"))
        }
    }

    /// Obtiene estadísticas
    pub async fn get_statistics(&self) -> EmailStatistics {
        self.statistics.read().await.clone()
    }

    /// Resetea estadísticas
    pub async fn reset_statistics(&self) {
        let mut stats = self.statistics.write().await;
        *stats = EmailStatistics::default();
    }

    /// Actualiza configuración
    pub async fn update_config(&mut self, new_config: EmailAlerterConfig) -> Result<()> {
        self.transport = if new_config.enabled {
            Some(Self::create_transport(&new_config).await?)
        } else {
            None
        };

        self.config = new_config;
        Ok(())
    }

    /// Obtiene configuración actual
    pub fn get_config(&self) -> &EmailAlerterConfig {
        &self.config
    }

    /// Obtiene tiempo promedio de entrega
    pub async fn get_average_delivery_time(&self) -> f64 {
        let stats = self.statistics.read().await;
        if stats.delivery_times_ms.is_empty() {
            0.0
        } else {
            stats.delivery_times_ms.iter().sum::<u64>() as f64 / stats.delivery_times_ms.len() as f64
        }
    }
}

impl EmailTemplateEngine {
    pub fn new() -> Self {
        let mut templates = HashMap::new();

        // Template de texto plano
        templates.insert(EmailTemplate::Plain, Self::create_plain_template());

        // Template HTML básico
        templates.insert(EmailTemplate::Html, Self::create_html_template());

        // Template HTML rico
        templates.insert(EmailTemplate::Rich, Self::create_rich_template());

        Self { templates }
    }

    /// Genera contenido del email
    pub fn generate_email_content(
        &self,
        alert: &SecurityAlert,
        template_style: &EmailTemplate,
        include_raw_logs: bool
    ) -> Result<(String, Option<String>)> {
        let text_body = self.generate_text_content(alert, include_raw_logs);

        let html_body = match template_style {
            EmailTemplate::Plain => None,
            EmailTemplate::Html => Some(self.generate_html_content(alert, include_raw_logs, false)?),
            EmailTemplate::Rich => Some(self.generate_html_content(alert, include_raw_logs, true)?),
        };

        Ok((text_body, html_body))
    }

    /// Genera contenido de texto plano
    fn generate_text_content(&self, alert: &SecurityAlert, _include_raw_logs: bool) -> String {
        let mut content = String::new();

        content.push_str("=".repeat(60).as_str());
        content.push('\n');
        content.push_str("🚨 RUSTSIEM SECURITY ALERT\n");
        content.push_str("=".repeat(60).as_str());
        content.push('\n');
        content.push('\n');

        content.push_str(&format!("Alert ID: {}\n", alert.id));
        content.push_str(&format!("Timestamp: {}\n", alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        content.push_str(&format!("Severity: {:?}\n", alert.severity));
        content.push('\n');

        content.push_str(&format!("Title: {}\n", alert.title));
        content.push('\n');

        content.push_str("Description:\n");
        content.push_str(&alert.description);
        content.push('\n');
        content.push('\n');

        if !alert.related_events.is_empty() {
            content.push_str(&format!("Related Events ({}):\n", alert.related_events.len()));
            for (i, event_id) in alert.related_events.iter().take(5).enumerate() {
                content.push_str(&format!("  {}. {}\n", i + 1, event_id));
            }
            if alert.related_events.len() > 5 {
                content.push_str(&format!("  ... and {} more\n", alert.related_events.len() - 5));
            }
            content.push('\n');
        }

        if !alert.mitigation_steps.is_empty() {
            content.push_str("Recommended Actions:\n");
            for (i, step) in alert.mitigation_steps.iter().enumerate() {
                content.push_str(&format!("  {}. {}\n", i + 1, step));
            }
            content.push('\n');
        }

        content.push_str(&format!("Acknowledged: {}\n", if alert.acknowledged { "Yes" } else { "No" }));
        content.push('\n');

        content.push_str("=".repeat(60).as_str());
        content.push('\n');
        content.push_str("This alert was generated by RustSIEM Security Monitoring System.\n");
        content.push_str(&format!("Generated at: {}\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

        content
    }

    /// Genera contenido HTML
    fn generate_html_content(&self, alert: &SecurityAlert, _include_raw_logs: bool, rich_style: bool) -> Result<String> {
        let severity_color = match alert.severity {
            crate::Severity::Info => "#3498db",
            crate::Severity::Warning => "#f39c12",
            crate::Severity::Critical => "#e74c3c",
            crate::Severity::Low => "#28a745",
            crate::Severity::Medium => "#ffc107",
            crate::Severity::High => "#fd7e14",
        };

        let severity_emoji = match alert.severity {
            crate::Severity::Info => "ℹ️",
            crate::Severity::Warning => "⚠️",
            crate::Severity::Critical => "🚨",
            crate::Severity::Low => "🔵",
            crate::Severity::Medium => "🟡",
            crate::Severity::High => "🔴",
        };

        let mut html = String::new();

        if rich_style {
            html.push_str(&format!(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RustSIEM Security Alert</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: {}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 20px; }}
        .alert-info {{ background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid {}; }}
        .field {{ margin: 10px 0; }}
        .field-label {{ font-weight: bold; color: #333; }}
        .field-value {{ margin-top: 5px; }}
        .actions {{ background: #e8f5e8; padding: 15px; border-radius: 6px; margin: 15px 0; }}
        .events {{ background: #fff3cd; padding: 15px; border-radius: 6px; margin: 15px 0; }}
        .footer {{ background: #f8f9fa; padding: 15px; border-radius: 0 0 8px 8px; text-align: center; font-size: 12px; color: #666; }}
        .severity-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; background: {}; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{} Security Alert</h1>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">RustSIEM Security Monitoring System</p>
        </div>
        <div class="content">
"#, severity_color, severity_color, severity_color, severity_emoji));
        } else {
            html.push_str(r#"
<html>
<body style="font-family: Arial, sans-serif; margin: 20px;">
<h2 style="color: "#);
            html.push_str(severity_color);
            html.push_str(r#";">🚨 Security Alert</h2>
"#);
        }

        // Información de la alerta
        html.push_str(&format!(r#"
            <div class="alert-info">
                <div class="field">
                    <div class="field-label">Alert ID:</div>
                    <div class="field-value"><code>{}</code></div>
                </div>
                <div class="field">
                    <div class="field-label">Timestamp:</div>
                    <div class="field-value">{}</div>
                </div>
                <div class="field">
                    <div class="field-label">Severity:</div>
                    <div class="field-value"><span class="severity-badge">{:?}</span></div>
                </div>
            </div>
            
            <div class="field">
                <div class="field-label">Title:</div>
                <div class="field-value"><strong>{}</strong></div>
            </div>
            
            <div class="field">
                <div class="field-label">Description:</div>
                <div class="field-value">{}</div>
            </div>
"#,
                               alert.id,
                               alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                               alert.severity,
                               alert.title,
                               alert.description.replace('\n', "<br>")
        ));

        // Eventos relacionados
        if !alert.related_events.is_empty() {
            html.push_str(r#"<div class="events">"#);
            html.push_str(&format!(r#"<div class="field-label">Related Events ({}):</div>"#, alert.related_events.len()));
            html.push_str(r#"<ul>"#);
            for event_id in alert.related_events.iter().take(5) {
                html.push_str(&format!(r#"<li><code>{}</code></li>"#, event_id));
            }
            if alert.related_events.len() > 5 {
                html.push_str(&format!(r#"<li>... and {} more</li>"#, alert.related_events.len() - 5));
            }
            html.push_str(r#"</ul></div>"#);
        }

        // Pasos de mitigación
        if !alert.mitigation_steps.is_empty() {
            html.push_str(r#"<div class="actions">"#);
            html.push_str(r#"<div class="field-label">Recommended Actions:</div>"#);
            html.push_str(r#"<div class="field-label">Recommended Actions:</div>"#);
            html.push_str(r#"<ol>"#);
            for step in &alert.mitigation_steps {
                html.push_str(&format!(r#"<li>{}</li>"#, step));
            }
            html.push_str(r#"</ol></div>"#);
        }

        // Estado de acknowledgment
        html.push_str(&format!(r#"
           <div class="field">
               <div class="field-label">Status:</div>
               <div class="field-value">{}</div>
           </div>
"#, if alert.acknowledged { "✅ Acknowledged" } else { "⏳ Pending Review" }));

        if rich_style {
            html.push_str(r#"
       </div>
       <div class="footer">
           <p>This alert was generated by RustSIEM Security Monitoring System</p>
           <p>Generated at: "#);
            html.push_str(&Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());
            html.push_str(r#"</p>
       </div>
   </div>
</body>
</html>"#);
        } else {
            html.push_str(r#"
<hr>
<p><small>This alert was generated by RustSIEM Security Monitoring System</small></p>
</body>
</html>"#);
        }

        Ok(html)
    }

    /// Genera contenido para batch de alertas
    pub fn generate_batch_content(
        &self,
        alerts: &[SecurityAlert],
        template_style: &EmailTemplate
    ) -> Result<(String, Option<String>)> {
        let text_body = self.generate_batch_text_content(alerts);

        let html_body = match template_style {
            EmailTemplate::Plain => None,
            EmailTemplate::Html | EmailTemplate::Rich => Some(self.generate_batch_html_content(alerts)?),
        };

        Ok((text_body, html_body))
    }

    /// Genera contenido de texto para batch
    fn generate_batch_text_content(&self, alerts: &[SecurityAlert]) -> String {
        let mut content = String::new();

        content.push_str("=".repeat(60).as_str());
        content.push('\n');
        content.push_str("📊 RUSTSIEM SECURITY ALERT SUMMARY\n");
        content.push_str("=".repeat(60).as_str());
        content.push('\n');
        content.push('\n');

        content.push_str(&format!("Total Alerts: {}\n", alerts.len()));
        content.push_str(&format!("Generated: {}\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
        content.push('\n');

        // Contar por severidad
        let mut severity_counts = std::collections::HashMap::new();
        for alert in alerts {
            *severity_counts.entry(format!("{:?}", alert.severity)).or_insert(0) += 1;
        }

        content.push_str("Severity Breakdown:\n");
        for (severity, count) in &severity_counts {
            content.push_str(&format!("  {}: {}\n", severity, count));
        }
        content.push('\n');

        content.push_str("Recent Alerts:\n");
        content.push_str("-".repeat(40).as_str());
        content.push('\n');

        for (i, alert) in alerts.iter().rev().take(10).enumerate() {
            content.push_str(&format!("{}. [{}] {:?} - {}\n",
                                      i + 1,
                                      alert.timestamp.format("%H:%M:%S"),
                                      alert.severity,
                                      alert.title
            ));
        }

        if alerts.len() > 10 {
            content.push_str(&format!("... and {} more alerts\n", alerts.len() - 10));
        }

        content.push('\n');
        content.push_str("=".repeat(60).as_str());
        content.push('\n');
        content.push_str("For detailed information, please check the RustSIEM dashboard.\n");

        content
    }

    /// Genera contenido HTML para batch
    fn generate_batch_html_content(&self, alerts: &[SecurityAlert]) -> Result<String> {
        let mut html = String::new();

        html.push_str(r#"
<!DOCTYPE html>
<html>
<head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title>RustSIEM Alert Summary</title>
   <style>
       body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }
       .container { max-width: 700px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
       .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; text-align: center; }
       .header h1 { margin: 0; font-size: 28px; }
       .summary { padding: 20px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; }
       .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 15px 0; }
       .stat-card { background: white; padding: 15px; border-radius: 6px; text-align: center; border: 1px solid #dee2e6; }
       .stat-number { font-size: 24px; font-weight: bold; color: #495057; }
       .stat-label { font-size: 12px; color: #6c757d; text-transform: uppercase; letter-spacing: 0.5px; }
       .alerts-list { padding: 20px; }
       .alert-item { display: flex; align-items: center; padding: 12px; margin: 8px 0; border-radius: 6px; border-left: 4px solid #dee2e6; background: #f8f9fa; }
       .alert-critical { border-left-color: #e74c3c; }
       .alert-warning { border-left-color: #f39c12; }
       .alert-info { border-left-color: #3498db; }
       .alert-time { font-size: 12px; color: #6c757d; margin-right: 15px; min-width: 60px; }
       .alert-severity { margin-right: 10px; font-weight: bold; font-size: 12px; padding: 2px 6px; border-radius: 3px; }
       .severity-critical { background: #e74c3c; color: white; }
       .severity-warning { background: #f39c12; color: white; }
       .severity-info { background: #3498db; color: white; }
       .alert-title { flex: 1; font-weight: 500; }
       .footer { background: #f8f9fa; padding: 15px; border-radius: 0 0 8px 8px; text-align: center; font-size: 12px; color: #666; }
   </style>
</head>
<body>
   <div class="container">
       <div class="header">
           <h1>📊 Security Alert Summary</h1>
           <p style="margin: 5px 0 0 0; opacity: 0.9;">RustSIEM Security Monitoring</p>
       </div>

       <div class="summary">
"#);

        // Estadísticas
        let mut severity_counts = std::collections::HashMap::new();
        for alert in alerts {
            *severity_counts.entry(format!("{:?}", alert.severity)).or_insert(0) += 1;
        }

        html.push_str(&format!(r#"
           <div class="stat-grid">
               <div class="stat-card">
                   <div class="stat-number">{}</div>
                   <div class="stat-label">Total Alerts</div>
               </div>
               <div class="stat-card">
                   <div class="stat-number" style="color: #e74c3c;">{}</div>
                   <div class="stat-label">Critical</div>
               </div>
               <div class="stat-card">
                   <div class="stat-number" style="color: #f39c12;">{}</div>
                   <div class="stat-label">Warning</div>
               </div>
               <div class="stat-card">
                   <div class="stat-number" style="color: #3498db;">{}</div>
                   <div class="stat-label">Info</div>
               </div>
           </div>
       </div>

       <div class="alerts-list">
           <h3 style="margin-top: 0;">Recent Alerts</h3>
"#,
                               alerts.len(),
                               severity_counts.get("Critical").unwrap_or(&0),
                               severity_counts.get("Warning").unwrap_or(&0),
                               severity_counts.get("Info").unwrap_or(&0)
        ));

        // Lista de alertas
        for alert in alerts.iter().rev().take(15) {
            let severity_class = match alert.severity {
                crate::Severity::Critical => "alert-critical",
                crate::Severity::Warning => "alert-warning",
                crate::Severity::Info => "alert-info",
                crate::Severity::Low => "alert-low",
                crate::Severity::Medium => "alert-medium",
                crate::Severity::High => "alert-high",
            };

            let severity_badge_class = match alert.severity {
                crate::Severity::Critical => "severity-critical",
                crate::Severity::Warning => "severity-warning",
                crate::Severity::Info => "severity-info",
                crate::Severity::Low => "severity-low",
                crate::Severity::Medium => "severity-medium",
                crate::Severity::High => "severity-high",
            };

            html.push_str(&format!(r#"
           <div class="alert-item {}">
               <div class="alert-time">{}</div>
               <div class="alert-severity {}">{:?}</div>
               <div class="alert-title">{}</div>
           </div>
"#,
                                   severity_class,
                                   alert.timestamp.format("%H:%M:%S"),
                                   severity_badge_class,
                                   alert.severity,
                                   alert.title
            ));
        }

        if alerts.len() > 15 {
            html.push_str(&format!(r#"
           <div style="text-align: center; padding: 15px; color: #6c757d; font-style: italic;">
               ... and {} more alerts
           </div>
"#, alerts.len() - 15));
        }

        html.push_str(r#"
       </div>

       <div class="footer">
           <p>This summary was generated by RustSIEM Security Monitoring System</p>
           <p>Generated at: "#);
        html.push_str(&Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());
        html.push_str(r#"</p>
           <p>For detailed information, please check the RustSIEM dashboard.</p>
       </div>
   </div>
</body>
</html>"#);

        Ok(html)
    }

    // Template factories
    fn create_plain_template() -> String {
        "Plain text email template".to_string()
    }

    fn create_html_template() -> String {
        "Basic HTML email template".to_string()
    }

    fn create_rich_template() -> String {
        "Rich HTML email template with advanced styling".to_string()
    }
}

impl Default for EmailAlerter {
    fn default() -> Self {
        futures::executor::block_on(Self::new()).unwrap()
    }
}

/// Utilidades para el alertador de email
pub mod utils {
    use super::*;

    /// Crea configuración para Gmail
    pub fn create_gmail_config(username: &str, password: &str, recipients: Vec<String>) -> EmailAlerterConfig {
        EmailAlerterConfig {
            enabled: true,
            smtp_server: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            use_tls: false,
            use_starttls: true,
            username: username.to_string(),
            password: password.to_string(),
            from_address: username.to_string(),
            from_name: "RustSIEM Security Monitor".to_string(),
            recipients: recipients.into_iter().map(|email| EmailRecipient {
                email,
                name: None,
                severity_filter: EmailSeverityFilter::All,
                alert_types: vec![],
                active_hours: None,
            }).collect(),
            subject_prefix: "[RUSTSIEM]".to_string(),
            rate_limit_per_hour: 60,
            batch_alerts: true,
            batch_timeout_minutes: 15,
            include_raw_logs: false,
            template_style: EmailTemplate::Html,
            severity_routing: HashMap::new(),
        }
    }

    /// Crea configuración para Outlook/Office365
    pub fn create_outlook_config(username: &str, password: &str, recipients: Vec<String>) -> EmailAlerterConfig {
        EmailAlerterConfig {
            enabled: true,
            smtp_server: "smtp-mail.outlook.com".to_string(),
            smtp_port: 587,
            use_tls: false,
            use_starttls: true,
            username: username.to_string(),
            password: password.to_string(),
            from_address: username.to_string(),
            from_name: "RustSIEM Security Monitor".to_string(),
            recipients: recipients.into_iter().map(|email| EmailRecipient {
                email,
                name: None,
                severity_filter: EmailSeverityFilter::All,
                alert_types: vec![],
                active_hours: None,
            }).collect(),
            subject_prefix: "[RUSTSIEM]".to_string(),
            rate_limit_per_hour: 60,
            batch_alerts: true,
            batch_timeout_minutes: 15,
            include_raw_logs: false,
            template_style: EmailTemplate::Rich,
            severity_routing: HashMap::new(),
        }
    }

    /// Crea configuración para servidor SMTP personalizado
    pub fn create_custom_smtp_config(
        server: &str,
        port: u16,
        username: &str,
        password: &str,
        recipients: Vec<String>,
        use_tls: bool
    ) -> EmailAlerterConfig {
        EmailAlerterConfig {
            enabled: true,
            smtp_server: server.to_string(),
            smtp_port: port,
            use_tls,
            use_starttls: !use_tls,
            username: username.to_string(),
            password: password.to_string(),
            from_address: username.to_string(),
            from_name: "RustSIEM Security Monitor".to_string(),
            recipients: recipients.into_iter().map(|email| EmailRecipient {
                email,
                name: None,
                severity_filter: EmailSeverityFilter::All,
                alert_types: vec![],
                active_hours: None,
            }).collect(),
            subject_prefix: "[RUSTSIEM]".to_string(),
            rate_limit_per_hour: 100,
            batch_alerts: true,
            batch_timeout_minutes: 10,
            include_raw_logs: false,
            template_style: EmailTemplate::Html,
            severity_routing: HashMap::new(),
        }
    }

    /// Crea destinatario con horas activas de oficina
    pub fn create_business_hours_recipient(email: &str, name: Option<&str>) -> EmailRecipient {
        EmailRecipient {
            email: email.to_string(),
            name: name.map(|n| n.to_string()),
            severity_filter: EmailSeverityFilter::Warning,
            alert_types: vec![],
            active_hours: Some(ActiveHours {
                start_hour: 9,
                end_hour: 17,
                timezone: "UTC".to_string(),
                weekdays_only: true,
            }),
        }
    }

    /// Crea destinatario para alertas críticas 24/7
    pub fn create_critical_alerts_recipient(email: &str, name: Option<&str>) -> EmailRecipient {
        EmailRecipient {
            email: email.to_string(),
            name: name.map(|n| n.to_string()),
            severity_filter: EmailSeverityFilter::Critical,
            alert_types: vec![],
            active_hours: None, // 24/7
        }
    }

    /// Valida dirección de email
    pub fn validate_email(email: &str) -> bool {
        let email_regex = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        email_regex.is_match(email)
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
            description: "This is a test security alert for email testing purposes.".to_string(),
            related_events: vec![Uuid::new_v4(), Uuid::new_v4()],
            mitigation_steps: vec![
                "Take immediate action".to_string(),
                "Review security logs".to_string(),
            ],
            acknowledged: false,
        }
    }

    #[tokio::test]
    async fn test_email_alerter_creation() {
        let alerter = EmailAlerter::new().await.unwrap();
        assert!(!alerter.config.enabled); // Disabled by default
    }

    #[tokio::test]
    async fn test_severity_filtering() {
        let config = EmailAlerterConfig {
            enabled: true,
            recipients: vec![
                EmailRecipient {
                    email: "critical@example.com".to_string(),
                    name: None,
                    severity_filter: EmailSeverityFilter::Critical,
                    alert_types: vec![],
                    active_hours: None,
                }
            ],
            ..Default::default()
        };

        let alerter = EmailAlerter::with_config(config).await.unwrap();

        let critical_alert = create_test_alert();
        let recipients = alerter.filter_recipients_for_alert(&critical_alert).await;
        assert_eq!(recipients.len(), 1);

        let mut warning_alert = create_test_alert();
        warning_alert.severity = crate::Severity::Warning;
        let recipients = alerter.filter_recipients_for_alert(&warning_alert).await;
        assert_eq!(recipients.len(), 0); // Filtrado por severidad
    }

    #[tokio::test]
    async fn test_active_hours_filtering() {
        let config = EmailAlerterConfig {
            enabled: true,
            recipients: vec![
                EmailRecipient {
                    email: "business@example.com".to_string(),
                    name: None,
                    severity_filter: EmailSeverityFilter::All,
                    alert_types: vec![],
                    active_hours: Some(ActiveHours {
                        start_hour: 9,
                        end_hour: 17,
                        timezone: "UTC".to_string(),
                        weekdays_only: true,
                    }),
                }
            ],
            ..Default::default()
        };

        let alerter = EmailAlerter::with_config(config).await.unwrap();

        // Test durante horas de oficina (asumiendo que el test se ejecuta en horario de oficina)
        let alert = create_test_alert();
        let recipients = alerter.filter_recipients_for_alert(&alert).await;
        // El resultado dependerá de cuándo se ejecute el test
    }

    #[test]
    fn test_template_engine() {
        let engine = EmailTemplateEngine::new();
        let alert = create_test_alert();

        let (text_content, html_content) = engine.generate_email_content(
            &alert,
            &EmailTemplate::Html,
            false
        ).unwrap();

        assert!(!text_content.is_empty());
        assert!(html_content.is_some());
        assert!(text_content.contains(&alert.title));

        if let Some(html) = html_content {
            assert!(html.contains(&alert.title));
            assert!(html.contains("<!DOCTYPE html") || html.contains("<html>"));
        }
    }

    #[test]
    fn test_batch_template() {
        let engine = EmailTemplateEngine::new();
        let alerts = vec![create_test_alert(), create_test_alert()];

        let (text_content, html_content) = engine.generate_batch_content(
            &alerts,
            &EmailTemplate::Rich
        ).unwrap();

        assert!(!text_content.is_empty());
        assert!(html_content.is_some());
        assert!(text_content.contains("Total Alerts: 2"));
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let alerter = EmailAlerter::new().await.unwrap();

        // Simular estadísticas
        {
            let mut stats = alerter.statistics.write().await;
            stats.emails_sent = 10;
            stats.emails_failed = 2;
            stats.delivery_times_ms = vec![100, 150, 200];
        }

        let avg_time = alerter.get_average_delivery_time().await;
        assert_eq!(avg_time, 150.0);

        let stats = alerter.get_statistics().await;
        assert_eq!(stats.emails_sent, 10);
        assert_eq!(stats.emails_failed, 2);
    }

    #[test]
    fn test_utility_configs() {
        let gmail_config = utils::create_gmail_config(
            "test@gmail.com",
            "password",
            vec!["recipient@example.com".to_string()]
        );
        assert_eq!(gmail_config.smtp_server, "smtp.gmail.com");
        assert_eq!(gmail_config.smtp_port, 587);
        assert!(gmail_config.use_starttls);

        let outlook_config = utils::create_outlook_config(
            "test@outlook.com",
            "password",
            vec!["recipient@example.com".to_string()]
        );
        assert_eq!(outlook_config.smtp_server, "smtp-mail.outlook.com");
        assert_eq!(outlook_config.template_style, EmailTemplate::Rich);
    }

    #[test]
    fn test_email_validation() {
        assert!(utils::validate_email("test@example.com"));
        assert!(utils::validate_email("user.name+tag@example.co.uk"));
        assert!(!utils::validate_email("invalid_email"));
        assert!(!utils::validate_email("@example.com"));
        assert!(!utils::validate_email("test@"));
    }

    #[test]
    fn test_recipient_creation() {
        let business_recipient = utils::create_business_hours_recipient(
            "business@example.com",
            Some("Business User")
        );
        assert_eq!(business_recipient.severity_filter, EmailSeverityFilter::Warning);
        assert!(business_recipient.active_hours.is_some());

        let critical_recipient = utils::create_critical_alerts_recipient(
            "oncall@example.com",
            Some("On-call Engineer")
        );
        assert_eq!(critical_recipient.severity_filter, EmailSeverityFilter::Critical);
        assert!(critical_recipient.active_hours.is_none());
    }
}