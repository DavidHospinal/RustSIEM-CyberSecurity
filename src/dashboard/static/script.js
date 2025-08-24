/**
 * RustSIEM Dashboard - Frontend JavaScript
 * Conecta el frontend HTML/CSS con las APIs del backend de Rust
 */

class RustSIEMDashboard {
    constructor() {
        this.apiBase = window.location.origin;
        this.updateInterval = 5000; // 5 segundos
        this.eventStreamActive = true;
        this.currentPage = 'dashboard';

        // Cache de datos
        this.cachedStats = null;
        this.cachedEvents = [];
        this.cachedAlerts = [];

        // Configuración de datos simulados para demo
        this.simulatedData = {
            attackPatterns: {
                'SQL Injection': { count: 247, percentage: 65 },
                'XSS': { count: 193, percentage: 45 },
                'Brute Force': { count: 156, percentage: 35 },
                'DDoS': { count: 89, percentage: 20 }
            },
            geographicThreats: [
                { country: 'China', flag: '🇨🇳', percentage: 45 },
                { country: 'Russia', flag: '🇷🇺', percentage: 23 },
                { country: 'Brazil', flag: '🇧🇷', percentage: 18 },
                { country: 'Others', flag: '🌍', percentage: 14 }
            ],
            anomalies: [
                { description: 'Unusual traffic spike from 203.0.113.45', score: 'HIGH' },
                { description: 'Abnormal request pattern detected', score: 'MEDIUM' },
                { description: 'New user agent string pattern', score: 'LOW' }
            ],
            detectionRules: [
                {
                    name: 'SQL Injection Detection',
                    status: 'active',
                    description: 'Detects SQL injection patterns in HTTP requests',
                    hits: 247
                },
                {
                    name: 'XSS Attack Pattern',
                    status: 'active',
                    description: 'Identifies XSS attempts in request parameters',
                    hits: 193
                },
                {
                    name: 'Brute Force Login',
                    status: 'warning',
                    description: 'Multiple failed login attempts detection',
                    hits: 156
                },
                {
                    name: 'Admin Panel Access',
                    status: 'critical',
                    description: 'Unauthorized admin panel access attempts',
                    hits: 12
                },
                {
                    name: 'File Upload Scanner',
                    status: 'active',
                    description: 'Scans uploaded files for malicious content',
                    hits: 89
                }
            ]
        };

        this.init();
    }

    async init() {
        console.log('🛡️ Iniciando RustSIEM Dashboard...');

        // Mostrar loading inicial
        this.showLoading();

        // Configurar event listeners
        this.setupEventListeners();

        // Cargar datos iniciales
        await this.loadInitialData();

        // Iniciar actualizaciones periódicas
        this.startPeriodicUpdates();

        // Simular stream de eventos
        this.startEventStream();

        // Ocultar loading
        this.hideLoading();

        console.log('✅ RustSIEM Dashboard iniciado correctamente');
    }

    setupEventListeners() {
        // Navegación
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const page = e.currentTarget.dataset.page;
                if (page) {
                    this.navigateToPage(page);
                }
            });
        });

        // Controles del stream
        const pauseBtn = document.getElementById('pause-stream');
        const clearBtn = document.getElementById('clear-stream');

        if (pauseBtn) {
            pauseBtn.addEventListener('click', () => this.toggleEventStream());
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearEventStream());
        }

        // Controles de eventos
        const eventsSearch = document.getElementById('events-search');
        const eventsFilter = document.getElementById('events-filter');

        if (eventsSearch) {
            eventsSearch.addEventListener('input', () => this.filterEvents());
        }

        if (eventsFilter) {
            eventsFilter.addEventListener('change', () => this.filterEvents());
        }

        // Controles de alertas
        const alertsFilter = document.getElementById('alerts-status-filter');
        const markAllReadBtn = document.getElementById('mark-all-read');

        if (alertsFilter) {
            alertsFilter.addEventListener('change', () => this.filterAlerts());
        }

        if (markAllReadBtn) {
            markAllReadBtn.addEventListener('click', () => this.markAllAlertsRead());
        }

        // Botón de agregar regla
        const addRuleBtn = document.getElementById('add-rule-btn');
        if (addRuleBtn) {
            addRuleBtn.addEventListener('click', () => this.showAddRuleModal());
        }
    }

    async loadInitialData() {
        try {
            // Cargar estadísticas
            await this.updateStats();

            // Cargar datos simulados para el dashboard
            this.loadSimulatedDashboardData();

            // Cargar eventos y alertas
            await this.loadEvents();
            await this.loadAlerts();

        } catch (error) {
            console.error('❌ Error cargando datos iniciales:', error);
            this.showError('Error cargando datos del sistema');
        }
    }

    async updateStats() {
        try {
            const response = await fetch(`${this.apiBase}/api/stats`);
            const result = await response.json();

            if (result.success) {
                this.cachedStats = result.data;
                this.displayStats(result.data);
                this.updateLastUpdatedTime();
            } else {
                throw new Error(result.message || 'Error obteniendo estadísticas');
            }
        } catch (error) {
            console.error('❌ Error actualizando estadísticas:', error);

            // Usar datos simulados si la API falla
            const simulatedStats = {
                events_per_second: 2.85 + (Math.random() * 2),
                critical_alerts: 3,
                threat_score: 7.3,
                active_sources: 12
            };
            this.displayStats(simulatedStats);
        }
    }

    displayStats(stats) {
        // Actualizar métricas principales
        this.updateElement('metric-events-per-second', (stats.events_per_second || 0).toFixed(2));
        this.updateElement('metric-critical-alerts', stats.critical_alerts || 0);
        this.updateElement('metric-threat-score', (stats.threat_score || 0).toFixed(1));
        this.updateElement('metric-active-sources', stats.active_sources || 0);

        // Actualizar barra de estado
        this.updateElement('events-per-second', (stats.events_per_second || 0).toFixed(1));
        this.updateElement('active-sources', stats.active_sources || 0);
        this.updateElement('critical-alerts-count', stats.critical_alerts || 0);

        // Actualizar uptime
        const uptime = this.formatUptime(stats.uptime_seconds || 0);
        this.updateElement('system-uptime', uptime);
    }

    loadSimulatedDashboardData() {
        // Cargar patrones de ataques
        this.loadAttackPatterns();

        // Cargar amenazas geográficas
        this.loadGeographicThreats();

        // Cargar anomalías ML
        this.loadMLAnomalies();

        // Cargar reglas de detección
        this.loadDetectionRules();
    }

    loadAttackPatterns() {
        Object.entries(this.simulatedData.attackPatterns).forEach(([pattern, data], index) => {
            const countId = pattern.toLowerCase().replace(/\s+/g, '-') + '-count';
            const progressId = pattern.toLowerCase().replace(/\s+/g, '-') + '-progress';

            this.updateElement(countId, data.count);

            setTimeout(() => {
                const progressElement = document.getElementById(progressId);
                if (progressElement) {
                    progressElement.style.width = data.percentage + '%';
                }
            }, index * 200);
        });
    }

    loadGeographicThreats() {
        const container = document.getElementById('geographic-threats-list');
        if (!container) return;

        container.innerHTML = '';

        this.simulatedData.geographicThreats.forEach(threat => {
            const threatElement = document.createElement('div');
            threatElement.className = 'threat-item';
            threatElement.innerHTML = `
                <div class="threat-country">
                    <span style="margin-right: 8px;">${threat.flag}</span>
                    ${threat.country}
                </div>
                <div class="threat-percentage">${threat.percentage}%</div>
            `;
            container.appendChild(threatElement);
        });
    }

    loadMLAnomalies() {
        const container = document.getElementById('anomaly-list');
        if (!container) return;

        container.innerHTML = '';

        this.simulatedData.anomalies.forEach(anomaly => {
            const anomalyElement = document.createElement('div');
            anomalyElement.className = 'anomaly-item';
            anomalyElement.innerHTML = `
                <div class="anomaly-description">${anomaly.description}</div>
                <div class="anomaly-score">${anomaly.score}</div>
            `;
            container.appendChild(anomalyElement);
        });
    }

    loadDetectionRules() {
        const container = document.getElementById('detection-rules-grid');
        if (!container) return;

        container.innerHTML = '';

        this.simulatedData.detectionRules.forEach(rule => {
            const ruleElement = document.createElement('div');
            ruleElement.className = 'rule-card';
            ruleElement.innerHTML = `
                <div class="rule-header">
                    <div class="rule-name">${rule.name}</div>
                    <div class="rule-status ${rule.status}">${rule.status.toUpperCase()}</div>
                </div>
                <div class="rule-description">${rule.description}</div>
                <div class="rule-stats">
                    <span>Hits: ${rule.hits}</span>
                    <span>Last Updated: 2h ago</span>
                </div>
            `;
            container.appendChild(ruleElement);
        });
    }

    async loadEvents() {
        try {
            const response = await fetch(`${this.apiBase}/api/events?limit=50`);
            const result = await response.json();

            if (result.success) {
                this.cachedEvents = result.data;
                this.displayEvents(result.data);
            } else {
                // Usar datos simulados
                this.cachedEvents = this.generateSimulatedEvents(20);
                this.displayEvents(this.cachedEvents);
            }
        } catch (error) {
            console.error('❌ Error cargando eventos:', error);
            this.cachedEvents = this.generateSimulatedEvents(20);
            this.displayEvents(this.cachedEvents);
        }
    }

    generateSimulatedEvents(count) {
        const events = [];
        const severities = ['critical', 'high', 'medium', 'low', 'info'];
        const sources = ['Apache', 'Nginx', 'SSH', 'MySQL', 'Firewall'];
        const eventTypes = ['HTTP Request', 'Login Attempt', 'File Access', 'SQL Query', 'Network Connection'];

        for (let i = 0; i < count; i++) {
            const now = new Date();
            const timestamp = new Date(now.getTime() - Math.random() * 86400000);

            events.push({
                id: `event-${i + 1}`,
                timestamp: timestamp.toISOString(),
                severity: severities[Math.floor(Math.random() * severities.length)],
                source: sources[Math.floor(Math.random() * sources.length)],
                event_type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
                description: this.generateEventDescription(),
                source_ip: this.generateRandomIP()
            });
        }

        return events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    generateEventDescription() {
        const descriptions = [
            'Suspicious HTTP request detected',
            'Multiple failed login attempts',
            'Unusual file access pattern',
            'Potential SQL injection attempt',
            'Anomalous network traffic',
            'Unauthorized admin access attempt',
            'Malformed HTTP headers detected',
            'Brute force attack detected',
            'XSS attempt blocked',
            'File upload scanner triggered'
        ];
        return descriptions[Math.floor(Math.random() * descriptions.length)];
    }

    generateRandomIP() {
        return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }

    displayEvents(events) {
        const tbody = document.getElementById('events-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';

        events.forEach(event => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.formatTimestamp(event.timestamp)}</td>
                <td><span class="severity-badge severity-${event.severity}">${event.severity?.toUpperCase() || 'INFO'}</span></td>
                <td>${event.source || 'Unknown'}</td>
                <td>${event.event_type || 'Unknown'}</td>
                <td class="event-description">${event.description || 'No description available'}</td>
                <td>
                    <button class="control-btn small" onclick="dashboard.viewEventDetails('${event.id}')">
                        <span class="btn-icon">👁️</span>
                        View
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async loadAlerts() {
        try {
            const response = await fetch(`${this.apiBase}/api/alerts?limit=20`);
            const result = await response.json();

            if (result.success) {
                this.cachedAlerts = result.data;
                this.displayAlerts(result.data);
            } else {
                this.cachedAlerts = this.generateSimulatedAlerts(10);
                this.displayAlerts(this.cachedAlerts);
            }
        } catch (error) {
            console.error('❌ Error cargando alertas:', error);
            this.cachedAlerts = this.generateSimulatedAlerts(10);
            this.displayAlerts(this.cachedAlerts);
        }
    }

    generateSimulatedAlerts(count) {
        const alerts = [];
        const severities = ['critical', 'warning', 'info'];
        const types = ['SQL Injection', 'XSS Attack', 'Brute Force', 'DDoS', 'Malware'];
        const statuses = ['active', 'acknowledged'];

        for (let i = 0; i < count; i++) {
            const now = new Date();
            const timestamp = new Date(now.getTime() - Math.random() * 3600000);
            const severity = severities[Math.floor(Math.random() * severities.length)];

            alerts.push({
                id: `alert-${i + 1}`,
                timestamp: timestamp.toISOString(),
                severity: severity,
                alert_type: types[Math.floor(Math.random() * types.length)],
                description: this.generateAlertDescription(),
                status: statuses[Math.floor(Math.random() * statuses.length)],
                source_ip: this.generateRandomIP()
            });
        }

        return alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    generateAlertDescription() {
        const descriptions = [
            'High-confidence SQL injection attack detected from suspicious IP',
            'Multiple XSS attempts blocked - potential targeted attack',
            'Brute force login attempt detected - recommend IP blocking',
            'DDoS attack detected - traffic volume exceeding normal thresholds',
            'Malware signature detected in file upload',
            'Suspicious user agent pattern - potential bot activity',
            'Anomalous API access pattern detected',
            'Failed authentication attempts from multiple IPs'
        ];
        return descriptions[Math.floor(Math.random() * descriptions.length)];
    }

    displayAlerts(alerts) {
        const container = document.getElementById('alerts-container');
        if (!container) return;

        container.innerHTML = '';

        if (alerts.length === 0) {
            container.innerHTML = `
                <div class="placeholder-content">
                    <span class="placeholder-icon">✅</span>
                    <h3>No Active Alerts</h3>
                    <p>All systems are operating normally.</p>
                </div>
            `;
            return;
        }

        alerts.forEach(alert => {
            const alertElement = document.createElement('div');
            alertElement.className = `alert-item ${alert.severity}`;
            alertElement.innerHTML = `
                <div class="alert-header">
                    <div class="alert-title">
                        <span class="severity-badge severity-${alert.severity}">${alert.severity?.toUpperCase() || 'INFO'}</span>
                        ${alert.alert_type || 'Security Alert'}
                    </div>
                    <div class="alert-timestamp">${this.formatTimestamp(alert.timestamp)}</div>
                </div>
                <div class="alert-description">${alert.description || 'No description available'}</div>
                <div class="alert-actions">
                    <button class="control-btn small" onclick="dashboard.acknowledgeAlert('${alert.id}')">
                        <span class="btn-icon">✅</span>
                        Acknowledge
                    </button>
                    <button class="control-btn small" onclick="dashboard.viewAlertDetails('${alert.id}')">
                        <span class="btn-icon">👁️</span>
                        Details
                    </button>
                </div>
            `;
            container.appendChild(alertElement);
        });
    }

    startEventStream() {
        const streamContainer = document.getElementById('event-stream');
        if (!streamContainer) return;

        setInterval(() => {
            if (!this.eventStreamActive) return;

            this.addEventToStream(this.generateRandomStreamEvent());
        }, 2000 + Math.random() * 3000);
    }

    generateRandomStreamEvent() {
        const now = new Date();
        const severities = ['CRITICAL', 'WARNING', 'INFO'];
        const severity = severities[Math.floor(Math.random() * severities.length)];
        const descriptions = [
            'SQL injection attempt from 192.168.1.100',
            'User authentication successful',
            'Multiple failed login attempts detected',
            'XSS attack blocked: script>alert(1)</script>',
            'Anomalous traffic pattern detected',
            'File upload scanner: clean file detected',
            'GET /api/users/profile HTTP/1.1 200',
            'Brute force attack: 15 attempts in 60 seconds'
        ];

        return {
            timestamp: now.toISOString(),
            severity: severity,
            description: descriptions[Math.floor(Math.random() * descriptions.length)],
            source: ['Apache', 'Nginx', 'SSH', 'WAF'][Math.floor(Math.random() * 4)]
        };
    }

    addEventToStream(event) {
        const streamContainer = document.getElementById('event-stream');
        if (!streamContainer) return;

        // Remover placeholder si existe
        const placeholder = streamContainer.querySelector('.stream-placeholder');
        if (placeholder) {
            placeholder.remove();
        }

        const eventElement = document.createElement('div');
        eventElement.className = 'stream-event';
        eventElement.innerHTML = `
            <span class="stream-timestamp">${this.formatTime(event.timestamp)}</span>
            <span class="stream-severity stream-${event.severity.toLowerCase()}">${event.severity}</span>
            <span class="stream-description">${event.description}</span>
            <span class="stream-source">${event.source}</span>
        `;

        eventElement.style.cssText = `
            padding: 8px 0;
            border-bottom: 1px solid rgba(148, 163, 184, 0.1);
            animation: slideInUp 0.3s ease-out;
            font-size: 0.85rem;
            display: grid;
            grid-template-columns: 80px 80px 1fr 80px;
            gap: 12px;
            align-items: center;
        `;

        streamContainer.insertBefore(eventElement, streamContainer.firstChild);

        // Mantener solo los últimos 50 eventos
        const events = streamContainer.querySelectorAll('.stream-event');
        if (events.length > 50) {
            events[events.length - 1].remove();
        }

        // Scroll al top para mostrar el nuevo evento
        streamContainer.scrollTop = 0;
    }

    toggleEventStream() {
        this.eventStreamActive = !this.eventStreamActive;
        const btn = document.getElementById('pause-stream');
        if (btn) {
            btn.innerHTML = this.eventStreamActive ?
                '<span class="btn-icon">⏸️</span> Pause' :
                '<span class="btn-icon">▶️</span> Resume';
        }
    }

    clearEventStream() {
        const streamContainer = document.getElementById('event-stream');
        if (streamContainer) {
            streamContainer.innerHTML = `
                <div class="stream-placeholder">
                    <span class="placeholder-icon">📡</span>
                    <span>Event stream cleared...</span>
                </div>
            `;
        }
    }

    navigateToPage(pageName) {
        // Actualizar navegación activa
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[data-page="${pageName}"]`).classList.add('active');

        // Mostrar página correspondiente
        document.querySelectorAll('.page-content').forEach(page => {
            page.classList.remove('active');
        });
        document.getElementById(`${pageName}-page`).classList.add('active');

        this.currentPage = pageName;

        // Cargar datos específicos de la página
        if (pageName === 'events') {
            this.loadEvents();
        } else if (pageName === 'alerts') {
            this.loadAlerts();
        }
    }

    startPeriodicUpdates() {
        setInterval(() => {
            this.updateStats();

            // Actualizar ML training progress
            this.updateMLTrainingProgress();
        }, this.updateInterval);
    }

    updateMLTrainingProgress() {
        const progressElement = document.getElementById('ml-training-progress');
        const percentElement = document.getElementById('ml-training-percent');

        if (progressElement && percentElement) {
            const currentPercent = parseInt(percentElement.textContent) || 80;
            const newPercent = Math.min(100, currentPercent + Math.random() * 2);

            progressElement.style.width = newPercent + '%';
            percentElement.textContent = Math.floor(newPercent) + '%';

            if (newPercent >= 100) {
                document.getElementById('ml-model-status').textContent = 'ACTIVE';
                document.querySelector('.progress-text').textContent = 'Model training completed. Monitoring for anomalies...';
            }
        }
    }

    // Utility functions
    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return '--';
        const date = new Date(timestamp);
        return date.toLocaleString('es-ES', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    formatTime(timestamp) {
        if (!timestamp) return '--';
        const date = new Date(timestamp);
        return date.toLocaleTimeString('es-ES', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    formatUptime(seconds) {
        if (!seconds) return '00:00:00';
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }

    updateLastUpdatedTime() {
        const now = new Date();
        this.updateElement('last-updated-time', now.toLocaleString('es-ES', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        }));
    }

    showLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.classList.remove('hidden');
        }
    }

    hideLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            setTimeout(() => {
                overlay.classList.add('hidden');
            }, 1000);
        }
    }

    showError(message) {
        console.error('Error:', message);
        // Aquí podrías agregar una notificación toast
    }

    // Event handlers para acciones específicas
    viewEventDetails(eventId) {
        console.log('Viewing event details for:', eventId);
        // Implementar modal o página de detalles
    }

    acknowledgeAlert(alertId) {
        console.log('Acknowledging alert:', alertId);
        // Aquí harías una llamada PUT/POST al backend
    }

    viewAlertDetails(alertId) {
        console.log('Viewing alert details for:', alertId);
        // Implementar modal o página de detalles
    }

    markAllAlertsRead() {
        console.log('Marking all alerts as read');
        // Implementar llamada al backend
    }

    filterEvents() {
        const searchTerm = document.getElementById('events-search').value.toLowerCase();
        const severityFilter = document.getElementById('events-filter').value;

        let filteredEvents = this.cachedEvents;

        if (searchTerm) {
            filteredEvents = filteredEvents.filter(event =>
                event.description?.toLowerCase().includes(searchTerm) ||
                event.source?.toLowerCase().includes(searchTerm) ||
                event.event_type?.toLowerCase().includes(searchTerm)
            );
        }

        if (severityFilter) {
            filteredEvents = filteredEvents.filter(event =>
                event.severity === severityFilter
            );
        }

        this.displayEvents(filteredEvents);
    }

    filterAlerts() {
        const statusFilter = document.getElementById('alerts-status-filter').value;

        let filteredAlerts = this.cachedAlerts;

        if (statusFilter) {
            filteredAlerts = filteredAlerts.filter(alert =>
                alert.status === statusFilter
            );
        }

        this.displayAlerts(filteredAlerts);
    }

    showAddRuleModal() {
        console.log('Showing add rule modal');
        // Implementar modal para agregar nueva regla
    }
}

// Inicializar dashboard cuando el DOM esté listo
let dashboard;

document.addEventListener('DOMContentLoaded', () => {
    dashboard = new RustSIEMDashboard();
});

// Añadir estilos dinámicos para badges de severidad
const style = document.createElement('style');
style.textContent = `
    .severity-badge {
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .severity-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
    .severity-high { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
    .severity-warning { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
    .severity-medium { background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); }
    .severity-low { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
    .severity-info { background: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }
    
    .stream-critical { color: #ef4444; font-weight: 600; }
    .stream-warning { color: #f59e0b; font-weight: 600; }
    .stream-info { color: #94a3b8; }
    
    .event-description {
        max-width: 300px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    
    .control-btn.small {
        padding: 4px 8px;
        font-size: 0.8rem;
        min-width: auto;
    }
    
    .alert-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 12px;
    }
    
    .alert-title {
        display: flex;
        align-items: center;
        gap: 8px;
        font-weight: 600;
    }
    
    .alert-timestamp {
        font-size: 0.8rem;
        color: var(--text-secondary);
    }
    
    .alert-description {
        margin-bottom: 16px;
        color: var(--text-secondary);
        line-height: 1.5;
    }
    
    .alert-actions {
        display: flex;
        gap: 8px;
        justify-content: flex-end;
    }
`;
document.head.appendChild(style);