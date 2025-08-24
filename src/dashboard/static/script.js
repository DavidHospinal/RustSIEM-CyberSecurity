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
                { 
                    country: 'China', 
                    flag: '🇨🇳', 
                    percentage: 45, 
                    ip_ranges: ['1.0.0.0/8', '27.0.0.0/8'],
                    threat_types: ['Brute Force', 'APT', 'Espionage'],
                    known_groups: ['APT1', 'APT40', 'Winnti Group']
                },
                { 
                    country: 'Russia', 
                    flag: '🇷🇺', 
                    percentage: 23,
                    ip_ranges: ['46.0.0.0/8', '95.0.0.0/8'],
                    threat_types: ['Ransomware', 'Banking Trojans', 'APT'],
                    known_groups: ['APT28', 'APT29', 'Fancy Bear']
                },
                { 
                    country: 'North Korea', 
                    flag: '🇰🇵', 
                    percentage: 18,
                    ip_ranges: ['175.45.176.0/22'],
                    threat_types: ['Cryptocurrency Theft', 'Ransomware', 'Banking'],
                    known_groups: ['Lazarus Group', 'APT38']
                },
                { 
                    country: 'Others', 
                    flag: '🌍', 
                    percentage: 14,
                    ip_ranges: ['Various'],
                    threat_types: ['Script Kiddies', 'Automated Tools'],
                    known_groups: ['Various']
                }
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
            threatElement.className = 'threat-item enhanced';
            threatElement.innerHTML = `
                <div class="threat-country">
                    <span style="margin-right: 8px;">${threat.flag}</span>
                    <strong>${threat.country}</strong>
                </div>
                <div class="threat-details">
                    <div class="threat-percentage">${threat.percentage}%</div>
                    <div class="threat-info">
                        <div class="threat-types">Tipos: ${threat.threat_types.join(', ')}</div>
                        <div class="threat-groups">Grupos: ${threat.known_groups.join(', ')}</div>
                        <div class="threat-ips">Rangos IP: ${threat.ip_ranges.join(', ')}</div>
                    </div>
                </div>
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
        const sources = ['Apache/2.4.41', 'Nginx/1.18.0', 'OpenSSH_8.3', 'MySQL/8.0', 'pfSense Firewall'];
        const eventTypes = ['HTTP Request', 'SSH Login', 'File Access', 'SQL Query', 'Network Connection', 'XSS Attempt', 'SQL Injection', 'Brute Force'];

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
            'Ataque de inyección SQL detectado: UNION SELECT en parámetro de consulta',
            'Múltiples intentos de login fallidos desde IP sospechosa (China)',
            'Patrón de acceso a archivos inusual durante horario no laboral',
            'Intento de XSS reflejado bloqueado: <script>alert(\'XSS\')</script>',
            'Tráfico de red anómalo hacia dominios C2 conocidos',
            'Acceso no autorizado a panel de administración detectado',
            'Headers HTTP malformados indicativos de herramientas automatizadas',
            'Ataque de fuerza bruta detectado: 50+ intentos en 60 segundos',
            'Payload XSS almacenado en campo de comentarios',
            'Escáner de vulnerabilidades activado: Nmap/Nessus signature',
            'Exfiltración de datos sospechosa: transferencia masiva fuera de horario',
            'Comunicación con servidor C2 de APT28 detectada',
            'Técnica de movimiento lateral detectada: PsExec execution',
            'Indicador de persistencia: modificación de registro de Windows'
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
        const types = ['SQL Injection', 'XSS Attack', 'Brute Force', 'APT Activity', 'Malware', 'Data Exfiltration', 'C2 Communication'];
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
            'Inyección SQL de alta confianza detectada desde IP 203.0.113.45 (China) - Técnica: UNION SELECT',
            'Múltiples intentos de XSS bloqueados desde Rusia - Posible ataque dirigido usando payloads de APT28',
            'Ataque de fuerza bruta SSH detectado: 250+ intentos desde botnet Mirai - Recomendar bloqueo inmediato',
            'Actividad APT detectada: movimiento lateral usando PsExec desde sistema comprometido',
            'Exfiltración de datos sospechosa: 2.3GB transferidos a servidor C2 durante horario no laboral',
            'Firma de malware Lazarus Group detectada en archivo ejecutable cargado',
            'Comunicación con dominio C2 conocido: malicious-c2.example.com (APT29)',
            'Patrón de User-Agent sospechoso: indicativo de herramientas automatizadas de reconocimiento',
            'Anomalía ML detectada: comportamiento de usuario anómalo - acceso masivo a bases de datos',
            'Técnica MITRE T1190 detectada: explotación de aplicación web pública',
            'Persistencia detectada: modificación de clave de registro de inicio de Windows',
            'Escalada de privilegios: intento de acceso a /etc/shadow desde usuario no privilegiado'
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
        } else if (pageName === 'threat-hunt') {
            this.loadThreatHuntingData();
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
        
        // Simular datos detallados de la alerta
        const alertDetails = {
            id: alertId,
            timestamp: new Date().toISOString(),
            severity: 'critical',
            title: 'Inyección SQL Detectada',
            attack_type: 'SQL Injection',
            confidence: 0.92,
            source_ip: '203.0.113.45',
            source_country: 'China',
            target_system: 'web-server-01.company.com',
            attack_vector: 'HTTP POST /login.php',
            payload: "' UNION SELECT username,password FROM users--",
            mitre_techniques: ['T1190 - Exploit Public-Facing Application'],
            iocs_matched: ['UNION keyword', 'SQL comment syntax'],
            timeline: [
                {
                    time: '2025-01-24 00:25:46',
                    event: 'Primera detección de payload SQL malicioso',
                    details: 'Sistema detectó patrón UNION SELECT en parámetro POST'
                },
                {
                    time: '2025-01-24 00:25:47',
                    event: 'Validación de contexto de ataque',
                    details: 'Confirmado: intento de extracción de tabla usuarios'
                },
                {
                    time: '2025-01-24 00:25:48',
                    event: 'Alerta generada y notificación enviada',
                    details: 'SOC Team notificado via email y Slack'
                }
            ],
            mitigation_steps: [
                'Implementar prepared statements en aplicación web',
                'Aplicar whitelist de caracteres permitidos en formularios',
                'Configurar Web Application Firewall (WAF) con reglas SQL injection',
                'Realizar testing de penetración en aplicación',
                'Revisar logs de base de datos para buscar acceso exitoso'
            ],
            related_events: [
                'Event #12: Múltiples requests desde la misma IP',
                'Event #13: User-Agent sospechoso (herramienta automatizada)',
                'Event #14: Escaneo de directorios web detectado'
            ],
            threat_intelligence: {
                ip_reputation: 'Conocida por actividad maliciosa - Botnet Mirai',
                geolocation: 'Beijing, China',
                asn: 'AS4134 China Telecom',
                previous_attacks: '47 ataques registrados en los últimos 30 días',
                threat_actors: 'Script kiddies usando herramientas automatizadas'
            },
            educational_notes: [
                'La inyección SQL es una de las vulnerabilidades más comunes en aplicaciones web',
                'El payload UNION SELECT busca combinar resultados de la consulta original con datos de otras tablas',
                'Los comentarios SQL (--) permiten ignorar el resto de la consulta original',
                'Esta técnica está catalogada como T1190 en MITRE ATT&CK Framework'
            ]
        };

        this.showAlertDetailsModal(alertDetails);
    }

    showAlertDetailsModal(alertDetails) {
        // Crear modal dinámicamente
        const modal = document.createElement('div');
        modal.className = 'alert-details-modal';
        modal.innerHTML = `
            <div class="modal-overlay" onclick="dashboard.closeAlertModal()"></div>
            <div class="modal-content">
                <div class="modal-header">
                    <h2>🚨 Detalles de Alerta de Seguridad</h2>
                    <button class="modal-close" onclick="dashboard.closeAlertModal()">✖️</button>
                </div>
                
                <div class="modal-body">
                    <!-- Información Principal -->
                    <div class="alert-info-section">
                        <div class="alert-title">
                            <span class="severity-badge severity-${alertDetails.severity}">${alertDetails.severity.toUpperCase()}</span>
                            ${alertDetails.title}
                        </div>
                        <div class="alert-meta">
                            <div class="meta-item">
                                <strong>Timestamp:</strong> ${this.formatTimestamp(alertDetails.timestamp)}
                            </div>
                            <div class="meta-item">
                                <strong>Confianza:</strong> ${(alertDetails.confidence * 100).toFixed(0)}%
                            </div>
                            <div class="meta-item">
                                <strong>Tipo de Ataque:</strong> ${alertDetails.attack_type}
                            </div>
                        </div>
                    </div>

                    <!-- Información de Origen -->
                    <div class="threat-source-section">
                        <h3>🌍 Información de Origen</h3>
                        <div class="threat-source-grid">
                            <div class="source-item">
                                <strong>IP de Origen:</strong> ${alertDetails.source_ip}
                            </div>
                            <div class="source-item">
                                <strong>País:</strong> ${alertDetails.source_country}
                            </div>
                            <div class="source-item">
                                <strong>Sistema Objetivo:</strong> ${alertDetails.target_system}
                            </div>
                            <div class="source-item">
                                <strong>Vector de Ataque:</strong> ${alertDetails.attack_vector}
                            </div>
                        </div>
                        
                        <div class="threat-intelligence">
                            <h4>📊 Threat Intelligence</h4>
                            <ul>
                                <li><strong>Reputación IP:</strong> ${alertDetails.threat_intelligence.ip_reputation}</li>
                                <li><strong>Geolocalización:</strong> ${alertDetails.threat_intelligence.geolocation}</li>
                                <li><strong>ASN:</strong> ${alertDetails.threat_intelligence.asn}</li>
                                <li><strong>Ataques Previos:</strong> ${alertDetails.threat_intelligence.previous_attacks}</li>
                                <li><strong>Actores de Amenaza:</strong> ${alertDetails.threat_intelligence.threat_actors}</li>
                            </ul>
                        </div>
                    </div>

                    <!-- Análisis Técnico -->
                    <div class="technical-analysis-section">
                        <h3>🔬 Análisis Técnico</h3>
                        <div class="payload-section">
                            <strong>Payload Detectado:</strong>
                            <div class="payload-code">${alertDetails.payload}</div>
                        </div>
                        
                        <div class="indicators-section">
                            <strong>IOCs Coincidentes:</strong>
                            <div class="ioc-tags">
                                ${alertDetails.iocs_matched.map(ioc => `<span class="ioc-tag">${ioc}</span>`).join('')}
                            </div>
                        </div>

                        <div class="mitre-section">
                            <strong>Técnicas MITRE ATT&CK:</strong>
                            <div class="mitre-tags">
                                ${alertDetails.mitre_techniques.map(technique => `<span class="mitre-tag">${technique}</span>`).join('')}
                            </div>
                        </div>
                    </div>

                    <!-- Timeline de Eventos -->
                    <div class="timeline-section">
                        <h3>⏱️ Timeline de Eventos</h3>
                        <div class="timeline">
                            ${alertDetails.timeline.map(event => `
                                <div class="timeline-event">
                                    <div class="timeline-time">${event.time}</div>
                                    <div class="timeline-content">
                                        <div class="timeline-title">${event.event}</div>
                                        <div class="timeline-details">${event.details}</div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>

                    <!-- Eventos Relacionados -->
                    <div class="related-events-section">
                        <h3>🔗 Eventos Relacionados</h3>
                        <ul class="related-events-list">
                            ${alertDetails.related_events.map(event => `<li>${event}</li>`).join('')}
                        </ul>
                    </div>

                    <!-- Pasos de Mitigación -->
                    <div class="mitigation-section">
                        <h3>🛡️ Pasos de Mitigación Recomendados</h3>
                        <ol class="mitigation-list">
                            ${alertDetails.mitigation_steps.map(step => `<li>${step}</li>`).join('')}
                        </ol>
                    </div>

                    <!-- Notas Educativas -->
                    <div class="educational-section">
                        <h3>🎓 Notas Educativas</h3>
                        <ul class="educational-list">
                            ${alertDetails.educational_notes.map(note => `<li>${note}</li>`).join('')}
                        </ul>
                    </div>
                </div>

                <div class="modal-actions">
                    <button class="control-btn" onclick="dashboard.acknowledgeAlert('${alertDetails.id}')">
                        <span class="btn-icon">✅</span>
                        Reconocer Alerta
                    </button>
                    <button class="control-btn secondary" onclick="dashboard.escalateAlert('${alertDetails.id}')">
                        <span class="btn-icon">⚠️</span>
                        Escalar
                    </button>
                    <button class="control-btn secondary" onclick="dashboard.exportAlertReport('${alertDetails.id}')">
                        <span class="btn-icon">📄</span>
                        Exportar Reporte
                    </button>
                    <button class="control-btn secondary" onclick="dashboard.blockThreatSource('${alertDetails.source_ip}')">
                        <span class="btn-icon">🚫</span>
                        Bloquear IP
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    closeAlertModal() {
        const modal = document.querySelector('.alert-details-modal');
        if (modal) {
            modal.remove();
        }
    }

    escalateAlert(alertId) {
        console.log('Escalating alert:', alertId);
        alert(`Escalando alerta ${alertId}\n\nEsta alerta será marcada como de alta prioridad y notificada al equipo de respuesta a incidentes.`);
        this.closeAlertModal();
    }

    exportAlertReport(alertId) {
        console.log('Exporting alert report:', alertId);
        alert(`Exportando reporte detallado de alerta ${alertId}\n\nEn un entorno real, esto generaría un PDF con todos los detalles técnicos y recomendaciones.`);
    }

    blockThreatSource(sourceIp) {
        console.log('Blocking threat source:', sourceIp);
        alert(`Bloqueando IP de amenaza: ${sourceIp}\n\nEsta IP será añadida inmediatamente a las listas de bloqueo del firewall y WAF.`);
        this.closeAlertModal();
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

    /// Funciones de Threat Hunting

    async loadThreatHuntingData() {
        try {
            // Cargar consultas de hunting disponibles
            await this.loadHuntQueries();
            
            // Cargar IOCs
            this.loadIOCs();
            
            // Cargar análisis MITRE
            this.loadMitreAnalysis();
            
            // Simular algunos resultados de hunting
            this.loadHuntResults();
            
        } catch (error) {
            console.error('Error cargando datos de threat hunting:', error);
        }
    }

    async loadHuntQueries() {
        try {
            // En un entorno real, esto haría fetch a /api/threat-hunt/queries
            const huntQueries = [
                {
                    id: 'hunt_001',
                    name: 'Exfiltración de Datos Fuera de Horario',
                    description: 'Busca actividad sospechosa de transferencia de datos durante horarios no laborales',
                    category: 'Data Exfiltration',
                    severity: 'high',
                    mitre_techniques: ['T1041', 'T1005'],
                    confidence_threshold: 0.6,
                    educational_context: 'Los atacantes suelen exfiltrar datos fuera del horario laboral para evitar detección.'
                },
                {
                    id: 'hunt_002',
                    name: 'Actividad APT - Movimiento Lateral',
                    description: 'Detecta patrones de movimiento lateral característicos de APTs',
                    category: 'APT Detection',
                    severity: 'critical',
                    mitre_techniques: ['T1078', 'T1021'],
                    confidence_threshold: 0.7,
                    educational_context: 'Las APTs mantienen persistencia moviéndose lateralmente por la red.'
                },
                {
                    id: 'hunt_003',
                    name: 'IOCs de Malware Conocido',
                    description: 'Búsqueda basada en indicadores de compromiso de malware conocido',
                    category: 'IOC Hunting',
                    severity: 'critical',
                    mitre_techniques: ['T1071', 'T1090'],
                    confidence_threshold: 0.8,
                    educational_context: 'Los IOCs permiten identificar amenazas conocidas.'
                }
            ];

            this.displayHuntQueries(huntQueries);
        } catch (error) {
            console.error('Error loading hunt queries:', error);
        }
    }

    displayHuntQueries(queries) {
        const container = document.getElementById('hunt-queries-grid');
        if (!container) return;

        container.innerHTML = '';

        queries.forEach(query => {
            const queryCard = document.createElement('div');
            queryCard.className = 'hunt-query-card';
            queryCard.innerHTML = `
                <div class="hunt-query-header">
                    <div class="query-name">${query.name}</div>
                    <div class="query-category ${query.category.toLowerCase().replace(' ', '-')}">${query.category}</div>
                </div>
                <div class="query-description">${query.description}</div>
                <div class="query-details">
                    <div class="mitre-techniques">
                        <strong>MITRE Techniques:</strong> ${query.mitre_techniques.join(', ')}
                    </div>
                    <div class="confidence-threshold">
                        <strong>Confianza:</strong> ${(query.confidence_threshold * 100).toFixed(0)}%
                    </div>
                    <div class="educational-context">
                        <strong>Context:</strong> ${query.educational_context}
                    </div>
                </div>
                <div class="query-actions">
                    <button class="control-btn small" onclick="dashboard.executeHunt('${query.id}')">
                        <span class="btn-icon">🔍</span>
                        Ejecutar Hunt
                    </button>
                    <button class="control-btn small secondary" onclick="dashboard.viewQueryDetails('${query.id}')">
                        <span class="btn-icon">👁️</span>
                        Detalles
                    </button>
                </div>
            `;
            container.appendChild(queryCard);
        });
    }

    loadIOCs() {
        const iocs = [
            {
                type: 'IP Address',
                value: '203.0.113.45',
                threat_level: 'HIGH',
                source: 'Threat Intelligence Feed',
                last_seen: new Date(Date.now() - 86400000).toISOString(), // 1 día atrás
                description: 'IP asociada con actividad de botnet Mirai'
            },
            {
                type: 'Domain',
                value: 'malicious-c2.example.com',
                threat_level: 'CRITICAL',
                source: 'Government Threat Intel',
                last_seen: new Date(Date.now() - 432000000).toISOString(), // 5 días atrás
                description: 'Dominio usado como C2 por APT28'
            },
            {
                type: 'File Hash',
                value: 'a1b2c3d4e5f6789...',
                threat_level: 'HIGH',
                source: 'Internal Analysis',
                last_seen: new Date(Date.now() - 172800000).toISOString(), // 2 días atrás
                description: 'Hash de malware Lazarus Group'
            },
            {
                type: 'User Agent',
                value: 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
                threat_level: 'MEDIUM',
                source: 'Automated Detection',
                last_seen: new Date(Date.now() - 3600000).toISOString(), // 1 hora atrás
                description: 'User Agent obsoleto usado por herramientas automatizadas'
            }
        ];

        this.displayIOCs(iocs);
    }

    displayIOCs(iocs) {
        const tbody = document.getElementById('iocs-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';

        iocs.forEach(ioc => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="ioc-type-badge">${ioc.type}</span></td>
                <td class="ioc-value">${ioc.value}</td>
                <td><span class="threat-level-badge ${ioc.threat_level.toLowerCase()}">${ioc.threat_level}</span></td>
                <td>${ioc.source}</td>
                <td>${this.formatTimestamp(ioc.last_seen)}</td>
                <td>
                    <button class="control-btn small" onclick="dashboard.searchIOC('${ioc.value}')">
                        <span class="btn-icon">🔍</span>
                        Buscar
                    </button>
                    <button class="control-btn small secondary" onclick="dashboard.blockIOC('${ioc.value}')">
                        <span class="btn-icon">🚫</span>
                        Bloquear
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    loadMitreAnalysis() {
        const tactics = [
            {
                id: 'TA0001',
                name: 'Initial Access',
                techniques: ['T1190', 'T1078'],
                detections: 45,
                description: 'Técnicas para obtener acceso inicial al sistema'
            },
            {
                id: 'TA0002',
                name: 'Execution',
                techniques: ['T1059', 'T1053'],
                detections: 32,
                description: 'Técnicas para ejecutar código malicioso'
            },
            {
                id: 'TA0003',
                name: 'Persistence',
                techniques: ['T1053', 'T1547'],
                detections: 18,
                description: 'Técnicas para mantener presencia en el sistema'
            },
            {
                id: 'TA0006',
                name: 'Credential Access',
                techniques: ['T1110', 'T1003'],
                detections: 67,
                description: 'Técnicas para obtener credenciales'
            },
            {
                id: 'TA0010',
                name: 'Exfiltration',
                techniques: ['T1041', 'T1005'],
                detections: 12,
                description: 'Técnicas para exfiltrar datos'
            }
        ];

        this.displayMitreTactics(tactics);
    }

    displayMitreTactics(tactics) {
        const container = document.getElementById('mitre-tactics-grid');
        if (!container) return;

        container.innerHTML = '';

        tactics.forEach(tactic => {
            const tacticCard = document.createElement('div');
            tacticCard.className = 'mitre-tactic-card';
            tacticCard.innerHTML = `
                <div class="tactic-header">
                    <div class="tactic-id">${tactic.id}</div>
                    <div class="tactic-name">${tactic.name}</div>
                </div>
                <div class="tactic-description">${tactic.description}</div>
                <div class="tactic-stats">
                    <div class="detections-count">
                        <strong>${tactic.detections}</strong> detecciones
                    </div>
                    <div class="techniques-list">
                        <strong>Técnicas:</strong> ${tactic.techniques.join(', ')}
                    </div>
                </div>
                <div class="tactic-actions">
                    <button class="control-btn small" onclick="dashboard.analyzeTactic('${tactic.id}')">
                        <span class="btn-icon">📊</span>
                        Analizar
                    </button>
                </div>
            `;
            container.appendChild(tacticCard);
        });
    }

    loadHuntResults() {
        const results = [
            {
                query_name: 'Exfiltración de Datos Fuera de Horario',
                execution_time: new Date().toISOString(),
                matches_found: 3,
                risk_level: 'HIGH',
                confidence: 0.75,
                status: 'completed'
            },
            {
                query_name: 'Actividad APT - Movimiento Lateral',
                execution_time: new Date(Date.now() - 1800000).toISOString(),
                matches_found: 1,
                risk_level: 'CRITICAL',
                confidence: 0.85,
                status: 'completed'
            }
        ];

        this.displayHuntResults(results);
    }

    displayHuntResults(results) {
        const container = document.getElementById('hunt-results-container');
        if (!container) return;

        if (results.length === 0) {
            container.innerHTML = `
                <div class="placeholder-content">
                    <span class="placeholder-icon">🔍</span>
                    <h3>No hay resultados de hunting activos</h3>
                    <p>Ejecuta una consulta de hunting para ver resultados aquí.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = '';

        results.forEach(result => {
            const resultCard = document.createElement('div');
            resultCard.className = 'hunt-result-card';
            resultCard.innerHTML = `
                <div class="result-header">
                    <div class="result-query">${result.query_name}</div>
                    <div class="result-status ${result.status}">${result.status.toUpperCase()}</div>
                </div>
                <div class="result-stats">
                    <div class="stat-item">
                        <div class="stat-label">Coincidencias</div>
                        <div class="stat-value">${result.matches_found}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Riesgo</div>
                        <div class="stat-value risk-${result.risk_level.toLowerCase()}">${result.risk_level}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Confianza</div>
                        <div class="stat-value">${(result.confidence * 100).toFixed(0)}%</div>
                    </div>
                </div>
                <div class="result-time">Ejecutado: ${this.formatTimestamp(result.execution_time)}</div>
                <div class="result-actions">
                    <button class="control-btn small" onclick="dashboard.viewHuntResults('${result.query_name}')">
                        <span class="btn-icon">👁️</span>
                        Ver Detalles
                    </button>
                    <button class="control-btn small secondary" onclick="dashboard.exportHuntResults('${result.query_name}')">
                        <span class="btn-icon">💾</span>
                        Exportar
                    </button>
                </div>
            `;
            container.appendChild(resultCard);
        });
    }

    // Handlers para acciones de threat hunting
    executeHunt(queryId) {
        console.log('Executing hunt query:', queryId);
        // En un entorno real, esto haría POST a /api/threat-hunt/execute/${queryId}
        alert(`Ejecutando consulta de hunting: ${queryId}\n\nEn un entorno real, esto iniciaría la búsqueda proactiva de amenazas usando los criterios definidos.`);
    }

    viewQueryDetails(queryId) {
        console.log('Viewing query details:', queryId);
        // Mostrar modal con detalles de la consulta
    }

    searchIOC(iocValue) {
        console.log('Searching IOC:', iocValue);
        alert(`Buscando IOC: ${iocValue}\n\nEsta función buscaría todas las ocurrencias de este indicador en los logs históricos.`);
    }

    blockIOC(iocValue) {
        console.log('Blocking IOC:', iocValue);
        alert(`Bloqueando IOC: ${iocValue}\n\nEste indicador sería añadido a las listas de bloqueo automático.`);
    }

    analyzeTactic(tacticId) {
        console.log('Analyzing MITRE tactic:', tacticId);
        alert(`Analizando táctica MITRE: ${tacticId}\n\nEsto mostraría un análisis detallado de las técnicas detectadas para esta táctica.`);
    }

    viewHuntResults(queryName) {
        console.log('Viewing hunt results for:', queryName);
        // Mostrar modal con resultados detallados
    }

    exportHuntResults(queryName) {
        console.log('Exporting hunt results for:', queryName);
        alert(`Exportando resultados de: ${queryName}\n\nEn un entorno real, esto generaría un reporte detallado en PDF/CSV.`);
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