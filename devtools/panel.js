// ===============================
// PANEL.JS
// UI DevTools per DOM XSS Scanner
// ===============================

class DOMXSSPanel {
    constructor() {
        this.port = null;
        this.currentData = {
            parameters: [],
            sinks: [],
            connections: [],
            highlights: [],
            breakpoints: [],
            summary: {
                totalParameters: 0,
                totalSinks: 0,
                totalConnections: 0,
                riskLevel: 'none',
                lastUpdate: null
            }
        };
        this.init();
    }

    init() {
        this.setupCommunication();
        this.setupEventListeners();
        this.initializeUI();
    }

    // ===============================
    // COMUNICAZIONE CON CONTENT SCRIPT
    // ===============================
    setupCommunication() {
        // Connessione con content script
        this.port = chrome.tabs.connect(chrome.devtools.inspectedWindow.tabId, {
            name: 'dom-xss-scanner'
        });

        this.port.onMessage.addListener((message) => {
            this.handleMessage(message);
        });

        this.port.onDisconnect.addListener(() => {
            this.handleDisconnect();
        });

        // Richiedi stato iniziale
        this.sendMessage('get-current-state');
    }

    sendMessage(type, data = {}) {
        if (this.port) {
            this.port.postMessage({
                type: type,
                data: data,
                timestamp: Date.now()
            });
        }
    }

    handleMessage(message) {
        const { type, data } = message;
        
        switch (type) {
            case 'initial-state':
            case 'current-state':
                this.updateAllData(data);
                break;
            case 'parameters-update':
                this.updateParameters(data.parameters);
                this.updateSummary(data.summary);
                break;
            case 'sinks-update':
                this.updateSinks(data.sinks);
                this.updateSummary(data.summary);
                break;
            case 'connections-update':
                this.updateConnections(data.connections);
                this.updateSummary(data.summary);
                break;
            case 'breakpoint-hit':
                this.showBreakpointHit(data.breakpoint);
                break;
            case 'sink-used-realtime':
                this.showRealtimeActivity('sink', data.sink);
                break;
            case 'parameter-accessed-realtime':
                this.showRealtimeActivity('parameter', data.parameter);
                break;
            case 'export-data':
                this.handleExportData(data);
                break;
            default:
                console.warn('Unknown message type:', type);
        }
    }

    handleDisconnect() {
        this.showDisconnectedState();
    }

    // ===============================
    // SETUP UI E EVENT LISTENERS
    // ===============================
    setupEventListeners() {
        // Refresh button
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.refreshScan();
        });

        // Export button
        document.getElementById('export-btn').addEventListener('click', () => {
            this.exportData();
        });

        // Clear highlights button
        document.getElementById('clear-highlights-btn').addEventListener('click', () => {
            this.clearHighlights();
        });

        // Risk level indicator click
        document.getElementById('risk-indicator').addEventListener('click', () => {
            this.showRiskDetails();
        });

        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });
    }

    initializeUI() {
        this.updateLastUpdateTime();
        this.showLoadingState();
        
        // Auto-refresh ogni 30 secondi
        setInterval(() => {
            this.updateLastUpdateTime();
        }, 30000);
    }

    // ===============================
    // AGGIORNAMENTO DATI
    // ===============================
    updateAllData(data) {
        this.currentData = { ...this.currentData, ...data };
        
        this.updateParameters(data.parameters);
        this.updateSinks(data.sinks);
        this.updateConnections(data.connections);
        this.updateSummary(data.summary);
        
        // Renderizza la nuova Flow View
        this.renderFlowView();
        
        this.hideLoadingState();
    }

    updateParameters(parameters) {
        this.currentData.parameters = parameters || [];
    }

    updateSinks(sinks) {
        this.currentData.sinks = sinks || [];
    }

    updateConnections(connections) {
        this.currentData.connections = connections || [];
    }

    updateSummary(summary) {
        this.currentData.summary = { ...this.currentData.summary, ...summary };
        this.renderSummary();
    }

    renderSummary() {
        const { totalParameters, totalSinks, totalConnections, riskLevel } = this.currentData.summary;
        
        // Aggiorna risk indicator
        const riskIndicator = document.getElementById('risk-indicator');
        riskIndicator.className = `risk-indicator risk-${riskLevel}`;
        riskIndicator.textContent = riskLevel.toUpperCase();
        
        // Aggiorna last update
        this.updateLastUpdateTime();
    }

    // ===============================
    // RENDERING FLOW VIEW
    // ===============================
    renderFlowView() {
        const container = document.getElementById('vulnerabilities-container');
        const noVulnDiv = document.getElementById('no-vulnerabilities');
        
        // Analizza connessioni per creare vulnerabilità
        const vulnerabilities = this.analyzeVulnerabilities();
        
        // Aggiorna contatori
        document.getElementById('vuln-count').textContent = vulnerabilities.length;
        document.getElementById('param-count').textContent = this.currentData.parameters.length;
        document.getElementById('sink-count').textContent = this.currentData.sinks.length;
        
        if (vulnerabilities.length === 0) {
            noVulnDiv.style.display = 'block';
            return;
        }
        
        noVulnDiv.style.display = 'none';
        
        // Rimuovi vulnerabilità esistenti
        const existingCards = container.querySelectorAll('.vulnerability-card');
        existingCards.forEach(card => card.remove());
        
        // Renderizza ogni vulnerabilità
        vulnerabilities.forEach(vuln => {
            const card = this.createVulnerabilityCard(vuln);
            container.appendChild(card);
        });
    }

    analyzeVulnerabilities() {
        const vulnerabilities = [];
        
        // Analizza ogni connessione per creare vulnerabilità
        this.currentData.connections.forEach(connection => {
            const param = this.findParameterById(connection.parameterId);
            const sink = this.findSinkById(connection.sinkId);
            
            if (param && sink) {
                vulnerabilities.push({
                    id: connection.id,
                    parameter: param,
                    sink: sink,
                    connection: connection,
                    severity: this.calculateSeverity(sink.severity),
                    riskDescription: this.getRiskDescription(sink.type),
                    testPayload: this.generateTestPayload(param.name, sink.type)
                });
            }
        });
        
        // Ordina per severità
        const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3 };
        vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
        
        return vulnerabilities;
    }

    createVulnerabilityCard(vuln) {
        const card = document.createElement('div');
        card.className = `vulnerability-card ${vuln.severity}`;
        card.innerHTML = `
            <div class="vulnerability-header">
                <div class="vulnerability-title">
                    Parameter "${vuln.parameter.name}" flows to ${vuln.sink.type}
                </div>
                <div class="severity-badge severity-${vuln.severity}">${vuln.severity}</div>
            </div>
            
            <div class="flow-container">
                <div class="flow-item flow-source">
                    <div class="flow-label">📍 Source</div>
                    <div class="flow-content">${vuln.parameter.source}</div>
                    <div class="flow-content">
                        ?${vuln.parameter.name}=${this.truncateValue(vuln.parameter.value)}
                    </div>
                </div>
                
                <div class="flow-arrow">→</div>
                
                <div class="flow-item flow-sink">
                    <div class="flow-label">🎯 Sink</div>
                    <div class="flow-content">${vuln.sink.type}</div>
                    <div class="flow-content">Line ${vuln.sink.lineNumber || 'unknown'}</div>
                </div>
                
                <div class="flow-arrow">→</div>
                
                <div class="flow-item flow-dom">
                    <div class="flow-label">📱 DOM</div>
                    <div class="flow-content">${vuln.connection.domPath || 'unknown'}</div>
                </div>
            </div>
            
            <div class="vulnerability-details">
                <div class="vulnerability-risk">
                    ⚠️ Risk: ${vuln.riskDescription}
                </div>
                <div class="vulnerability-test">
                    🧪 Test: ${vuln.testPayload}
                </div>
                
                <div class="action-buttons">
                    <button class="action-btn highlight" onclick="window.domXSSPanel.highlightVulnerability('${vuln.id}')">
                        📍 Highlight DOM
                    </button>
                    <button class="action-btn" onclick="window.domXSSPanel.showSinkCode('${vuln.sink.scriptId}', ${vuln.sink.lineNumber})">
                        🔍 Show Code
                    </button>
                    <button class="action-btn" onclick="window.domXSSPanel.copyTestPayload('${vuln.testPayload}')">
                        📋 Copy Test
                    </button>
                </div>
            </div>
        `;
        
        return card;
    }

    calculateSeverity(sinkSeverity) {
        // Usa la severità del sink
        return sinkSeverity || 'medium';
    }

    getRiskDescription(sinkType) {
        const descriptions = {
            'innerHTML': 'User input directly inserted in DOM without sanitization',
            'outerHTML': 'User input replaces DOM element content without sanitization',
            'eval': 'User input executed as JavaScript code',
            'setTimeout': 'User input executed as delayed JavaScript code',
            'document.write': 'User input written directly to document',
            'insertAdjacentHTML': 'User input inserted adjacent to DOM element',
            'location.href': 'User input used for navigation/redirect',
            'addEventListener': 'User input used as event handler'
        };
        
        return descriptions[sinkType] || 'User input flows to potentially dangerous sink';
    }

    generateTestPayload(paramName, sinkType) {
        const payloads = {
            'innerHTML': `Try: ?${paramName}=<script>alert('XSS')</script>`,
            'outerHTML': `Try: ?${paramName}=<img src=x onerror=alert('XSS')>`,
            'eval': `Try: ?${paramName}=alert('XSS')`,
            'setTimeout': `Try: ?${paramName}=alert('XSS')`,
            'document.write': `Try: ?${paramName}=<script>alert('XSS')</script>`,
            'insertAdjacentHTML': `Try: ?${paramName}=<img src=x onerror=alert('XSS')>`,
            'location.href': `Try: ?${paramName}=javascript:alert('XSS')`,
            'addEventListener': `Try: ?${paramName}=alert('XSS')`
        };
        
        return payloads[sinkType] || `Try: ?${paramName}=<script>alert('XSS')</script>`;
    }

    findParameterById(parameterId) {
        return this.currentData.parameters.find(param => 
            param.name === this.extractParameterName(parameterId)
        );
    }

    findSinkById(sinkId) {
        return this.currentData.sinks.find(sink => 
            sink.match && sink.match.includes(this.extractSinkType(sinkId))
        );
    }

    extractParameterName(parameterId) {
        // Estrai nome parametro dall'ID (es: "param-name" -> "name")
        return parameterId.split('-').pop();
    }

    extractSinkType(sinkId) {
        // Estrai tipo sink dall'ID (es: "sink-innerHTML" -> "innerHTML")
        return sinkId.split('-')[1] || sinkId;
    }

    truncateValue(value, maxLength = 50) {
        if (typeof value !== 'string') return value;
        if (value.length <= maxLength) return value;
        return value.substring(0, maxLength) + '...';
    }

    // ===============================
    // AZIONI VULNERABILITÀ
    // ===============================
    highlightVulnerability(vulnerabilityId) {
        this.sendMessage('command', {
            command: 'highlight-vulnerability',
            vulnerabilityId: vulnerabilityId
        });
    }

    showSinkCode(scriptId, lineNumber) {
        // Mostra codice sink in modal o console
        console.log(`Show code for script ${scriptId} at line ${lineNumber}`);
    }

    copyTestPayload(payload) {
        navigator.clipboard.writeText(payload).then(() => {
            // Mostra feedback
            this.showNotification('Test payload copied to clipboard!');
        });
    }

    showNotification(message) {
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            z-index: 1000;
        `;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    renderParameters() {
        const container = document.getElementById('url-parameters');
        container.innerHTML = '';
        
        if (this.currentData.parameters.length === 0) {
            container.innerHTML = '<div class="no-data">No parameters found</div>';
            return;
        }

        this.currentData.parameters.forEach((param, index) => {
            const paramDiv = document.createElement('div');
            paramDiv.className = 'parameter';
            paramDiv.innerHTML = `
                <div class="parameter-header">
                    <span class="parameter-name">${this.escapeHTML(param.name)}</span>
                    <span class="parameter-source">${param.source}</span>
                    <button class="breakpoint-btn" data-parameter="${param.name}">
                        ${this.hasBreakpoint(param.name) ? '🔴' : '⚪'}
                    </button>
                </div>
                <div class="parameter-details">
                    <div class="parameter-value">
                        <strong>Value:</strong> ${this.escapeHTML(param.value)}
                    </div>
                    ${param.decoded !== param.value ? `
                        <div class="parameter-decoded">
                            <strong>Decoded:</strong> ${this.escapeHTML(param.decoded)}
                        </div>
                    ` : ''}
                    <div class="parameter-raw">
                        <strong>Raw:</strong> <code>${this.escapeHTML(param.raw)}</code>
                    </div>
                </div>
            `;
            
            // Event listener per breakpoint
            const breakpointBtn = paramDiv.querySelector('.breakpoint-btn');
            breakpointBtn.addEventListener('click', () => {
                this.toggleBreakpoint(param.name);
            });
            
            container.appendChild(paramDiv);
        });
    }

    renderSinks() {
        const container = document.getElementById('sources-sinks');
        container.innerHTML = '';
        
        if (this.currentData.sinks.length === 0) {
            container.innerHTML = '<div class="no-data">No sinks found</div>';
            return;
        }

        // Raggruppa sink per severità
        const sinksBySeverity = this.groupSinksBySeverity();
        
        ['critical', 'high', 'medium', 'low'].forEach(severity => {
            if (sinksBySeverity[severity] && sinksBySeverity[severity].length > 0) {
                const severityDiv = document.createElement('div');
                severityDiv.className = `sink-group severity-${severity}`;
                severityDiv.innerHTML = `
                    <div class="sink-group-header">
                        <span class="severity-label">${severity.toUpperCase()}</span>
                        <span class="sink-count">${sinksBySeverity[severity].length}</span>
                    </div>
                `;
                
                const sinkList = document.createElement('div');
                sinkList.className = 'sink-list';
                
                sinksBySeverity[severity].forEach(sink => {
                    const sinkDiv = document.createElement('div');
                    sinkDiv.className = 'sink';
                    sinkDiv.innerHTML = `
                        <div class="sink-header">
                            <span class="sink-type">${sink.category}</span>
                            <span class="sink-line">Line ${sink.lineNumber}</span>
                        </div>
                        <div class="sink-match">
                            <code>${this.escapeHTML(sink.match)}</code>
                        </div>
                        <div class="sink-context">
                            <strong>Context:</strong>
                            <code>${this.escapeHTML(sink.context)}</code>
                        </div>
                        <div class="sink-description">
                            ${sink.description}
                        </div>
                    `;
                    
                    sinkList.appendChild(sinkDiv);
                });
                
                severityDiv.appendChild(sinkList);
                container.appendChild(severityDiv);
            }
        });
    }

    renderConnections() {
        const container = document.getElementById('connections');
        container.innerHTML = '';
        
        if (this.currentData.connections.length === 0) {
            container.innerHTML = '<div class="no-data">No connections found</div>';
            return;
        }

        this.currentData.connections.forEach(connection => {
            const connectionDiv = document.createElement('div');
            connectionDiv.className = `connection ${connection.verified ? 'verified' : 'unverified'}`;
            connectionDiv.innerHTML = `
                <div class="connection-header">
                    <span class="connection-status">
                        ${connection.verified ? '✅' : '❓'}
                    </span>
                    <span class="connection-id">${connection.id}</span>
                </div>
                <div class="connection-flow">
                    <div class="connection-param">
                        <strong>Parameter:</strong> ${this.getParameterName(connection.parameterId)}
                    </div>
                    <div class="connection-arrow">→</div>
                    <div class="connection-sink">
                        <strong>Sink:</strong> ${this.getSinkName(connection.sinkId)}
                    </div>
                </div>
                <div class="connection-details">
                    ${connection.parameterDetails && connection.parameterDetails.found ? `
                        <div class="param-details">
                            <strong>Source:</strong> ${connection.parameterDetails.source}
                        </div>
                    ` : ''}
                    ${connection.sinkDetails && connection.sinkDetails.found ? `
                        <div class="sink-details">
                            <strong>Type:</strong> ${connection.sinkDetails.type}
                            <strong>Severity:</strong> <span class="severity-${connection.sinkDetails.severity}">${connection.sinkDetails.severity}</span>
                        </div>
                    ` : ''}
                </div>
            `;
            
            container.appendChild(connectionDiv);
        });
    }

    renderDOMElements() {
        const container = document.getElementById('dom-elements');
        container.innerHTML = '';
        
        if (this.currentData.highlights.length === 0) {
            container.innerHTML = '<div class="no-data">No DOM elements highlighted</div>';
            return;
        }

        this.currentData.highlights.forEach(highlight => {
            const highlightDiv = document.createElement('div');
            highlightDiv.className = 'dom-element';
            highlightDiv.innerHTML = `
                <div class="element-path">
                    <code>${this.escapeHTML(highlight.path || 'Unknown path')}</code>
                </div>
                <div class="element-details">
                    <strong>Type:</strong> ${highlight.type}
                    <strong>Parameters:</strong> ${highlight.parameterCount || 0}
                </div>
            `;
            
            container.appendChild(highlightDiv);
        });
    }

    // ===============================
    // UTILITY FUNCTIONS
    // ===============================
    groupSinksBySeverity() {
        const grouped = {
            critical: [],
            high: [],
            medium: [],
            low: []
        };
        
        this.currentData.sinks.forEach(sink => {
            if (grouped[sink.severity]) {
                grouped[sink.severity].push(sink);
            }
        });
        
        return grouped;
    }

    hasBreakpoint(parameter) {
        return this.currentData.breakpoints.some(bp => bp.parameter === parameter);
    }

    getParameterName(parameterId) {
        // Estrai nome parametro dall'ID
        const matches = parameterId.match(/param-(.+)/);
        return matches ? matches[1] : parameterId;
    }

    getSinkName(sinkId) {
        // Estrai nome sink dall'ID
        const matches = sinkId.match(/sink-(.+)/);
        return matches ? matches[1] : sinkId;
    }

    getRiskDescription(riskLevel) {
        const descriptions = {
            'none': 'No vulnerabilities detected',
            'low': 'Parameters and sinks found, but no connections detected',
            'medium': 'Connections found with medium-risk sinks',
            'high': 'Connections found with high-risk sinks',
            'critical': 'Connections found with critical sinks - immediate attention required'
        };
        
        return descriptions[riskLevel] || 'Unknown risk level';
    }

    escapeHTML(text) {
        if (typeof text !== 'string') return text;
        
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    updateLastUpdateTime() {
        const now = new Date();
        document.getElementById('last-update').textContent = 
            `Last update: ${now.toLocaleTimeString()}`;
    }

    // ===============================
    // AZIONI UTENTE
    // ===============================
    toggleBreakpoint(parameter) {
        const hasBreakpoint = this.hasBreakpoint(parameter);
        
        if (hasBreakpoint) {
            this.sendMessage('command', {
                command: 'remove-breakpoint',
                parameter: parameter
            });
        } else {
            this.sendMessage('command', {
                command: 'set-breakpoint',
                parameter: parameter
            });
        }
        
        // Aggiorna UI immediatamente
        setTimeout(() => {
            this.renderParameters();
        }, 100);
    }

    refreshScan() {
        this.showLoadingState();
        this.sendMessage('command', {
            command: 'refresh-scan'
        });
    }

    exportData() {
        this.sendMessage('command', {
            command: 'export-data'
        });
    }

    clearHighlights() {
        this.sendMessage('command', {
            command: 'clear-highlights'
        });
    }

    switchTab(tabName) {
        // Aggiorna tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        // Aggiorna sezioni
        document.querySelectorAll('.section').forEach(section => {
            section.style.display = 'none';
        });
        document.getElementById(tabName).style.display = 'block';
    }

    showRiskDetails() {
        const { riskLevel } = this.currentData.summary;
        const description = this.getRiskDescription(riskLevel);
        
        alert(`Risk Level: ${riskLevel.toUpperCase()}\n\n${description}`);
    }

    // ===============================
    // REAL-TIME ACTIVITY
    // ===============================
    showRealtimeActivity(type, data) {
        const activityDiv = document.getElementById('realtime-activity');
        
        const activityItem = document.createElement('div');
        activityItem.className = `activity-item activity-${type}`;
        activityItem.innerHTML = `
            <span class="activity-time">${new Date().toLocaleTimeString()}</span>
            <span class="activity-type">${type.toUpperCase()}</span>
            <span class="activity-details">${this.escapeHTML(data.type || data.source)}</span>
        `;
        
        activityDiv.insertBefore(activityItem, activityDiv.firstChild);
        
        // Mantieni solo ultimi 10 items
        while (activityDiv.children.length > 10) {
            activityDiv.removeChild(activityDiv.lastChild);
        }
        
        // Auto-remove dopo 5 secondi
        setTimeout(() => {
            if (activityItem.parentNode) {
                activityItem.parentNode.removeChild(activityItem);
            }
        }, 5000);
    }

    showBreakpointHit(breakpoint) {
        const notification = document.createElement('div');
        notification.className = 'breakpoint-notification';
        notification.innerHTML = `
            <div class="notification-header">🔴 Breakpoint Hit!</div>
            <div class="notification-content">
                <strong>Parameter:</strong> ${breakpoint.parameter}<br>
                <strong>Value:</strong> ${this.escapeHTML(breakpoint.value)}<br>
                <strong>Source:</strong> ${breakpoint.source}
            </div>
            <button class="close-notification">×</button>
        `;
        
        document.body.appendChild(notification);
        
        // Close button
        notification.querySelector('.close-notification').addEventListener('click', () => {
            notification.remove();
        });
        
        // Auto-remove dopo 10 secondi
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 10000);
    }

    // ===============================
    // STATE MANAGEMENT
    // ===============================
    showLoadingState() {
        document.getElementById('loading-indicator').style.display = 'block';
    }

    hideLoadingState() {
        document.getElementById('loading-indicator').style.display = 'none';
    }

    showDisconnectedState() {
        document.getElementById('disconnected-warning').style.display = 'block';
    }

    handleExportData(data) {
        // Crea e scarica file JSON
        const blob = new Blob([JSON.stringify(data, null, 2)], {
            type: 'application/json'
        });
        
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dom-xss-scan-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        
        URL.revokeObjectURL(url);
    }
}

// ===============================
// INIZIALIZZAZIONE
// ===============================
document.addEventListener('DOMContentLoaded', () => {
    const panel = new DOMXSSPanel();
    
    // Esporta per debugging
    window.domXSSPanel = panel;
});