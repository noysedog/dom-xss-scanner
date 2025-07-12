// ===============================
// CONTENT-SCRIPT.JS
// Coordinatore principale del DOM XSS Scanner
// ===============================

class DOMXSSScanner {
    constructor() {
        this.initialized = false;
        this.devToolsPort = null;
        this.scanData = {
            parameters: new Map(),
            sinks: new Map(),
            connections: new Map(),
            highlights: new Set(),
            breakpoints: new Map()
        };
        this.aggregatedResults = {
            lastUpdate: null,
            totalParameters: 0,
            totalSinks: 0,
            totalConnections: 0,
            riskLevel: 'none'
        };
        this.init();
    }

    init() {
        if (this.initialized) return;
        
        console.log('🔍 DOM XSS Scanner initializing...');
        
        // Aspetta che il DOM sia pronto
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.startScanning());
        } else {
            this.startScanning();
        }
    }

    startScanning() {
        // Inietta script nella pagina per accesso completo al window context
        this.injectPageScript();
        
        // Inizializza listeners per eventi dai core engine
        this.setupEventListeners();
        
        // Inizializza comunicazione con DevTools
        this.setupDevToolsCommunication();
        
        // Avvia scansione iniziale
        this.performInitialScan();
        
        this.initialized = true;
        console.log('✅ DOM XSS Scanner initialized');
    }

    // ===============================
    // INIEZIONE SCRIPT PAGINA
    // ===============================
    injectPageScript() {
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('injected/page-script.js');
        script.onload = function() {
            this.remove();
        };
        (document.head || document.documentElement).appendChild(script);
    }

    // ===============================
    // SETUP EVENT LISTENERS
    // ===============================
    setupEventListeners() {
        // Listener per parametri trovati
        window.addEventListener('domxss-parameters-found', (event) => {
            this.handleParametersFound(event.detail);
        });

        // Listener per sink trovati
        window.addEventListener('domxss-sinks-found', (event) => {
            this.handleSinksFound(event.detail);
        });

        // Listener per connessioni trovate
        window.addEventListener('domxss-connection-found', (event) => {
            this.handleConnectionFound(event.detail);
        });

        // Listener per vulnerabilità rilevate
        window.addEventListener('domxss-vulnerability-found', (event) => {
            this.handleVulnerabilityFound(event.detail);
        });

        // Listener per breakpoint hit
        window.addEventListener('domxss-breakpoint-hit', (event) => {
            this.handleBreakpointHit(event.detail);
        });

        // Listener per storage access
        window.addEventListener('domxss-storage-access', (event) => {
            this.handleStorageAccess(event.detail);
        });

        // Listener per sink usage real-time
        window.addEventListener('domxss-sink-used', (event) => {
            this.handleSinkUsed(event.detail);
        });

        // Listener per parameter access real-time
        window.addEventListener('domxss-parameter-accessed', (event) => {
            this.handleParameterAccessed(event.detail);
        });

        // Listener per comandi da DevTools
        window.addEventListener('domxss-devtools-command', (event) => {
            this.handleDevToolsCommand(event.detail);
        });
    }

    handleVulnerabilityFound(detail) {
        // 🚨 VULNERABILITÀ CRITICA RILEVATA!
        console.error('🚨 CRITICAL: DOM XSS VULNERABILITY CONFIRMED!', {
            '🎯 Sink': detail.type,
            '⚠️ Severity': detail.severity,
            '📍 Parameters': detail.parameters,
            '📱 DOM Element': detail.element,
            '🔍 Value': detail.value
        });

        // Aggiorna contatore vulnerabilità
        this.aggregatedResults.vulnerabilityCount = (this.aggregatedResults.vulnerabilityCount || 0) + 1;
        this.aggregatedResults.hasVulnerabilities = true;
        
        // Forza risk level a match severity
        if (detail.severity === 'CRITICAL') {
            this.aggregatedResults.riskLevel = 'critical';
        } else if (detail.severity === 'HIGH' && this.aggregatedResults.riskLevel !== 'critical') {
            this.aggregatedResults.riskLevel = 'high';
        }

        // Notifica background per badge
        this.notifyBackgroundVulnerability(detail);

        // Invia a DevTools con priorità alta
        this.sendToDevTools('vulnerability-found', {
            vulnerability: detail,
            summary: this.aggregatedResults,
            timestamp: Date.now()
        });

        // Mostra notification se critica
        if (detail.severity === 'CRITICAL') {
            this.showCriticalVulnerabilityAlert(detail);
        }
    }

    notifyBackgroundVulnerability(detail) {
        // Invia messaggio al background script per badge
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                type: 'vulnerability-found',
                data: detail
            });
        }
    }

    showCriticalVulnerabilityAlert(detail) {
        // Crea alert prominente per vulnerabilità critica
        const alertDiv = document.createElement('div');
        alertDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #ff0000;
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            font-family: Arial, sans-serif;
            font-size: 14px;
            font-weight: bold;
            z-index: 9999999;
            box-shadow: 0 4px 20px rgba(255, 0, 0, 0.5);
            animation: domxss-alert-pulse 2s infinite;
            cursor: pointer;
        `;
        
        alertDiv.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 18px;">🚨</span>
                <div>
                    <div>CRITICAL DOM XSS FOUND!</div>
                    <div style="font-size: 12px; font-weight: normal;">
                        Parameter → ${detail.type}
                    </div>
                </div>
            </div>
        `;

        // Aggiungi animation CSS se non esiste
        if (!document.getElementById('domxss-alert-styles')) {
            const style = document.createElement('style');
            style.id = 'domxss-alert-styles';
            style.textContent = `
                @keyframes domxss-alert-pulse {
                    0% { transform: scale(1); opacity: 1; }
                    50% { transform: scale(1.05); opacity: 0.9; }
                    100% { transform: scale(1); opacity: 1; }
                }
            `;
            document.head.appendChild(style);
        }

        // Click per chiudere
        alertDiv.onclick = () => alertDiv.remove();

        document.body.appendChild(alertDiv);

        // Auto-remove dopo 10 secondi
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 10000);
    }

    // ===============================
    // HANDLERS EVENTI
    // ===============================
    handleParametersFound(detail) {
        const parametersId = `params-${detail.timestamp}`;
        
        this.scanData.parameters.set(parametersId, {
            id: parametersId,
            ...detail,
            processed: false
        });

        this.aggregatedResults.totalParameters = this.scanData.parameters.size;
        this.updateRiskLevel();
        this.sendToDevTools('parameters-update', {
            parameters: this.getParametersForUI(),
            summary: this.aggregatedResults
        });

        console.log('📊 Parameters found:', detail);
    }

    handleSinksFound(detail) {
        const sinksId = `sinks-${detail.timestamp}`;
        
        this.scanData.sinks.set(sinksId, {
            id: sinksId,
            ...detail,
            processed: false
        });

        this.aggregatedResults.totalSinks = this.scanData.sinks.size;
        this.updateRiskLevel();
        this.sendToDevTools('sinks-update', {
            sinks: this.getSinksForUI(),
            summary: this.aggregatedResults
        });

        console.log('🎯 Sinks found:', detail);
    }

    handleConnectionFound(detail) {
        const connectionId = detail.id || `conn-${Date.now()}`;
        
        this.scanData.connections.set(connectionId, {
            id: connectionId,
            ...detail,
            verified: this.verifyConnection(detail)
        });

        this.aggregatedResults.totalConnections = this.scanData.connections.size;
        this.updateRiskLevel();
        this.sendToDevTools('connections-update', {
            connections: this.getConnectionsForUI(),
            summary: this.aggregatedResults
        });

        console.log('🔗 Connection found:', detail);
    }

    handleBreakpointHit(detail) {
        this.sendToDevTools('breakpoint-hit', {
            breakpoint: detail,
            timestamp: Date.now()
        });

        console.log('🔴 Breakpoint hit:', detail);
    }

    handleStorageAccess(detail) {
        // Traccia accessi a storage per analisi avanzata
        this.sendToDevTools('storage-access', {
            access: detail,
            timestamp: Date.now()
        });
    }

    handleSinkUsed(detail) {
        // Sink usato in real-time
        this.sendToDevTools('sink-used-realtime', {
            sink: detail,
            timestamp: Date.now()
        });
    }

    handleParameterAccessed(detail) {
        // Parametro acceduto in real-time
        this.sendToDevTools('parameter-accessed-realtime', {
            parameter: detail,
            timestamp: Date.now()
        });
    }

    handleDevToolsCommand(detail) {
        const { command, data } = detail;
        
        switch (command) {
            case 'set-breakpoint':
                this.setBreakpoint(data.parameter);
                break;
            case 'remove-breakpoint':
                this.removeBreakpoint(data.parameter);
                break;
            case 'refresh-scan':
                this.refreshScan();
                break;
            case 'highlight-element':
                this.highlightElement(data.element);
                break;
            case 'export-data':
                this.exportData();
                break;
            case 'clear-highlights':
                this.clearHighlights();
                break;
            default:
                console.warn('Unknown DevTools command:', command);
        }
    }

    // ===============================
    // COMUNICAZIONE DEVTOOLS
    // ===============================
    setupDevToolsCommunication() {
        // Connessione con DevTools
        chrome.runtime.onConnect.addListener((port) => {
            if (port.name === 'dom-xss-scanner') {
                this.devToolsPort = port;
                
                port.onMessage.addListener((message) => {
                    this.handleDevToolsMessage(message);
                });
                
                port.onDisconnect.addListener(() => {
                    this.devToolsPort = null;
                });

                // Invia stato iniziale
                this.sendInitialState();
            }
        });
    }

    sendToDevTools(type, data) {
        if (this.devToolsPort) {
            this.devToolsPort.postMessage({
                type: type,
                data: data,
                timestamp: Date.now()
            });
        }
    }

    handleDevToolsMessage(message) {
        const { type, data } = message;
        
        switch (type) {
            case 'get-current-state':
                this.sendCurrentState();
                break;
            case 'command':
                this.handleDevToolsCommand({ command: data.command, data: data });
                break;
            default:
                console.warn('Unknown DevTools message:', type);
        }
    }

    sendInitialState() {
        this.sendToDevTools('initial-state', {
            parameters: this.getParametersForUI(),
            sinks: this.getSinksForUI(),
            connections: this.getConnectionsForUI(),
            summary: this.aggregatedResults
        });
    }

    sendCurrentState() {
        this.sendToDevTools('current-state', {
            parameters: this.getParametersForUI(),
            sinks: this.getSinksForUI(),
            connections: this.getConnectionsForUI(),
            highlights: Array.from(this.scanData.highlights),
            breakpoints: Array.from(this.scanData.breakpoints.values()),
            summary: this.aggregatedResults
        });
    }

    // ===============================
    // PREPARAZIONE DATI PER UI
    // ===============================
    getParametersForUI() {
        const parameters = [];
        
        this.scanData.parameters.forEach((paramData) => {
            if (paramData.parameters) {
                Object.keys(paramData.parameters).forEach(source => {
                    if (paramData.parameters[source]) {
                        Object.keys(paramData.parameters[source]).forEach(param => {
                            const data = paramData.parameters[source][param];
                            parameters.push({
                                name: param,
                                value: data.value,
                                decoded: data.decoded,
                                source: data.source,
                                raw: data.raw,
                                url: paramData.url,
                                timestamp: paramData.timestamp
                            });
                        });
                    }
                });
            }
        });

        return parameters;
    }

    getSinksForUI() {
        const sinks = [];
        
        this.scanData.sinks.forEach((sinkData) => {
            if (sinkData.sinks) {
                Object.keys(sinkData.sinks).forEach(category => {
                    const categoryData = sinkData.sinks[category];
                    categoryData.matches.forEach(match => {
                        sinks.push({
                            category: category,
                            description: categoryData.description,
                            severity: categoryData.severity,
                            match: match.match,
                            lineNumber: match.lineNumber,
                            context: match.context,
                            scriptId: sinkData.scriptId,
                            timestamp: sinkData.timestamp
                        });
                    });
                });
            }
        });

        // Ordina per severità
        const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3 };
        sinks.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        return sinks;
    }

    getConnectionsForUI() {
        const connections = [];
        
        this.scanData.connections.forEach((connection) => {
            // Arricchisce connessione con dati parametri e sink
            const enrichedConnection = {
                ...connection,
                parameterDetails: this.getParameterDetails(connection.parameterId),
                sinkDetails: this.getSinkDetails(connection.sinkId)
            };
            
            connections.push(enrichedConnection);
        });

        return connections;
    }

    getParameterDetails(parameterId) {
        // Trova dettagli parametro dal suo ID
        for (const [, paramData] of this.scanData.parameters) {
            // Logica per trovare parametro specifico
            // Implementazione semplificata
            if (parameterId.includes('search') || parameterId.includes('hash')) {
                return {
                    source: parameterId.includes('search') ? 'location.search' : 'location.hash',
                    found: true
                };
            }
        }
        return { found: false };
    }

    getSinkDetails(sinkId) {
        // Trova dettagli sink dal suo ID
        for (const [, sinkData] of this.scanData.sinks) {
            if (sinkId.includes('innerHTML')) {
                return {
                    type: 'innerHTML',
                    severity: 'high',
                    found: true
                };
            }
            if (sinkId.includes('eval')) {
                return {
                    type: 'eval',
                    severity: 'critical',
                    found: true
                };
            }
        }
        return { found: false };
    }

    // ===============================
    // UTILITY E CONTROLLI
    // ===============================
    verifyConnection(connection) {
        // Verifica se la connessione è plausibile
        const paramDetails = this.getParameterDetails(connection.parameterId);
        const sinkDetails = this.getSinkDetails(connection.sinkId);
        
        return paramDetails.found && sinkDetails.found;
    }

    updateRiskLevel() {
        const { totalParameters, totalSinks, totalConnections } = this.aggregatedResults;
        
        if (totalConnections > 0) {
            // Controlla severità sink collegati
            const criticalSinks = this.countSinksBySeverity('critical');
            const highSinks = this.countSinksBySeverity('high');
            
            if (criticalSinks > 0) {
                this.aggregatedResults.riskLevel = 'critical';
            } else if (highSinks > 0) {
                this.aggregatedResults.riskLevel = 'high';
            } else {
                this.aggregatedResults.riskLevel = 'medium';
            }
        } else if (totalSinks > 0 && totalParameters > 0) {
            this.aggregatedResults.riskLevel = 'low';
        } else {
            this.aggregatedResults.riskLevel = 'none';
        }
        
        this.aggregatedResults.lastUpdate = Date.now();
    }

    countSinksBySeverity(severity) {
        let count = 0;
        this.scanData.sinks.forEach((sinkData) => {
            if (sinkData.sinks) {
                Object.values(sinkData.sinks).forEach(categoryData => {
                    if (categoryData.severity === severity) {
                        count += categoryData.matches.length;
                    }
                });
            }
        });
        return count;
    }

    // ===============================
    // COMANDI UTENTE
    // ===============================
    setBreakpoint(parameter) {
        this.scanData.breakpoints.set(parameter, {
            parameter: parameter,
            active: true,
            timestamp: Date.now()
        });
        
        // Invia comando al page context
        window.dispatchEvent(new CustomEvent('domxss-set-breakpoint', {
            detail: { parameter: parameter }
        }));
    }

    removeBreakpoint(parameter) {
        this.scanData.breakpoints.delete(parameter);
        
        window.dispatchEvent(new CustomEvent('domxss-remove-breakpoint', {
            detail: { parameter: parameter }
        }));
    }

    refreshScan() {
        // Reset dati
        this.scanData.parameters.clear();
        this.scanData.sinks.clear();
        this.scanData.connections.clear();
        
        // Riavvia scansione
        this.performInitialScan();
    }

    highlightElement(elementSelector) {
        try {
            const element = document.querySelector(elementSelector);
            if (element) {
                window.dispatchEvent(new CustomEvent('domxss-highlight-element', {
                    detail: { element: element }
                }));
            }
        } catch (e) {
            console.error('Error highlighting element:', e);
        }
    }

    clearHighlights() {
        window.dispatchEvent(new CustomEvent('domxss-clear-highlights'));
    }

    exportData() {
        const exportData = {
            url: location.href,
            timestamp: Date.now(),
            summary: this.aggregatedResults,
            parameters: this.getParametersForUI(),
            sinks: this.getSinksForUI(),
            connections: this.getConnectionsForUI()
        };
        
        this.sendToDevTools('export-data', exportData);
    }

    performInitialScan() {
        // Trigger scansione iniziale se i core engine sono disponibili
        if (window.domXSSAnalyzer) {
            if (window.domXSSAnalyzer.urlAnalyzer) {
                window.domXSSAnalyzer.urlAnalyzer.refreshAnalysis();
            }
            if (window.domXSSAnalyzer.sinkDetector) {
                window.domXSSAnalyzer.sinkDetector.refreshScan();
            }
        }
    }
}

// ===============================
// INIZIALIZZAZIONE
// ===============================
const domXSSScanner = new DOMXSSScanner();

// Esporta per debugging
window.domXSSScanner = domXSSScanner;