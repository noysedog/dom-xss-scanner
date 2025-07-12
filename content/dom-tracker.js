// ===============================
// DOM-TRACKER.JS - FINAL VERSION
// Traccia collegamenti parametri → sink → modifiche DOM
// ===============================

class DOMTracker {

    constructor() {
        this.connections = new Map();
        this.domObserver = null;
        this.highlightedElements = new Set();
        this.parameterUsageMap = new Map();
        this.sinkDOMMap = new Map();
        this.breakpoints = new Map();
        
        // 🎯 CONSOLE THROTTLING ONLY
        this.lastLogTime = 0;
        this.logThrottle = 200; // 200ms tra log
        this.vulnerabilityLogCount = 0;
        this.maxVulnerabilityLogs = 3; // Max 3 vulnerability log per sessione
        
        this.init();
    }

    init() {
        this.setupDOMObserver();
        this.setupEventListeners();
        this.setupParameterTracking();
        this.setupBreakpointSystem();
    }

    // ===============================
    // SISTEMA DI TRACKING PRINCIPALE
    // ===============================
    setupParameterTracking() {
        // Intercetta accessi ai parametri per tracciare il flusso
        this.interceptParameterAccess();
        
        // Monitora quando i parametri vengono usati
        window.addEventListener('domxss-parameter-accessed', (event) => {
            this.handleParameterAccess(event.detail);
        });

        // Monitora quando i sink vengono usati
        window.addEventListener('domxss-sink-used', (event) => {
            this.handleSinkUsage(event.detail);
        });
    }

    interceptParameterAccess() {
        // Intercetta location.search
        const originalSearch = Object.getOwnPropertyDescriptor(Location.prototype, 'search');
        Object.defineProperty(location, 'search', {
            get: function() {
                const value = originalSearch.get.call(this);
                window.dispatchEvent(new CustomEvent('domxss-parameter-accessed', {
                    detail: {
                        source: 'location.search',
                        value: value,
                        stackTrace: new Error().stack,
                        timestamp: Date.now()
                    }
                }));
                return value;
            }
        });

        // Intercetta location.hash
        const originalHash = Object.getOwnPropertyDescriptor(Location.prototype, 'hash');
        Object.defineProperty(location, 'hash', {
            get: function() {
                const value = originalHash.get.call(this);
                window.dispatchEvent(new CustomEvent('domxss-parameter-accessed', {
                    detail: {
                        source: 'location.hash',
                        value: value,
                        stackTrace: new Error().stack,
                        timestamp: Date.now()
                    }
                }));
                return value;
            }
        });

        // Intercetta URLSearchParams
        const originalURLSearchParams = window.URLSearchParams;
        window.URLSearchParams = function(init) {
            const params = new originalURLSearchParams(init);
            
            // Intercetta get method
            const originalGet = params.get;
            params.get = function(name) {
                const value = originalGet.call(this, name);
                if (value !== null) {
                    window.dispatchEvent(new CustomEvent('domxss-parameter-accessed', {
                        detail: {
                            source: 'URLSearchParams.get',
                            parameter: name,
                            value: value,
                            stackTrace: new Error().stack,
                            timestamp: Date.now()
                        }
                    }));
                }
                return value;
            };
            
            return params;
        };

        // Intercetta localStorage.getItem
        const originalGetItem = Storage.prototype.getItem;
        Storage.prototype.getItem = function(key) {
            const value = originalGetItem.call(this, key);
            if (value && this === localStorage) {
                window.dispatchEvent(new CustomEvent('domxss-parameter-accessed', {
                    detail: {
                        source: 'localStorage.getItem',
                        parameter: key,
                        value: value,
                        stackTrace: new Error().stack,
                        timestamp: Date.now()
                    }
                }));
            }
            return value;
        };
    }

// ===============================
// 🎯 MODIFICA handleParameterAccess() - Solo i console.log
// ===============================

    handleParameterAccess(detail) {
        const accessId = 'access-' + Date.now() + '-' + Math.random();
        
        this.parameterUsageMap.set(accessId, {
            ...detail,
            id: accessId,
            connectedSinks: []
        });

        // Imposta breakpoint automatico se richiesto - LOGICA INVARIATA
        if (this.breakpoints.has(detail.parameter)) {
            this.triggerBreakpoint(detail);
        }

        // LOG THROTTLED
        if (this.shouldLog('normal')) {
            console.log('Parameter accessed:', detail);
        }
    }

    handleSinkUsage(detail) {
        const sinkId = 'sink-' + Date.now() + '-' + Math.random();
        
        // Cerca collegamenti con parametri recenti - LOGICA INVARIATA
        const recentParameters = this.findRecentParameterAccess(detail.stackTrace, detail.value);
        
        const sinkData = {
            ...detail,
            id: sinkId,
            connectedParameters: recentParameters,
            domElement: detail.element,
            domPath: this.getDOMPath(detail.element)
        };

        this.sinkDOMMap.set(sinkId, sinkData);

        // Crea collegamenti parametri ← → sink - LOGICA INVARIATA
        recentParameters.forEach(paramId => {
            this.createConnection(paramId, sinkId);
        });

        // EVIDENZIAZIONE VULNERABILITÀ - LOGICA INVARIATA
        if (recentParameters.length > 0) {
            // 🚨 VULNERABILITÀ RILEVATA! - THROTTLED LOG
            if (this.shouldLog('vulnerability')) {
                console.warn('🚨 DOM XSS VULNERABILITY DETECTED!', {
                    'Sink Type': detail.type,
                    'Connected Parameters': recentParameters,
                    'DOM Element': this.getDOMPath(detail.element),
                    'Severity': this.getSeverityBySinkType(detail.type),
                    'Value': detail.value,
                    'Correlation Method': 'Enhanced (Stack + Regex)'
                });
            }
            
            // Evidenzia elemento DOM coinvolto - LOGICA INVARIATA
            this.highlightVulnerableElement(detail.element, sinkData);
            
            // Notifica background script per badge - LOGICA INVARIATA
            this.notifyVulnerabilityFound(sinkData);
            
        } else {
            // ✅ Sink sicuro - THROTTLED LOG
            if (this.shouldLog('normal')) {
                console.log('✅ Safe sink usage:', {
                    type: detail.type,
                    element: this.getDOMPath(detail.element),
                    value: detail.value.substring(0, 50) + '...'
                });
            }
        }

        // Evidenzia elemento DOM coinvolto comunque - LOGICA INVARIATA
        if (detail.element && detail.element.nodeType === 1) {
            this.highlightDOMElement(detail.element, sinkData);
        }

        // LOG THROTTLED invece di sempre
        if (this.shouldLog('normal')) {
            console.log('Sink used with connections:', sinkData);
        }
    }

    // CORRELAZIONE MIGLIORATA: Stack Trace + Regex
    findRecentParameterAccess(sinkStackTrace, sinkValue) {
        const recentParams = [];
        const timeWindow = 5000; // 5 secondi
        const currentTime = Date.now();

        this.parameterUsageMap.forEach((paramData, paramId) => {
            // Controlla se il parametro è stato acceduto recentemente
            if (currentTime - paramData.timestamp < timeWindow) {
                // 1. Prova correlazione stack trace (metodo esistente)
                if (this.stackTracesRelated(paramData.stackTrace, sinkStackTrace)) {
                    recentParams.push(paramId);
                    return;
                }
            }
        });

        // 2. Se non trova nulla con stack trace, prova regex correlation
        if (recentParams.length === 0 && sinkValue) {
            const regexParams = this.findParameterInSinkValue(sinkValue);
            recentParams.push(...regexParams);
        }

        return recentParams;
    }

    // CERCA PARAMETRI NELL'HTML DELLA PAGINA
    findParameterInSinkValue(sinkValue) {
        const foundParams = [];
        const timeWindow = 5000; // 5 secondi
        const currentTime = Date.now();

        // Ottieni HTML completo della pagina
        const pageHTML = document.documentElement.innerHTML;

        this.parameterUsageMap.forEach((paramData, paramId) => {
            // Controlla timing window
            if (currentTime - paramData.timestamp < timeWindow) {
                // Ottieni tutte le versioni encoded/decoded del parametro
                const paramVersions = this.getAllEncodingVersions(paramData.value);
                
                // Testa ogni versione nell'HTML della pagina
                const hasMatch = paramVersions.some(version => {
                    return this.isParameterInPageHTML(version, pageHTML);
                });

                if (hasMatch) {
                    foundParams.push(paramId);
                    console.log('🔍 Regex correlation found in page HTML:', {
                        parameter: paramData.parameter,
                        value: paramData.value,
                        foundInHTML: true,
                        matchedVersions: paramVersions.filter(v => this.isParameterInPageHTML(v, pageHTML))
                    });
                }
            }
        });

        return foundParams;
    }

    getAllEncodingVersions(paramValue) {
        if (!paramValue || typeof paramValue !== 'string') return [];
        
        const versions = new Set();
        let currentValue = paramValue;
        
        // Aggiungi versione originale
        versions.add(currentValue);
        
        // Se è un URL completo, estrai solo i parametri
        if (currentValue.includes('?')) {
            const urlParams = this.extractURLParameters(currentValue);
            urlParams.forEach(param => versions.add(param));
        }
        
        // Decode fino a 3 livelli (gestisce double/triple encoding)
        for (let i = 0; i < 3; i++) {
            try {
                const decoded = decodeURIComponent(currentValue);
                if (decoded === currentValue) break; // Nessun cambio, stop
                versions.add(decoded);
                currentValue = decoded;
            } catch (e) {
                break; // Errore di decoding, stop
            }
        }
        
        // Aggiungi versione HTML decoded
        try {
            const htmlDecoded = this.htmlDecode(paramValue);
            if (htmlDecoded !== paramValue) {
                versions.add(htmlDecoded);
            }
        } catch (e) {
            // Ignore HTML decode errors
        }
        
        return Array.from(versions).filter(v => v && v.length > 0);
    }

    // Estrai parametri da URL completi
    extractURLParameters(url) {
        const params = [];
        
        try {
            const urlObj = new URL(url);
            
            // Parametri search (?param=value)
            urlObj.searchParams.forEach((value, key) => {
                if (value) params.push(value);
            });
            
            // Hash parameters (#param=value)
            if (urlObj.hash) {
                const hashParams = urlObj.hash.substring(1);
                if (hashParams.includes('=')) {
                    const hashSearchParams = new URLSearchParams(hashParams);
                    hashSearchParams.forEach((value, key) => {
                        if (value) params.push(value);
                    });
                } else {
                    params.push(hashParams);
                }
            }
            
            // Path segments
            const pathSegments = urlObj.pathname.split('/').filter(s => s && s.length > 0);
            params.push(...pathSegments);
            
        } catch (e) {
            console.warn('Error parsing URL:', e);
        }
        
        return params;
    }

    isParameterInSinkValue(paramVersion, sinkValue) {
        if (!paramVersion || !sinkValue || typeof paramVersion !== 'string' || typeof sinkValue !== 'string') {
            return false;
        }
        
        // Ignora parametri troppo corti (evita falsi positivi)
        if (paramVersion.length < 2) return false;
        
        // Ignora parametri "noise" comuni
        const noiseValues = ['true', 'false', '1', '0', 'yes', 'no', 'on', 'off'];
        if (noiseValues.includes(paramVersion.toLowerCase())) return false;
        
        // Escape regex special characters - REGEX CORRETTA
        const specialChars = /[.*+?^${}()|[\]\\]/g;
        const escapedParam = paramVersion.replace(specialChars, '\\$&');
        
        // Cerca parametro completo con word boundaries
        const regex = new RegExp('\\b' + escapedParam + '\\b', 'i');
        return regex.test(sinkValue);
    }

    // Cerca parametro nell'HTML della pagina
    isParameterInPageHTML(paramVersion, pageHTML) {
        if (!paramVersion || !pageHTML || typeof paramVersion !== 'string' || typeof pageHTML !== 'string') {
            return false;
        }
        
        // Ignora parametri troppo corti (evita falsi positivi)
        if (paramVersion.length < 3) return false;
        
        // Ignora parametri "noise" comuni
        const noiseValues = ['true', 'false', '1', '0', 'yes', 'no', 'on', 'off', 'null', 'undefined'];
        if (noiseValues.includes(paramVersion.toLowerCase())) return false;
        
        // Escape regex special characters - REGEX CORRETTA
        const specialChars = /[.*+?^${}()|[\]\\]/g;
        const escapedParam = paramVersion.replace(specialChars, '\\$&');
        
        // Cerca parametro completo con word boundaries nell'HTML
        const regex = new RegExp('\\b' + escapedParam + '\\b', 'i');
        const found = regex.test(pageHTML);
        
        if (found) {
            console.log('🎯 Parameter found in page HTML:', {
                parameter: paramVersion,
                context: this.getParameterContext(paramVersion, pageHTML)
            });
        }
        
        return found;
    }

    // Ottieni contesto dove il parametro appare nell'HTML
    getParameterContext(paramVersion, pageHTML) {
        const specialChars = /[.*+?^${}()|[\]\\]/g;
        const escapedParam = paramVersion.replace(specialChars, '\\$&');
        const regex = new RegExp('(.{0,50})\\b' + escapedParam + '\\b(.{0,50})', 'i');
        const match = pageHTML.match(regex);
        
        if (match) {
            return '...' + match[1] + '**' + paramVersion + '**' + match[2] + '...';
        }
        
        return 'Context not found';
    }

    htmlDecode(str) {
        // 🔧 CIRCUIT BREAKER: Evita loop infinito
        this.processingDepth = this.processingDepth || 0;
        
        if (this.processingDepth > 5) {
            console.log('🔧 Circuit breaker: htmlDecode depth limit reached');
            return str || '';
        }
        
        this.processingDepth++;
        
        try {
            if (!str || typeof str !== 'string') {
                this.processingDepth--;
                return str;
            }
            
            const textarea = document.createElement('textarea');
            textarea.innerHTML = str;
            const result = textarea.value;
            
            this.processingDepth--;
            return result;
            
        } catch (e) {
            this.processingDepth--;
            return str || '';
        }
    }

    getSeverityBySinkType(sinkType) {
        const severityMap = {
            'eval': 'CRITICAL',
            'setTimeout': 'CRITICAL',
            'setInterval': 'CRITICAL',
            'Function': 'CRITICAL',
            'innerHTML': 'HIGH',
            'outerHTML': 'HIGH',
            'document.write': 'HIGH',
            'insertAdjacentHTML': 'HIGH',
            'location.href': 'MEDIUM',
            'addEventListener': 'MEDIUM'
        };
        
        return severityMap[sinkType] || 'MEDIUM';
    }

    highlightVulnerableElement(element, sinkData) {
        if (!element || element.nodeType !== 1) return;

        // Rimuovi highlighting precedente
        this.removeHighlight(element);

        // Aggiungi highlighting VULNERABILITÀ (rosso lampeggiante)
        const highlight = document.createElement('div');
        highlight.className = 'domxss-vulnerability-highlight';
        highlight.style.cssText = 'position: absolute; border: 3px solid #ff0000; background: rgba(255, 0, 0, 0.2); pointer-events: none; z-index: 999999; box-shadow: 0 0 20px rgba(255, 0, 0, 0.8); animation: domxss-pulse 1s infinite;';

        // Aggiungi CSS animation
        if (!document.getElementById('domxss-vulnerability-styles')) {
            const style = document.createElement('style');
            style.id = 'domxss-vulnerability-styles';
            style.textContent = '@keyframes domxss-pulse { 0% { transform: scale(1); box-shadow: 0 0 20px rgba(255, 0, 0, 0.8); } 50% { transform: scale(1.05); box-shadow: 0 0 30px rgba(255, 0, 0, 1); } 100% { transform: scale(1); box-shadow: 0 0 20px rgba(255, 0, 0, 0.8); } }';
            document.head.appendChild(style);
        }

        // Posiziona highlight
        const rect = element.getBoundingClientRect();
        highlight.style.left = (rect.left + window.scrollX) + 'px';
        highlight.style.top = (rect.top + window.scrollY) + 'px';
        highlight.style.width = rect.width + 'px';
        highlight.style.height = rect.height + 'px';

        // Aggiungi tooltip VULNERABILITÀ
        const tooltip = document.createElement('div');
        tooltip.className = 'domxss-vulnerability-tooltip';
        tooltip.style.cssText = 'position: absolute; background: #ff0000; color: white; padding: 8px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; white-space: nowrap; z-index: 1000000; top: -35px; left: 0; box-shadow: 0 2px 10px rgba(0,0,0,0.3);';
        tooltip.innerHTML = '🚨 VULNERABILITY: ' + sinkData.type + ' - ' + sinkData.connectedParameters.length + ' param(s)';
        
        highlight.appendChild(tooltip);
        document.body.appendChild(highlight);

        // Salva riferimento per cleanup
        this.highlightedElements.add({
            element: element,
            highlight: highlight,
            sinkData: sinkData,
            isVulnerability: true
        });

        // Auto-remove dopo 10 secondi (più lungo per vulnerabilità)
        setTimeout(() => {
            this.removeHighlight(element);
        }, 10000);
    }

    notifyVulnerabilityFound(sinkData) {
        // Notifica background script per badge e notification
        window.dispatchEvent(new CustomEvent('domxss-vulnerability-found', {
            detail: {
                type: sinkData.type,
                severity: this.getSeverityBySinkType(sinkData.type),
                parameters: sinkData.connectedParameters,
                element: this.getDOMPath(sinkData.domElement),
                value: sinkData.value
            }
        }));
    }

    stackTracesRelated(paramStack, sinkStack) {
        // Semplificata: cerca funzioni comuni negli stack trace
        const paramFunctions = this.extractFunctionNames(paramStack);
        const sinkFunctions = this.extractFunctionNames(sinkStack);
        
        // Se condividono almeno una funzione, sono probabilmente collegati
        return paramFunctions.some(func => sinkFunctions.includes(func));
    }

    extractFunctionNames(stackTrace) {
        if (!stackTrace) return [];
        
        const functionNames = [];
        const lines = stackTrace.split('\n');
        
        lines.forEach(line => {
            const match = line.match(/at\s+(\w+)/);
            if (match && match[1]) {
                functionNames.push(match[1]);
            }
        });
        
        return functionNames;
    }

    createConnection(paramId, sinkId) {
        const connectionId = 'conn-' + paramId + '-' + sinkId;
        
        const connection = {
            id: connectionId,
            parameterId: paramId,
            sinkId: sinkId,
            timestamp: Date.now(),
            verified: false
        };

        this.connections.set(connectionId, connection);

        // Aggiorna mapping bidirezionale
        const paramData = this.parameterUsageMap.get(paramId);
        if (paramData) {
            paramData.connectedSinks.push(sinkId);
        }

        // Notifica connessione trovata
        this.notifyConnectionFound(connection);
    }

    // ===============================
    // DOM OBSERVER E HIGHLIGHTING
    // ===============================
    setupDOMObserver() {
        this.domObserver = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                this.handleDOMChange(mutation);
            });
        });

        // Osserva document.body se disponibile, altrimenti document.documentElement
        const targetNode = document.body || document.documentElement;
        if (targetNode) {
            this.domObserver.observe(targetNode, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeOldValue: true,
                characterData: true,
                characterDataOldValue: true
            });
        } else {
            // Se DOM non è ancora pronto, riprova dopo
            setTimeout(() => {
                const retryTarget = document.body || document.documentElement;
                if (retryTarget) {
                    this.domObserver.observe(retryTarget, {
                        childList: true,
                        subtree: true,
                        attributes: true,
                        attributeOldValue: true,
                        characterData: true,
                        characterDataOldValue: true
                    });
                }
            }, 100);
        }
    }

    handleDOMChange(mutation) {
        // Trova sink collegati a questa modifica DOM
        const relevantSinks = this.findSinksForDOMChange(mutation);
        
        relevantSinks.forEach(sinkData => {
            // Aggiorna informazioni sulla modifica DOM
            sinkData.domMutations = sinkData.domMutations || [];
            sinkData.domMutations.push({
                type: mutation.type,
                target: mutation.target,
                addedNodes: Array.from(mutation.addedNodes),
                removedNodes: Array.from(mutation.removedNodes),
                oldValue: mutation.oldValue,
                timestamp: Date.now()
            });

            // Re-evidenzia elemento se necessario
            if (mutation.target && mutation.target.nodeType === 1) {
                this.highlightDOMElement(mutation.target, sinkData);
            }
        });
    }

    findSinksForDOMChange(mutation) {
        const relevantSinks = [];
        
        this.sinkDOMMap.forEach((sinkData, sinkId) => {
            // Controlla se il sink è collegato a questo elemento DOM
            if (sinkData.domElement === mutation.target || 
                sinkData.domElement && sinkData.domElement.contains && sinkData.domElement.contains(mutation.target)) {
                relevantSinks.push(sinkData);
            }
        });
        
        return relevantSinks;
    }

    highlightDOMElement(element, sinkData) {
        if (!element || element.nodeType !== 1) return;

        // Rimuovi highlighting precedente
        this.removeHighlight(element);

        // Aggiungi nuovo highlighting
        const highlight = document.createElement('div');
        highlight.className = 'domxss-highlight';
        highlight.style.cssText = 'position: absolute; border: 2px solid #ff0000; background: rgba(255, 0, 0, 0.1); pointer-events: none; z-index: 999999; box-shadow: 0 0 10px rgba(255, 0, 0, 0.5);';

        // Posiziona highlight
        const rect = element.getBoundingClientRect();
        highlight.style.left = (rect.left + window.scrollX) + 'px';
        highlight.style.top = (rect.top + window.scrollY) + 'px';
        highlight.style.width = rect.width + 'px';
        highlight.style.height = rect.height + 'px';

        // Aggiungi tooltip con informazioni
        const tooltip = document.createElement('div');
        tooltip.className = 'domxss-tooltip';
        tooltip.style.cssText = 'position: absolute; background: black; color: white; padding: 5px; border-radius: 3px; font-size: 12px; white-space: nowrap; z-index: 1000000; top: -30px; left: 0;';
        tooltip.textContent = sinkData.type + ' - ' + sinkData.connectedParameters.length + ' param(s)';
        
        highlight.appendChild(tooltip);
        document.body.appendChild(highlight);

        // Salva riferimento per cleanup
        this.highlightedElements.add({
            element: element,
            highlight: highlight,
            sinkData: sinkData
        });

        // Auto-remove dopo 5 secondi
        setTimeout(() => {
            this.removeHighlight(element);
        }, 5000);
    }

    removeHighlight(element) {
        this.highlightedElements.forEach(item => {
            if (item.element === element) {
                if (item.highlight.parentNode) {
                    item.highlight.parentNode.removeChild(item.highlight);
                }
                this.highlightedElements.delete(item);
            }
        });
    }

    // ===============================
    // SISTEMA BREAKPOINT
    // ===============================
    setupBreakpointSystem() {
        window.addEventListener('domxss-set-breakpoint', (event) => {
            this.setBreakpoint(event.detail.parameter);
        });

        window.addEventListener('domxss-remove-breakpoint', (event) => {
            this.removeBreakpoint(event.detail.parameter);
        });
    }

    setBreakpoint(parameter) {
        this.breakpoints.set(parameter, {
            parameter: parameter,
            active: true,
            timestamp: Date.now()
        });

        console.log('Breakpoint set for parameter: ' + parameter);
    }

    removeBreakpoint(parameter) {
        this.breakpoints.delete(parameter);
        console.log('Breakpoint removed for parameter: ' + parameter);
    }

    triggerBreakpoint(parameterDetail) {
        console.log('🔴 BREAKPOINT TRIGGERED:', parameterDetail);
        
        // Crea messaggio di debug dettagliato
        const debugInfo = {
            parameter: parameterDetail.parameter,
            value: parameterDetail.value,
            source: parameterDetail.source,
            stackTrace: parameterDetail.stackTrace,
            timestamp: parameterDetail.timestamp
        };

        // Notifica breakpoint
        window.dispatchEvent(new CustomEvent('domxss-breakpoint-hit', {
            detail: debugInfo
        }));

        // Opzionale: pausa esecuzione (se debugger disponibile)
        if (window.devtools && window.devtools.inspectedWindow) {
            debugger;
        }
    }

    // ===============================
    // UTILITY FUNCTIONS
    // ===============================
    getDOMPath(element) {
        if (!element || element.nodeType !== 1) return '';
        
        const path = [];
        let current = element;
        
        while (current && current.nodeType === 1) {
            let selector = current.tagName.toLowerCase();
            
            if (current.id) {
                selector += '#' + current.id;
            } else if (current.className) {
                selector += '.' + current.className.split(' ').join('.');
            }
            
            path.unshift(selector);
            current = current.parentElement;
        }
        
        return path.join(' > ');
    }

    setupEventListeners() {
        // Listener per cleanup
        window.addEventListener('beforeunload', () => {
            this.cleanup();
        });

        // 🔧 FIX: Bridge per eventi dal content-script
        window.addEventListener('domxss-parameters-found', (event) => {
            this.handleContentScriptParameters(event.detail);
        });

        // 🔧 FIX: Bridge per eventi sink dal content-script  
        window.addEventListener('domxss-sinks-found', (event) => {
            this.handleContentScriptSinks(event.detail);
        });
    }

    cleanup() {
        // Rimuovi tutti gli highlight
        this.highlightedElements.forEach(item => {
            if (item.highlight.parentNode) {
                item.highlight.parentNode.removeChild(item.highlight);
            }
        });
        this.highlightedElements.clear();

        // Disconnetti observer
        if (this.domObserver) {
            this.domObserver.disconnect();
        }
    }

    notifyConnectionFound(connection) {
        window.dispatchEvent(new CustomEvent('domxss-connection-found', {
            detail: connection
        }));
    }

    // ===============================
    // API PUBBLICHE
    // ===============================
    getAllConnections() {
        return Array.from(this.connections.values());
    }

    getConnectionsByParameter(parameter) {
        return this.getAllConnections().filter(conn => {
            const paramData = this.parameterUsageMap.get(conn.parameterId);
            return paramData && paramData.parameter === parameter;
        });
    }

    getHighlightedElements() {
        return Array.from(this.highlightedElements);
    }

    forceHighlightElement(element) {
        this.highlightDOMElement(element, {
            type: 'manual',
            connectedParameters: []
        });
    }

    getDetailedReport() {
            const report = {
                connections: this.getAllConnections(),
                parameters: Array.from(this.parameterUsageMap.values()),
                sinks: Array.from(this.sinkDOMMap.values()),
                highlightedElements: this.getHighlightedElements().length,
                breakpoints: Array.from(this.breakpoints.values())
            };
            return report;
}

    // ===============================
    // 🔧 NUOVE FUNZIONI DI BRIDGE
    // ===============================
handleContentScriptParameters(detail) {
    console.log('🔧 Bridge: Parameters from content-script:', detail);
    
    if (detail.parameters) {
        Object.keys(detail.parameters).forEach(source => {
            if (detail.parameters[source]) {
                Object.keys(detail.parameters[source]).forEach(paramName => {
                    const paramData = detail.parameters[source][paramName];
                    
                    this.handleParameterAccess({
                        source: source,
                        parameter: paramName,
                        value: paramData.value || paramData.decoded,
                        stackTrace: 'Content-Script-Generated',
                        timestamp: Date.now()
                    });
                });
            }
        });
    }
}

handleContentScriptSinks(detail) {
    console.log('🔧 Bridge: Sinks from content-script:', detail);
    
    if (detail.sinks) {
        Object.keys(detail.sinks).forEach(category => {
            const categoryData = detail.sinks[category];
            if (categoryData.matches) {
                categoryData.matches.forEach(match => {
                    this.handleSinkUsage({
                        type: category,
                        value: match.context || match.match,
                        element: document.body,
                        stackTrace: 'Content-Script-Generated',
                        timestamp: Date.now()
                    });
                });
            }
        });
    }

        
        // Cleanup più aggressivo
        setTimeout(() => {
            if (this.processedSinks) {
                this.processedSinks.delete(detail.timestamp);
            }
        }, 5000); // Cleanup dopo 5 secondi invece di 10
    }
// ===============================
// 🎯 CONSOLE THROTTLING HELPER
// ===============================

shouldLog(type = 'normal') {
    const now = Date.now();
    
    // Per vulnerability log, limita il numero
    if (type === 'vulnerability') {
        if (this.vulnerabilityLogCount >= this.maxVulnerabilityLogs) {
            return false;
        }
        this.vulnerabilityLogCount++;
        return true;
    }
    
    // Per log normali, throttling temporale
    if (now - this.lastLogTime < this.logThrottle) {
        return false;
    }
    
    this.lastLogTime = now;
    return true;
}

}  


// ===============================
// INIZIALIZZAZIONE
// ===============================
const domTracker = new DOMTracker();

// Esporta per uso da altri script
window.domXSSAnalyzer = window.domXSSAnalyzer || {};
window.domXSSAnalyzer.domTracker = domTracker;