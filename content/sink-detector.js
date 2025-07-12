// ===============================
// SINK-DETECTOR.JS
// Rileva sink vulnerabili nel JavaScript per DOM-based XSS
// ===============================

class SinkDetector {
    constructor() {
        this.foundSinks = new Map();
        this.monitoredSinks = new Set();
        this.sinkPatterns = this.initializeSinkPatterns();
        this.init();
    }

    init() {
        this.scanExistingScripts();
        this.setupDynamicScriptMonitoring();
        this.setupSinkInterception();
    }

    // ===============================
    // DEFINIZIONE PATTERN SINK
    // ===============================
    initializeSinkPatterns() {
        return {
            // Sink DOM manipulation - ALTO RISCHIO
            domManipulation: {
                patterns: [
                    /\.innerHTML\s*=/g,
                    /\.outerHTML\s*=/g,
                    /\.insertAdjacentHTML\s*\(/g,
                    /document\.write\s*\(/g,
                    /document\.writeln\s*\(/g
                ],
                severity: 'high',
                description: 'DOM manipulation sinks'
            },

            // Sink JavaScript execution - MOLTO ALTO RISCHIO
            jsExecution: {
                patterns: [
                    /eval\s*\(/g,
                    /Function\s*\(/g,
                    /setTimeout\s*\([^,]*[^"'][^,]*,/g,  // setTimeout con string
                    /setInterval\s*\([^,]*[^"'][^,]*,/g, // setInterval con string
                    /execScript\s*\(/g,
                    /new\s+Function\s*\(/g
                ],
                severity: 'critical',
                description: 'JavaScript execution sinks'
            },

            // Sink URL/Navigation - MEDIO RISCHIO
            urlNavigation: {
                patterns: [
                    /location\s*=\s*/g,
                    /location\.href\s*=/g,
                    /location\.assign\s*\(/g,
                    /location\.replace\s*\(/g,
                    /window\.open\s*\(/g,
                    /document\.location\s*=/g
                ],
                severity: 'medium',
                description: 'URL navigation sinks'
            },

            // Sink Event handlers - ALTO RISCHIO
            eventHandlers: {
                patterns: [
                    /\.on\w+\s*=/g,
                    /addEventListener\s*\(\s*[^,]*,\s*[^,]*\)/g,
                    /attachEvent\s*\(/g
                ],
                severity: 'high',
                description: 'Event handler sinks'
            },

            // Sink jQuery - ALTO RISCHIO (se jQuery presente)
            jquery: {
                patterns: [
                    /\$\([^)]*\)\.html\s*\(/g,
                    /\$\([^)]*\)\.append\s*\(/g,
                    /\$\([^)]*\)\.prepend\s*\(/g,
                    /\$\([^)]*\)\.after\s*\(/g,
                    /\$\([^)]*\)\.before\s*\(/g,
                    /\$\([^)]*\)\.replaceWith\s*\(/g,
                    /jQuery\([^)]*\)\.html\s*\(/g
                ],
                severity: 'high',
                description: 'jQuery manipulation sinks'
            },

            // Sink Attributi - MEDIO RISCHIO
            attributes: {
                patterns: [
                    /\.setAttribute\s*\(\s*["']on\w+["']/g,
                    /\.src\s*=/g,
                    /\.href\s*=/g,
                    /\.action\s*=/g,
                    /\.formAction\s*=/g
                ],
                severity: 'medium',
                description: 'Attribute manipulation sinks'
            },

            // Sink Storage - BASSO RISCHIO
            storage: {
                patterns: [
                    /localStorage\.setItem\s*\(/g,
                    /sessionStorage\.setItem\s*\(/g,
                    /document\.cookie\s*=/g
                ],
                severity: 'low',
                description: 'Storage sinks'
            }
        };
    }

    // ===============================
    // SCAN SCRIPT ESISTENTI
    // ===============================
    scanExistingScripts() {
        // Scan script inline
        const inlineScripts = document.querySelectorAll('script:not([src])');
        inlineScripts.forEach((script, index) => {
            this.analyzeScriptContent(script.textContent, `inline-script-${index}`, 'inline');
        });

        // Scan script esterni (se già caricati)
        const externalScripts = document.querySelectorAll('script[src]');
        externalScripts.forEach((script, index) => {
            this.loadAndAnalyzeExternalScript(script.src, `external-script-${index}`);
        });

        // Scan event handlers inline
        this.scanInlineEventHandlers();
    }

    analyzeScriptContent(content, scriptId, type) {
        if (!content || content.trim().length === 0) return;

        const results = {};
        
        Object.keys(this.sinkPatterns).forEach(category => {
            const categoryData = this.sinkPatterns[category];
            const matches = [];

            categoryData.patterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    const lineNumber = this.getLineNumber(content, match.index);
                    const context = this.getContext(content, match.index, 50);
                    
                    matches.push({
                        match: match[0],
                        index: match.index,
                        lineNumber: lineNumber,
                        context: context,
                        severity: categoryData.severity
                    });
                }
            });

            if (matches.length > 0) {
                results[category] = {
                    description: categoryData.description,
                    matches: matches,
                    severity: categoryData.severity
                };
            }
        });

        if (Object.keys(results).length > 0) {
            this.foundSinks.set(scriptId, {
                type: type,
                scriptId: scriptId,
                content: content,
                sinks: results,
                timestamp: Date.now()
            });

            this.notifySinksFound(scriptId, results);
        }
    }

    loadAndAnalyzeExternalScript(src, scriptId) {
        // Prova a caricare script esterno per l'analisi
        fetch(src)
            .then(response => response.text())
            .then(content => {
                this.analyzeScriptContent(content, scriptId, 'external');
            })
            .catch(error => {
                console.log(`Cannot load external script ${src}:`, error);
                // Nota: molti script esterni potrebbero essere cross-origin
            });
    }

    scanInlineEventHandlers() {
        const elements = document.querySelectorAll('*');
        const eventAttributes = [
            'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
            'onkeyup', 'onkeydown', 'onchange', 'onsubmit', 'onblur', 'onfocus'
        ];

        elements.forEach((element, index) => {
            eventAttributes.forEach(attr => {
                const handler = element.getAttribute(attr);
                if (handler) {
                    this.analyzeScriptContent(handler, `inline-handler-${index}-${attr}`, 'event-handler');
                }
            });
        });
    }

    // ===============================
    // MONITORAGGIO DINAMICO
    // ===============================
    setupDynamicScriptMonitoring() {
        // Observer per nuovi script aggiunti - Firefox safe
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        if (node.tagName === 'SCRIPT') {
                            const scriptId = `dynamic-script-${Date.now()}`;
                            if (node.src) {
                                this.loadAndAnalyzeExternalScript(node.src, scriptId);
                            } else {
                                this.analyzeScriptContent(node.textContent, scriptId, 'dynamic');
                            }
                        }
                        
                        // Scan script nested
                        const nestedScripts = node.querySelectorAll('script');
                        nestedScripts.forEach((script, index) => {
                            const scriptId = `nested-script-${Date.now()}-${index}`;
                            if (script.src) {
                                this.loadAndAnalyzeExternalScript(script.src, scriptId);
                            } else {
                                this.analyzeScriptContent(script.textContent, scriptId, 'nested');
                            }
                        });
                    }
                });
            });
        });

        // Osserva document.body se disponibile, altrimenti document.documentElement
        const targetNode = document.body || document.documentElement;
        if (targetNode) {
            observer.observe(targetNode, {
                childList: true,
                subtree: true
            });
        } else {
            // Se DOM non è ancora pronto, riprova dopo
            setTimeout(() => {
                const retryTarget = document.body || document.documentElement;
                if (retryTarget) {
                    observer.observe(retryTarget, {
                        childList: true,
                        subtree: true
                    });
                }
            }, 100);
        }
    }

    setupSinkInterception() {
        // Intercetta chiamate a sink critici per real-time monitoring
        this.interceptDOMManipulation();
        this.interceptJSExecution();
        this.interceptURLNavigation();
    }

    interceptDOMManipulation() {
        // Intercetta innerHTML
        const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                // Notifica utilizzo sink
                window.dispatchEvent(new CustomEvent('domxss-sink-used', {
                    detail: {
                        type: 'innerHTML',
                        element: this,
                        value: value,
                        stackTrace: new Error().stack
                    }
                }));
                
                return originalInnerHTML.set.call(this, value);
            },
            get: originalInnerHTML.get
        });

        // Intercetta outerHTML
        const originalOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(value) {
                window.dispatchEvent(new CustomEvent('domxss-sink-used', {
                    detail: {
                        type: 'outerHTML',
                        element: this,
                        value: value,
                        stackTrace: new Error().stack
                    }
                }));
                
                return originalOuterHTML.set.call(this, value);
            },
            get: originalOuterHTML.get
        });

        // Intercetta document.write
        const originalWrite = document.write;
        document.write = function(content) {
            window.dispatchEvent(new CustomEvent('domxss-sink-used', {
                detail: {
                    type: 'document.write',
                    element: document,
                    value: content,
                    stackTrace: new Error().stack
                }
            }));
            
            return originalWrite.call(this, content);
        };
    }

    interceptJSExecution() {
        // Intercetta eval
        const originalEval = window.eval;
        window.eval = function(code) {
            window.dispatchEvent(new CustomEvent('domxss-sink-used', {
                detail: {
                    type: 'eval',
                    element: window,
                    value: code,
                    stackTrace: new Error().stack
                }
            }));
            
            return originalEval.call(this, code);
        };

        // Intercetta setTimeout con string
        const originalSetTimeout = window.setTimeout;
        window.setTimeout = function(handler, delay) {
            if (typeof handler === 'string') {
                window.dispatchEvent(new CustomEvent('domxss-sink-used', {
                    detail: {
                        type: 'setTimeout',
                        element: window,
                        value: handler,
                        stackTrace: new Error().stack
                    }
                }));
            }
            
            return originalSetTimeout.call(this, handler, delay);
        };
    }

    interceptURLNavigation() {
        // Intercetta location changes - Firefox safe
        try {
            const originalHref = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
            if (originalHref && originalHref.set) {
                Object.defineProperty(location, 'href', {
                    set: function(value) {
                        window.dispatchEvent(new CustomEvent('domxss-sink-used', {
                            detail: {
                                type: 'location.href',
                                element: location,
                                value: value,
                                stackTrace: new Error().stack
                            }
                        }));
                        
                        return originalHref.set.call(this, value);
                    },
                    get: originalHref.get
                });
            }
        } catch (e) {
            console.warn('Cannot intercept location.href:', e);
        }
    }

    // ===============================
    // UTILITY FUNCTIONS
    // ===============================
    getLineNumber(content, index) {
        const lines = content.substring(0, index).split('\n');
        return lines.length;
    }

    getContext(content, index, contextLength) {
        const start = Math.max(0, index - contextLength);
        const end = Math.min(content.length, index + contextLength);
        return content.substring(start, end);
    }

    notifySinksFound(scriptId, sinks) {
        window.dispatchEvent(new CustomEvent('domxss-sinks-found', {
            detail: {
                scriptId: scriptId,
                sinks: sinks,
                timestamp: Date.now()
            }
        }));
    }

    // ===============================
    // API PUBBLICHE
    // ===============================
    getAllSinks() {
        return this.foundSinks;
    }

    getSinksByScript(scriptId) {
        return this.foundSinks.get(scriptId);
    }

    getSinksByCategory(category) {
        const results = {};
        this.foundSinks.forEach((data, scriptId) => {
            if (data.sinks[category]) {
                results[scriptId] = data.sinks[category];
            }
        });
        return results;
    }

    refreshScan() {
        this.foundSinks.clear();
        this.scanExistingScripts();
    }
}

// ===============================
// INIZIALIZZAZIONE
// ===============================
const sinkDetector = new SinkDetector();

// Listener per sink usage real-time
window.addEventListener('domxss-sink-used', (event) => {
    console.log('Sink used:', event.detail);
});

// Esporta per uso da altri script
window.domXSSAnalyzer = window.domXSSAnalyzer || {};
window.domXSSAnalyzer.sinkDetector = sinkDetector;