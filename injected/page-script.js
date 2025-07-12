// ===============================
// PAGE-SCRIPT.JS
// Script injected nel context della pagina per intercettazioni profonde
// ===============================

(function() {
    'use strict';

    // Evita doppia inizializzazione
    if (window.domXSSPageScript) {
        return;
    }

    class DOMXSSPageScript {
        constructor() {
            this.initialized = false;
            this.originalFunctions = new Map();
            this.interceptedCalls = new Map();
            this.parameterTrace = new Map();
            this.sinkTrace = new Map();
            this.debugMode = false;
            this.init();
        }

        init() {
            if (this.initialized) return;
            
            console.log('🚀 DOM XSS Page Script initializing...');
            
            this.setupDeepInterceptions();
            this.setupParameterTracing();
            this.setupSinkTracing();
            this.setupCommunication();
            this.setupFrameworkHooks();
            
            this.initialized = true;
            console.log('✅ DOM XSS Page Script initialized');
        }

        // ===============================
        // INTERCETTAZIONI PROFONDE
        // ===============================
        setupDeepInterceptions() {
            // Intercetta Object.defineProperty per catturare dynamic properties
            this.interceptObjectDefineProperty();
            
            // Intercetta Function constructor
            this.interceptFunctionConstructor();
            
            // Intercetta eval e varianti
            this.interceptEvalFamily();
            
            // Intercetta DOM manipulation avanzata
            this.interceptAdvancedDOMManipulation();
            
            // Intercetta URL/Location modifications
            this.interceptLocationModifications();
            
            // Intercetta Event handling
            this.interceptEventHandling();
            
            // Intercetta Storage operations
            this.interceptStorageOperations();
            
            // Intercetta Network requests
            this.interceptNetworkRequests();
        }

        interceptObjectDefineProperty() {
            const original = Object.defineProperty;
            const self = this;
            
            Object.defineProperty = function(obj, prop, descriptor) {
                // Traccia definizioni di proprietà pericolose
                if (descriptor.set && typeof descriptor.set === 'function') {
                    if (prop === 'innerHTML' || prop === 'outerHTML') {
                        self.logInterception('Object.defineProperty', {
                            object: obj,
                            property: prop,
                            hasStackTrace: true,
                            stackTrace: new Error().stack
                        });
                    }
                }
                
                return original.call(this, obj, prop, descriptor);
            };
            
            this.originalFunctions.set('Object.defineProperty', original);
        }

        interceptFunctionConstructor() {
            const original = window.Function;
            const self = this;
            
            window.Function = function(...args) {
                const code = args[args.length - 1];
                
                self.logInterception('Function constructor', {
                    arguments: args,
                    code: code,
                    stackTrace: new Error().stack
                });
                
                // Analizza il codice per parametri
                if (typeof code === 'string') {
                    self.analyzeCodeForParameters(code, 'Function constructor');
                }
                
                return original.apply(this, args);
            };
            
            this.originalFunctions.set('Function', original);
        }

        interceptEvalFamily() {
            // eval
            const originalEval = window.eval;
            const self = this;
            
            window.eval = function(code) {
                self.logInterception('eval', {
                    code: code,
                    stackTrace: new Error().stack
                });
                
                if (typeof code === 'string') {
                    self.analyzeCodeForParameters(code, 'eval');
                }
                
                return originalEval.call(this, code);
            };
            
            // setTimeout/setInterval con string
            const originalSetTimeout = window.setTimeout;
            const originalSetInterval = window.setInterval;
            
            window.setTimeout = function(handler, delay, ...args) {
                if (typeof handler === 'string') {
                    self.logInterception('setTimeout', {
                        code: handler,
                        delay: delay,
                        stackTrace: new Error().stack
                    });
                    
                    self.analyzeCodeForParameters(handler, 'setTimeout');
                }
                
                return originalSetTimeout.call(this, handler, delay, ...args);
            };
            
            window.setInterval = function(handler, delay, ...args) {
                if (typeof handler === 'string') {
                    self.logInterception('setInterval', {
                        code: handler,
                        delay: delay,
                        stackTrace: new Error().stack
                    });
                    
                    self.analyzeCodeForParameters(handler, 'setInterval');
                }
                
                return originalSetInterval.call(this, handler, delay, ...args);
            };
            
            this.originalFunctions.set('eval', originalEval);
            this.originalFunctions.set('setTimeout', originalSetTimeout);
            this.originalFunctions.set('setInterval', originalSetInterval);
        }

        interceptAdvancedDOMManipulation() {
            // insertAdjacentHTML
            const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
            const self = this;
            
            Element.prototype.insertAdjacentHTML = function(position, html) {
                self.logInterception('insertAdjacentHTML', {
                    element: this,
                    position: position,
                    html: html,
                    stackTrace: new Error().stack
                });
                
                if (typeof html === 'string') {
                    self.analyzeCodeForParameters(html, 'insertAdjacentHTML');
                }
                
                return originalInsertAdjacentHTML.call(this, position, html);
            };
            
            // createContextualFragment
            if (window.Range && Range.prototype.createContextualFragment) {
                const originalCreateContextualFragment = Range.prototype.createContextualFragment;
                
                Range.prototype.createContextualFragment = function(html) {
                    self.logInterception('createContextualFragment', {
                        html: html,
                        stackTrace: new Error().stack
                    });
                    
                    if (typeof html === 'string') {
                        self.analyzeCodeForParameters(html, 'createContextualFragment');
                    }
                    
                    return originalCreateContextualFragment.call(this, html);
                };
            }
            
            this.originalFunctions.set('insertAdjacentHTML', originalInsertAdjacentHTML);
        }

        interceptLocationModifications() {
            // Intercetta tutte le modifiche a location
            const locationProperties = ['href', 'search', 'hash', 'pathname'];
            
            locationProperties.forEach(prop => {
                const descriptor = Object.getOwnPropertyDescriptor(Location.prototype, prop);
                if (descriptor && descriptor.set) {
                    const originalSetter = descriptor.set;
                    const self = this;
                    
                    Object.defineProperty(Location.prototype, prop, {
                        set: function(value) {
                            self.logInterception(`location.${prop}`, {
                                value: value,
                                currentLocation: location.href,
                                stackTrace: new Error().stack
                            });
                            
                            if (typeof value === 'string') {
                                self.analyzeCodeForParameters(value, `location.${prop}`);
                            }
                            
                            return originalSetter.call(this, value);
                        },
                        get: descriptor.get
                    });
                }
            });
        }

        interceptEventHandling() {
            // addEventListener
            const originalAddEventListener = EventTarget.prototype.addEventListener;
            const self = this;
            
            EventTarget.prototype.addEventListener = function(type, listener, options) {
                if (typeof listener === 'string') {
                    self.logInterception('addEventListener', {
                        element: this,
                        type: type,
                        listener: listener,
                        stackTrace: new Error().stack
                    });
                    
                    self.analyzeCodeForParameters(listener, 'addEventListener');
                }
                
                return originalAddEventListener.call(this, type, listener, options);
            };
            
            // Event handler properties (onclick, onload, etc.)
            const eventProps = [
                'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
                'onkeyup', 'onkeydown', 'onchange', 'onsubmit', 'onblur', 'onfocus'
            ];
            
            eventProps.forEach(prop => {
                this.interceptElementProperty(prop);
            });
            
            this.originalFunctions.set('addEventListener', originalAddEventListener);
        }

        interceptElementProperty(propName) {
            const self = this;
            
            // Intercetta su Element.prototype
            const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, propName) ||
                              Object.getOwnPropertyDescriptor(HTMLElement.prototype, propName) ||
                              Object.getOwnPropertyDescriptor(Document.prototype, propName) ||
                              Object.getOwnPropertyDescriptor(Window.prototype, propName);
            
            if (descriptor && descriptor.set) {
                const originalSetter = descriptor.set;
                
                Object.defineProperty(Element.prototype, propName, {
                    set: function(value) {
                        if (typeof value === 'string') {
                            self.logInterception(`${propName} property`, {
                                element: this,
                                value: value,
                                stackTrace: new Error().stack
                            });
                            
                            self.analyzeCodeForParameters(value, propName);
                        }
                        
                        return originalSetter.call(this, value);
                    },
                    get: descriptor.get
                });
            }
        }

        interceptStorageOperations() {
            // localStorage
            const originalLocalStorageSetItem = Storage.prototype.setItem;
            const originalLocalStorageGetItem = Storage.prototype.getItem;
            const self = this;
            
            Storage.prototype.setItem = function(key, value) {
                if (this === localStorage) {
                    self.logInterception('localStorage.setItem', {
                        key: key,
                        value: value,
                        stackTrace: new Error().stack
                    });
                    
                    if (typeof value === 'string') {
                        self.analyzeCodeForParameters(value, 'localStorage.setItem');
                    }
                }
                
                return originalLocalStorageSetItem.call(this, key, value);
            };
            
            Storage.prototype.getItem = function(key) {
                const value = originalLocalStorageGetItem.call(this, key);
                
                if (this === localStorage && value !== null) {
                    self.logInterception('localStorage.getItem', {
                        key: key,
                        value: value,
                        stackTrace: new Error().stack
                    });
                    
                    // Traccia uso del valore
                    self.traceParameterUsage(key, value, 'localStorage.getItem');
                }
                
                return value;
            };
            
            this.originalFunctions.set('localStorage.setItem', originalLocalStorageSetItem);
            this.originalFunctions.set('localStorage.getItem', originalLocalStorageGetItem);
        }

        interceptNetworkRequests() {
            // fetch
            const originalFetch = window.fetch;
            const self = this;
            
            window.fetch = function(resource, init) {
                let url = resource;
                if (typeof resource === 'object' && resource.url) {
                    url = resource.url;
                }
                
                self.logInterception('fetch', {
                    url: url,
                    init: init,
                    stackTrace: new Error().stack
                });
                
                if (typeof url === 'string') {
                    self.analyzeCodeForParameters(url, 'fetch');
                }
                
                return originalFetch.call(this, resource, init);
            };
            
            // XMLHttpRequest
            const originalXHROpen = XMLHttpRequest.prototype.open;
            const originalXHRSend = XMLHttpRequest.prototype.send;
            
            XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
                self.logInterception('XMLHttpRequest.open', {
                    method: method,
                    url: url,
                    stackTrace: new Error().stack
                });
                
                if (typeof url === 'string') {
                    self.analyzeCodeForParameters(url, 'XMLHttpRequest.open');
                }
                
                return originalXHROpen.call(this, method, url, async, user, password);
            };
            
            this.originalFunctions.set('fetch', originalFetch);
            this.originalFunctions.set('XMLHttpRequest.open', originalXHROpen);
        }

        // ===============================
        // FRAMEWORK HOOKS
        // ===============================
        setupFrameworkHooks() {
            // jQuery hooks
            this.setupJQueryHooks();
            
            // React hooks
            this.setupReactHooks();
            
            // Vue hooks
            this.setupVueHooks();
            
            // Angular hooks
            this.setupAngularHooks();
        }

        setupJQueryHooks() {
            if (window.jQuery || window.$) {
                const $ = window.jQuery || window.$;
                const self = this;
                
                // Intercetta jQuery HTML methods
                const htmlMethods = ['html', 'append', 'prepend', 'after', 'before', 'replaceWith'];
                
                htmlMethods.forEach(method => {
                    if ($.fn[method]) {
                        const original = $.fn[method];
                        
                        $.fn[method] = function(content) {
                            if (typeof content === 'string') {
                                self.logInterception(`jQuery.${method}`, {
                                    content: content,
                                    selector: this.selector,
                                    stackTrace: new Error().stack
                                });
                                
                                self.analyzeCodeForParameters(content, `jQuery.${method}`);
                            }
                            
                            return original.apply(this, arguments);
                        };
                    }
                });
            }
        }

        setupReactHooks() {
            // Hook into React's createElement if available
            if (window.React && window.React.createElement) {
                const originalCreateElement = window.React.createElement;
                const self = this;
                
                window.React.createElement = function(type, props, ...children) {
                    if (props && props.dangerouslySetInnerHTML) {
                        self.logInterception('React.dangerouslySetInnerHTML', {
                            type: type,
                            html: props.dangerouslySetInnerHTML.__html,
                            stackTrace: new Error().stack
                        });
                        
                        if (typeof props.dangerouslySetInnerHTML.__html === 'string') {
                            self.analyzeCodeForParameters(props.dangerouslySetInnerHTML.__html, 'React.dangerouslySetInnerHTML');
                        }
                    }
                    
                    return originalCreateElement.apply(this, arguments);
                };
            }
        }

        setupVueHooks() {
            // Hook into Vue's $el manipulation if available
            if (window.Vue) {
                // Vue hooks would go here
                console.log('Vue detected, hooks available');
            }
        }

        setupAngularHooks() {
            // Hook into Angular's $compile if available
            if (window.angular) {
                // Angular hooks would go here
                console.log('Angular detected, hooks available');
            }
        }

        // ===============================
        // PARAMETER TRACING
        // ===============================
        setupParameterTracing() {
            this.interceptURLParameters();
            this.interceptReferrerAccess();
            this.interceptCookieAccess();
        }

        setupSinkTracing() {
            // Placeholder per sink tracing avanzato
            console.log('Sink tracing initialized');
        }

        interceptURLParameters() {
            const self = this;
            
            // Intercetta accessi a location properties
            const urlProps = ['search', 'hash', 'pathname', 'href'];
            
            urlProps.forEach(prop => {
                const descriptor = Object.getOwnPropertyDescriptor(Location.prototype, prop);
                if (descriptor && descriptor.get) {
                    const originalGetter = descriptor.get;
                    
                    Object.defineProperty(Location.prototype, prop, {
                        get: function() {
                            const value = originalGetter.call(this);
                            
                            self.traceParameterUsage(prop, value, `location.${prop}`);
                            
                            return value;
                        },
                        set: descriptor.set
                    });
                }
            });
        }

        interceptReferrerAccess() {
            const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'referrer');
            if (descriptor && descriptor.get) {
                const originalGetter = descriptor.get;
                const self = this;
                
                Object.defineProperty(Document.prototype, 'referrer', {
                    get: function() {
                        const value = originalGetter.call(this);
                        
                        self.traceParameterUsage('referrer', value, 'document.referrer');
                        
                        return value;
                    }
                });
            }
        }

        interceptCookieAccess() {
            const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
            if (descriptor && descriptor.get) {
                const originalGetter = descriptor.get;
                const self = this;
                
                Object.defineProperty(Document.prototype, 'cookie', {
                    get: function() {
                        const value = originalGetter.call(this);
                        
                        self.traceParameterUsage('cookie', value, 'document.cookie');
                        
                        return value;
                    },
                    set: descriptor.set
                });
            }
        }

        traceParameterUsage(name, value, source) {
            const traceId = `param-${Date.now()}-${Math.random()}`;
            
            this.parameterTrace.set(traceId, {
                name: name,
                value: value,
                source: source,
                timestamp: Date.now(),
                stackTrace: new Error().stack
            });
            
            // Notifica content script
            this.notifyContentScript('parameter-accessed', {
                traceId: traceId,
                name: name,
                value: value,
                source: source,
                stackTrace: new Error().stack
            });
        }

        // ===============================
        // ANALISI CODICE
        // ===============================
        analyzeCodeForParameters(code, sinkType) {
            if (typeof code !== 'string') return;
            
            // Cerca pattern di parametri URL
            const urlPatterns = [
                /location\.search/g,
                /location\.hash/g,
                /location\.href/g,
                /document\.referrer/g,
                /document\.cookie/g,
                /localStorage\.getItem/g,
                /sessionStorage\.getItem/g,
                /URLSearchParams/g,
                /window\.name/g
            ];
            
            const foundPatterns = [];
            
            urlPatterns.forEach(pattern => {
                const matches = code.match(pattern);
                if (matches) {
                    foundPatterns.push(...matches);
                }
            });
            
            if (foundPatterns.length > 0) {
                this.notifyContentScript('parameter-pattern-found', {
                    code: code,
                    sinkType: sinkType,
                    patterns: foundPatterns,
                    stackTrace: new Error().stack
                });
            }
        }

        // ===============================
        // LOGGING E COMUNICAZIONE
        // ===============================
        logInterception(type, details) {
            const logEntry = {
                type: type,
                timestamp: Date.now(),
                details: details
            };
            
            this.interceptedCalls.set(`${type}-${Date.now()}`, logEntry);
            
            // Notifica content script
            this.notifyContentScript('interception-logged', logEntry);
            
            if (this.debugMode) {
                console.log(`🔍 Intercepted: ${type}`, details);
            }
        }

        setupCommunication() {
            // Listener per comandi dal content script
            window.addEventListener('domxss-page-command', (event) => {
                this.handleCommand(event.detail);
            });
        }

        notifyContentScript(type, data) {
            window.dispatchEvent(new CustomEvent('domxss-page-event', {
                detail: {
                    type: type,
                    data: data,
                    timestamp: Date.now()
                }
            }));
        }

        handleCommand(command) {
            const { type, data } = command;
            
            switch (type) {
                case 'enable-debug':
                    this.debugMode = true;
                    console.log('Debug mode enabled');
                    break;
                    
                case 'disable-debug':
                    this.debugMode = false;
                    console.log('Debug mode disabled');
                    break;
                    
                case 'get-intercepted-calls':
                    this.notifyContentScript('intercepted-calls-response', {
                        calls: Array.from(this.interceptedCalls.values())
                    });
                    break;
                    
                case 'clear-logs':
                    this.interceptedCalls.clear();
                    this.parameterTrace.clear();
                    break;
                    
                default:
                    console.warn('Unknown page command:', type);
            }
        }

        // ===============================
        // UTILITY METHODS
        // ===============================
        getInterceptionStats() {
            return {
                totalInterceptions: this.interceptedCalls.size,
                parameterTraces: this.parameterTrace.size,
                debugMode: this.debugMode
            };
        }

        restoreOriginalFunctions() {
            this.originalFunctions.forEach((original, name) => {
                try {
                    if (name === 'Object.defineProperty') {
                        Object.defineProperty = original;
                    } else if (name === 'Function') {
                        window.Function = original;
                    } else if (name === 'eval') {
                        window.eval = original;
                    }
                    // Add more restorations as needed
                } catch (error) {
                    console.warn(`Failed to restore ${name}:`, error);
                }
            });
        }
    }

    // ===============================
    // INIZIALIZZAZIONE
    // ===============================
    const pageScript = new DOMXSSPageScript();
    window.domXSSPageScript = pageScript;
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        pageScript.restoreOriginalFunctions();
    });

})();