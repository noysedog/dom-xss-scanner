// ===============================
// URL-ANALYZER.JS
// Analizza parametri URL e sources per DOM-based XSS
// ===============================

class URLAnalyzer {
    constructor() {
        this.foundParameters = new Map();
        this.monitoredSources = new Set();
        this.noiseParams = [
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
            'fbclid', 'gclid', 'msclkid', 'twclid',
            '_ga', '_gid', '_gat', '_fbp', '_fbc',
            'ref', 'source', 'medium', 'campaign'
        ];
        this.init();
    }

    init() {
        this.analyzeCurrentURL();
        this.setupURLMonitoring();
        this.setupSourcesMonitoring();
    }

    // ===============================
    // ANALISI URL CORRENTE
    // ===============================
    analyzeCurrentURL() {
        const results = {
            search: this.parseSearchParams(),
            hash: this.parseHashParams(),
            pathname: this.parsePathname(),
            referrer: this.parseReferrer(),
            cookie: this.parseCookies(),
            localStorage: this.parseLocalStorage(),
            sessionStorage: this.parseSessionStorage(),
            windowName: this.parseWindowName(),
            fullURL: this.parseFullURL()
        };

        // Filtra parametri noise
        Object.keys(results).forEach(source => {
            if (results[source]) {
                results[source] = this.filterNoiseParams(results[source]);
            }
        });

        this.foundParameters.set('initial', results);
        this.notifyParametersFound(results);
    }

    // ===============================
    // PARSING SOURCES SPECIFICHE
    // ===============================
    parseSearchParams() {
        try {
            const params = new URLSearchParams(location.search);
            const result = {};
            
            for (const [key, value] of params) {
                result[key] = {
                    value: value,
                    decoded: this.decodeValue(value),
                    source: 'location.search',
                    raw: `?${key}=${value}`
                };
            }
            return Object.keys(result).length > 0 ? result : null;
        } catch (e) {
            console.error('Error parsing search params:', e);
            return null;
        }
    }

    parseHashParams() {
        try {
            const hash = location.hash.substring(1);
            if (!hash) return null;

            const result = {};
            
            // Hash come parametri (?param=value)
            if (hash.includes('=')) {
                const params = new URLSearchParams(hash);
                for (const [key, value] of params) {
                    result[key] = {
                        value: value,
                        decoded: this.decodeValue(value),
                        source: 'location.hash',
                        raw: `#${key}=${value}`
                    };
                }
            } else {
                // Hash semplice
                result['hash_value'] = {
                    value: hash,
                    decoded: this.decodeValue(hash),
                    source: 'location.hash',
                    raw: `#${hash}`
                };
            }
            
            return Object.keys(result).length > 0 ? result : null;
        } catch (e) {
            console.error('Error parsing hash params:', e);
            return null;
        }
    }

    parsePathname() {
        try {
            const pathname = location.pathname;
            if (pathname === '/' || pathname === '') return null;

            const segments = pathname.split('/').filter(s => s.length > 0);
            if (segments.length === 0) return null;

            const result = {};
            segments.forEach((segment, index) => {
                result[`path_segment_${index}`] = {
                    value: segment,
                    decoded: this.decodeValue(segment),
                    source: 'location.pathname',
                    raw: pathname
                };
            });

            return result;
        } catch (e) {
            console.error('Error parsing pathname:', e);
            return null;
        }
    }

    parseReferrer() {
        try {
            const referrer = document.referrer;
            if (!referrer) return null;

            const url = new URL(referrer);
            const result = {};

            // Parametri del referrer
            for (const [key, value] of url.searchParams) {
                result[`ref_${key}`] = {
                    value: value,
                    decoded: this.decodeValue(value),
                    source: 'document.referrer',
                    raw: referrer
                };
            }

            // Referrer completo
            result['referrer_full'] = {
                value: referrer,
                decoded: this.decodeValue(referrer),
                source: 'document.referrer',
                raw: referrer
            };

            return Object.keys(result).length > 0 ? result : null;
        } catch (e) {
            console.error('Error parsing referrer:', e);
            return null;
        }
    }

    parseCookies() {
        try {
            const cookies = document.cookie;
            if (!cookies) return null;

            const result = {};
            cookies.split(';').forEach(cookie => {
                const [key, value] = cookie.trim().split('=');
                if (key && value) {
                    result[`cookie_${key}`] = {
                        value: value,
                        decoded: this.decodeValue(value),
                        source: 'document.cookie',
                        raw: cookie.trim()
                    };
                }
            });

            return Object.keys(result).length > 0 ? result : null;
        } catch (e) {
            console.error('Error parsing cookies:', e);
            return null;
        }
    }

    parseLocalStorage() {
        try {
            if (!window.localStorage) return null;

            const result = {};
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);
                
                result[`ls_${key}`] = {
                    value: value,
                    decoded: this.decodeValue(value),
                    source: 'localStorage',
                    raw: `localStorage.getItem('${key}')`
                };
            }

            return Object.keys(result).length > 0 ? result : null;
        } catch (e) {
            console.error('Error parsing localStorage:', e);
            return null;
        }
    }

    parseSessionStorage() {
        try {
            if (!window.sessionStorage) return null;

            const result = {};
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const value = sessionStorage.getItem(key);
                
                result[`ss_${key}`] = {
                    value: value,
                    decoded: this.decodeValue(value),
                    source: 'sessionStorage',
                    raw: `sessionStorage.getItem('${key}')`
                };
            }

            return Object.keys(result).length > 0 ? result : null;
        } catch (e) {
            console.error('Error parsing sessionStorage:', e);
            return null;
        }
    }

    parseWindowName() {
        try {
            const name = window.name;
            if (!name) return null;

            return {
                window_name: {
                    value: name,
                    decoded: this.decodeValue(name),
                    source: 'window.name',
                    raw: name
                }
            };
        } catch (e) {
            console.error('Error parsing window.name:', e);
            return null;
        }
    }

    parseFullURL() {
        try {
            const url = document.URL;
            return {
                full_url: {
                    value: url,
                    decoded: this.decodeValue(url),
                    source: 'document.URL',
                    raw: url
                }
            };
        } catch (e) {
            console.error('Error parsing full URL:', e);
            return null;
        }
    }

    // ===============================
    // MONITORAGGIO REAL-TIME
    // ===============================
    setupURLMonitoring() {
        // Monitora cambi URL (SPA)
        let currentURL = location.href;
        
        const checkURL = () => {
            if (location.href !== currentURL) {
                currentURL = location.href;
                this.analyzeCurrentURL();
            }
        };

        // Polling per SPA che non triggherano events
        setInterval(checkURL, 1000);

        // Eventi standard
        window.addEventListener('popstate', () => {
            setTimeout(() => this.analyzeCurrentURL(), 100);
        });

        window.addEventListener('hashchange', () => {
            setTimeout(() => this.analyzeCurrentURL(), 100);
        });
    }

    setupSourcesMonitoring() {
        // Monitora accessi a localStorage/sessionStorage
        this.interceptStorageAccess();
        
        // Monitora postMessage events
        window.addEventListener('message', (event) => {
            this.handlePostMessage(event);
        });
    }

    interceptStorageAccess() {
        // Intercetta getItem su localStorage - Firefox safe
        try {
            const originalGetItem = localStorage.getItem;
            localStorage.getItem = function(key) {
                const value = originalGetItem.call(this, key);
                if (value) {
                    window.dispatchEvent(new CustomEvent('domxss-storage-access', {
                        detail: { type: 'localStorage', key, value }
                    }));
                }
                return value;
            };
        } catch (e) {
            console.warn('Cannot intercept localStorage.getItem:', e);
        }

        // Intercetta sessionStorage - Firefox safe
        try {
            const originalSessionGetItem = sessionStorage.getItem;
            sessionStorage.getItem = function(key) {
                const value = originalSessionGetItem.call(this, key);
                if (value) {
                    window.dispatchEvent(new CustomEvent('domxss-storage-access', {
                        detail: { type: 'sessionStorage', key, value }
                    }));
                }
                return value;
            };
        } catch (e) {
            console.warn('Cannot intercept sessionStorage.getItem:', e);
        }
    }

    handlePostMessage(event) {
        try {
            const result = {
                [`postmsg_${Date.now()}`]: {
                    value: typeof event.data === 'string' ? event.data : JSON.stringify(event.data),
                    decoded: this.decodeValue(event.data),
                    source: 'postMessage',
                    raw: `postMessage from ${event.origin}`
                }
            };

            this.notifyParametersFound({ postMessage: result });
        } catch (e) {
            console.error('Error handling postMessage:', e);
        }
    }

    // ===============================
    // UTILITY FUNCTIONS
    // ===============================
    decodeValue(value) {
        if (typeof value !== 'string') return value;

        try {
            let decoded = value;
            
            // URL decode multiplo
            let previous = '';
            while (decoded !== previous) {
                previous = decoded;
                decoded = decodeURIComponent(decoded);
            }

            // HTML entities
            const textarea = document.createElement('textarea');
            textarea.innerHTML = decoded;
            decoded = textarea.value;

            return decoded;
        } catch (e) {
            return value; // Ritorna originale se decode fallisce
        }
    }

    filterNoiseParams(params) {
        if (!params) return params;

        const filtered = {};
        Object.keys(params).forEach(key => {
            const paramName = key.replace(/^(ref_|cookie_|ls_|ss_)/, '');
            if (!this.noiseParams.includes(paramName.toLowerCase())) {
                filtered[key] = params[key];
            }
        });

        return Object.keys(filtered).length > 0 ? filtered : null;
    }

    notifyParametersFound(results) {
        // Invia risultati al content script
        window.dispatchEvent(new CustomEvent('domxss-parameters-found', {
            detail: {
                timestamp: Date.now(),
                url: location.href,
                parameters: results
            }
        }));
    }

    // ===============================
    // API PUBBLICHE
    // ===============================
    getAllParameters() {
        return this.foundParameters;
    }

    getParametersBySource(source) {
        const all = this.foundParameters.get('initial');
        return all ? all[source] : null;
    }

    refreshAnalysis() {
        this.analyzeCurrentURL();
    }
}

// ===============================
// INIZIALIZZAZIONE
// ===============================
const urlAnalyzer = new URLAnalyzer();

// Esporta per uso da altri script
window.domXSSAnalyzer = {
    urlAnalyzer: urlAnalyzer
};