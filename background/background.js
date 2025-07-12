// ===============================
// BACKGROUND.JS
// Background script per DOM XSS Scanner
// ===============================

class DOMXSSBackground {
    constructor() {
        this.connections = new Map();
        this.tabData = new Map();
        this.activeScans = new Set();
        this.init();
    }

    init() {
        this.setupConnectionHandlers();
        this.setupTabHandlers();
        this.setupContextMenu();
        this.setupNotifications();
        console.log('DOM XSS Scanner background initialized');
    }

    // ===============================
    // CONNECTION HANDLERS
    // ===============================
    setupConnectionHandlers() {
        // Gestisce connessioni dai content script e DevTools
        chrome.runtime.onConnect.addListener((port) => {
            console.log('New connection:', port.name);
            
            if (port.name === 'dom-xss-scanner') {
                this.handleScannerConnection(port);
            }
        });

        // Gestisce messaggi one-time
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            return this.handleMessage(message, sender, sendResponse);
        });
    }

    handleScannerConnection(port) {
        const tabId = port.sender?.tab?.id;
        
        if (!tabId) {
            console.warn('Connection without tab ID');
            return;
        }

        // Salva connessione
        this.connections.set(tabId, port);
        
        // Setup message handler
        port.onMessage.addListener((message) => {
            this.handlePortMessage(message, tabId);
        });

        // Cleanup on disconnect
        port.onDisconnect.addListener(() => {
            this.handleDisconnect(tabId);
        });

        console.log(`Scanner connected for tab ${tabId}`);
    }

    handlePortMessage(message, tabId) {
        const { type, data } = message;
        
        switch (type) {
            case 'scan-update':
                this.handleScanUpdate(data, tabId);
                break;
            case 'vulnerability-found':
                this.handleVulnerabilityFound(data, tabId);
                break;
            case 'scan-complete':
                this.handleScanComplete(data, tabId);
                break;
            case 'request-tab-info':
                this.sendTabInfo(tabId);
                break;
            default:
                console.log('Unknown port message:', type);
        }
    }

    handleMessage(message, sender, sendResponse) {
        const { type, data } = message;
        
        switch (type) {
            case 'vulnerability-found':
                this.handleVulnerabilityAlert(data, sender.tab?.id);
                sendResponse({ success: true });
                break;
                
            case 'get-scan-status':
                this.getScanStatus(sender.tab?.id, sendResponse);
                return true; // Async response
                
            case 'start-scan':
                this.startScan(sender.tab?.id, data);
                sendResponse({ success: true });
                break;
                
            case 'stop-scan':
                this.stopScan(sender.tab?.id);
                sendResponse({ success: true });
                break;
                
            case 'get-tab-data':
                this.getTabData(sender.tab?.id, sendResponse);
                return true; // Async response
                
            case 'export-scan-data':
                this.exportScanData(sender.tab?.id, sendResponse);
                return true; // Async response
                
            default:
                console.log('Unknown message:', type);
        }
        
        return false;
    }

    handleVulnerabilityAlert(vulnerabilityData, tabId) {
        if (!tabId) return;

        // Aggiorna badge con icona di allerta
        this.updateVulnerabilityBadge(tabId, vulnerabilityData.severity);

        // Mostra notification per vulnerabilità critiche
        if (vulnerabilityData.severity === 'CRITICAL') {
            this.showCriticalVulnerabilityNotification(vulnerabilityData, tabId);
        }

        // Aggiorna dati tab
        const tabData = this.tabData.get(tabId) || {};
        tabData.vulnerabilities = tabData.vulnerabilities || [];
        tabData.vulnerabilities.push({
            ...vulnerabilityData,
            timestamp: Date.now()
        });
        
        tabData.hasVulnerabilities = true;
        tabData.vulnerabilityCount = tabData.vulnerabilities.length;
        
        this.tabData.set(tabId, tabData);

        console.warn('🚨 VULNERABILITY LOGGED:', vulnerabilityData);
    }

    updateVulnerabilityBadge(tabId, severity) {
        const badgeConfig = this.getBadgeConfigBySeverity(severity);
        
        // Badge con icona di allerta
        if (typeof chrome !== 'undefined' && chrome.action) {
            chrome.action.setBadgeText({
                text: '!',
                tabId: tabId
            });
            
            chrome.action.setBadgeBackgroundColor({
                color: badgeConfig.color,
                tabId: tabId
            });

            // Aggiorna title per tooltip
            chrome.action.setTitle({
                title: `DOM XSS Scanner - ${badgeConfig.text} vulnerability found!`,
                tabId: tabId
            });
        } else if (typeof chrome !== 'undefined' && chrome.browserAction) {
            // Fallback per versioni precedenti
            chrome.browserAction.setBadgeText({
                text: '!',
                tabId: tabId
            });
            
            chrome.browserAction.setBadgeBackgroundColor({
                color: badgeConfig.color,
                tabId: tabId
            });

            chrome.browserAction.setTitle({
                title: `DOM XSS Scanner - ${badgeConfig.text} vulnerability found!`,
                tabId: tabId
            });
        }
    }

    getBadgeConfigBySeverity(severity) {
        const configs = {
            'CRITICAL': { color: '#ff0000', text: 'Critical' },
            'HIGH': { color: '#ff6600', text: 'High' },
            'MEDIUM': { color: '#ffcc00', text: 'Medium' },
            'LOW': { color: '#33cc33', text: 'Low' }
        };
        
        return configs[severity] || configs['MEDIUM'];
    }

    handleDisconnect(tabId) {
        this.connections.delete(tabId);
        this.activeScans.delete(tabId);
        console.log(`Scanner disconnected for tab ${tabId}`);
    }

    // ===============================
    // TAB MANAGEMENT
    // ===============================
    setupTabHandlers() {
        // Cleanup quando tab viene chiuso
        chrome.tabs.onRemoved.addListener((tabId) => {
            this.cleanupTab(tabId);
        });

        // Reset quando tab naviga
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'loading' && changeInfo.url) {
                this.resetTabData(tabId);
            }
        });

        // Gestisce tab activation per notifications
        chrome.tabs.onActivated.addListener((activeInfo) => {
            this.handleTabActivated(activeInfo.tabId);
        });
    }

    cleanupTab(tabId) {
        this.connections.delete(tabId);
        this.tabData.delete(tabId);
        this.activeScans.delete(tabId);
        console.log(`Cleaned up tab ${tabId}`);
    }

    resetTabData(tabId) {
        const existingData = this.tabData.get(tabId);
        if (existingData) {
            this.tabData.set(tabId, {
                ...existingData,
                parameters: [],
                sinks: [],
                connections: [],
                lastScan: null,
                scanInProgress: false
            });
        }
    }

    handleTabActivated(tabId) {
        const tabData = this.tabData.get(tabId);
        if (tabData && tabData.hasVulnerabilities) {
            // Mostra badge se ci sono vulnerabilità
            this.updateBadge(tabId, tabData.vulnerabilityCount);
        }
    }

    // ===============================
    // SCAN MANAGEMENT
    // ===============================
    handleScanUpdate(data, tabId) {
        const tabData = this.tabData.get(tabId) || {};
        
        // Aggiorna dati tab
        this.tabData.set(tabId, {
            ...tabData,
            ...data,
            lastUpdate: Date.now(),
            scanInProgress: true
        });

        // Invia aggiornamento ai DevTools se connessi
        this.notifyDevTools(tabId, 'scan-update', data);
    }

    handleVulnerabilityFound(data, tabId) {
        const tabData = this.tabData.get(tabId) || {};
        
        // Aggiorna contatore vulnerabilità
        const vulnCount = (tabData.vulnerabilityCount || 0) + 1;
        
        this.tabData.set(tabId, {
            ...tabData,
            hasVulnerabilities: true,
            vulnerabilityCount: vulnCount,
            lastVulnerability: data,
            lastVulnerabilityTime: Date.now()
        });

        // Aggiorna badge
        this.updateBadge(tabId, vulnCount);
        
        // Mostra notifica se critica
        if (data.severity === 'critical') {
            this.showCriticalVulnerabilityNotification(data, tabId);
        }

        // Invia ai DevTools
        this.notifyDevTools(tabId, 'vulnerability-found', data);
    }

    handleScanComplete(data, tabId) {
        const tabData = this.tabData.get(tabId) || {};
        
        this.tabData.set(tabId, {
            ...tabData,
            scanInProgress: false,
            lastScan: Date.now(),
            scanResults: data
        });

        this.activeScans.delete(tabId);
        
        // Invia completion ai DevTools
        this.notifyDevTools(tabId, 'scan-complete', data);
        
        console.log(`Scan complete for tab ${tabId}:`, data);
    }

    startScan(tabId, options = {}) {
        if (this.activeScans.has(tabId)) {
            console.log(`Scan already active for tab ${tabId}`);
            return;
        }

        this.activeScans.add(tabId);
        
        // Invia comando di avvio al content script
        this.sendToContentScript(tabId, {
            type: 'start-scan',
            options: options
        });
    }

    stopScan(tabId) {
        this.activeScans.delete(tabId);
        
        // Invia comando di stop al content script
        this.sendToContentScript(tabId, {
            type: 'stop-scan'
        });
    }

    getScanStatus(tabId, sendResponse) {
        const tabData = this.tabData.get(tabId);
        const isActive = this.activeScans.has(tabId);
        
        sendResponse({
            isActive: isActive,
            data: tabData,
            hasConnection: this.connections.has(tabId)
        });
    }

    // ===============================
    // COMMUNICATION HELPERS
    // ===============================
    sendToContentScript(tabId, message) {
        chrome.tabs.sendMessage(tabId, message, (response) => {
            if (chrome.runtime.lastError) {
                console.warn(`Error sending to content script:`, chrome.runtime.lastError);
            }
        });
    }

    notifyDevTools(tabId, type, data) {
        const port = this.connections.get(tabId);
        if (port) {
            try {
                port.postMessage({
                    type: type,
                    data: data,
                    timestamp: Date.now()
                });
            } catch (error) {
                console.warn('Error notifying DevTools:', error);
            }
        }
    }

    sendTabInfo(tabId) {
        chrome.tabs.get(tabId, (tab) => {
            if (chrome.runtime.lastError) {
                console.warn('Error getting tab info:', chrome.runtime.lastError);
                return;
            }
            
            this.notifyDevTools(tabId, 'tab-info', {
                url: tab.url,
                title: tab.title,
                favIconUrl: tab.favIconUrl
            });
        });
    }

    // ===============================
    // CONTEXT MENU
    // ===============================
    setupContextMenu() {
        // Context menu solo se supportato (Chrome)
        if (typeof chrome !== 'undefined' && chrome.contextMenus) {
            chrome.contextMenus.create({
                id: 'dom-xss-scan',
                title: 'Scan for DOM XSS',
                contexts: ['page']
            });

            chrome.contextMenus.create({
                id: 'dom-xss-scan-element',
                title: 'Check element for XSS',
                contexts: ['all']
            });

            chrome.contextMenus.onClicked.addListener((info, tab) => {
                this.handleContextMenuClick(info, tab);
            });
        } else {
            console.log('Context menus not supported in this browser');
        }
    }

    handleContextMenuClick(info, tab) {
        switch (info.menuItemId) {
            case 'dom-xss-scan':
                this.startScan(tab.id);
                break;
                
            case 'dom-xss-scan-element':
                this.sendToContentScript(tab.id, {
                    type: 'scan-element',
                    elementInfo: {
                        tagName: info.tagName,
                        selectionText: info.selectionText
                    }
                });
                break;
        }
    }

    // ===============================
    // NOTIFICATIONS & BADGE
    // ===============================
    setupNotifications() {
        // Request permission se necessario e supportato
        if (typeof chrome !== 'undefined' && chrome.notifications) {
            chrome.notifications.onClicked.addListener((notificationId) => {
                this.handleNotificationClick(notificationId);
            });
        }
    }

    updateBadge(tabId, count) {
        const text = count > 0 ? count.toString() : '';
        const color = this.getBadgeColor(count);
        
        // Badge API - verifica supporto
        if (typeof chrome !== 'undefined' && chrome.action) {
            chrome.action.setBadgeText({
                text: text,
                tabId: tabId
            });
            
            chrome.action.setBadgeBackgroundColor({
                color: color,
                tabId: tabId
            });
        } else if (typeof chrome !== 'undefined' && chrome.browserAction) {
            // Fallback per versioni precedenti
            chrome.browserAction.setBadgeText({
                text: text,
                tabId: tabId
            });
            
            chrome.browserAction.setBadgeBackgroundColor({
                color: color,
                tabId: tabId
            });
        }
    }

    getBadgeColor(count) {
        if (count === 0) return '#00FF00';  // Verde
        if (count <= 2) return '#FFA500';  // Arancione
        return '#FF0000';  // Rosso
    }

    showCriticalVulnerabilityNotification(vulnerability, tabId) {
        // Notifiche solo se supportate
        if (typeof chrome === 'undefined' || !chrome.notifications) {
            console.log('Notifications not supported');
            return;
        }
        
        const notificationId = `critical-${tabId}-${Date.now()}`;
        
        chrome.notifications.create(notificationId, {
            type: 'basic',
            iconUrl: 'icon.png',
            title: 'Critical DOM XSS Vulnerability Found!',
            message: `Found ${vulnerability.type} vulnerability in tab. Click to view details.`
        });
        
        // Store tab reference for click handler
        this.notificationTabs = this.notificationTabs || new Map();
        this.notificationTabs.set(notificationId, tabId);
    }

    handleNotificationClick(notificationId) {
        const tabId = this.notificationTabs?.get(notificationId);
        if (tabId) {
            // Porta il tab in primo piano
            chrome.tabs.update(tabId, { active: true });
            
            // Apri DevTools se possibile
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0] && tabs[0].id === tabId) {
                    // Trigger DevTools opening (se extension ha permissions)
                    this.sendToContentScript(tabId, {
                        type: 'show-devtools-notification'
                    });
                }
            });
        }
        
        if (chrome.notifications) {
            chrome.notifications.clear(notificationId);
        }
    }

    // ===============================
    // DATA EXPORT
    // ===============================
    getTabData(tabId, sendResponse) {
        const tabData = this.tabData.get(tabId);
        
        chrome.tabs.get(tabId, (tab) => {
            if (chrome.runtime.lastError) {
                sendResponse({ error: chrome.runtime.lastError.message });
                return;
            }
            
            sendResponse({
                success: true,
                data: {
                    tab: {
                        id: tab.id,
                        url: tab.url,
                        title: tab.title
                    },
                    scanData: tabData,
                    isActive: this.activeScans.has(tabId)
                }
            });
        });
    }

    exportScanData(tabId, sendResponse) {
        const tabData = this.tabData.get(tabId);
        
        if (!tabData) {
            sendResponse({ error: 'No scan data available' });
            return;
        }
        
        chrome.tabs.get(tabId, (tab) => {
            if (chrome.runtime.lastError) {
                sendResponse({ error: chrome.runtime.lastError.message });
                return;
            }
            
            const exportData = {
                meta: {
                    url: tab.url,
                    title: tab.title,
                    exportTime: new Date().toISOString(),
                    scannerVersion: chrome.runtime.getManifest().version
                },
                scanData: tabData,
                summary: {
                    totalParameters: tabData.parameters?.length || 0,
                    totalSinks: tabData.sinks?.length || 0,
                    totalConnections: tabData.connections?.length || 0,
                    vulnerabilityCount: tabData.vulnerabilityCount || 0,
                    hasVulnerabilities: tabData.hasVulnerabilities || false
                }
            };
            
            sendResponse({
                success: true,
                data: exportData
            });
        });
    }

    // ===============================
    // UTILITY METHODS
    // ===============================
    getAllTabsData() {
        return Array.from(this.tabData.entries()).map(([tabId, data]) => ({
            tabId,
            ...data
        }));
    }

    getActiveScansCount() {
        return this.activeScans.size;
    }

    getTotalVulnerabilities() {
        let total = 0;
        this.tabData.forEach((data) => {
            total += data.vulnerabilityCount || 0;
        });
        return total;
    }

    // Debug method
    getDebugInfo() {
        return {
            connections: this.connections.size,
            tabData: this.tabData.size,
            activeScans: this.activeScans.size,
            totalVulnerabilities: this.getTotalVulnerabilities()
        };
    }
}

// ===============================
// INIZIALIZZAZIONE
// ===============================
const domXSSBackground = new DOMXSSBackground();

// Esporta per debugging
if (typeof window !== 'undefined') {
    window.domXSSBackground = domXSSBackground;
}