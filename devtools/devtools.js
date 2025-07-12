// ===============================
// DEVTOOLS/DEVTOOLS.JS
// ===============================
// Crea il panel nelle DevTools
chrome.devtools.panels.create(
    "DOM XSS Scanner",
    "icon.png",
    "devtools/panel.html"
);
