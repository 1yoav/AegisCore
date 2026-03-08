const { contextBridge, ipcRenderer } = require('electron');

// This file is the ONLY bridge between your HTML pages and Electron/Node.
// It exposes a safe 'window.aegis' object that all your HTML files can use.

contextBridge.exposeInMainWorld('aegis', {

    // ── Window Controls ──────────────────────────────────────────────────────
    // Call these from your existing titlebar buttons in HTML
    minimize: () => ipcRenderer.send('window-minimize'),
    maximize: () => ipcRenderer.send('window-maximize'),
    close: () => ipcRenderer.send('window-close'),
    communication: (message) => ipcRenderer.send('communication', message),


    // ── File Picker ──────────────────────────────────────────────────────────
    // Opens native Windows file picker - use in manual_scan.html
    pickFile:   () => ipcRenderer.invoke('pick-file'),
    pickFolder: () => ipcRenderer.invoke('pick-folder'),

    // ── Threat History ───────────────────────────────────────────────────────
    // Reads from your C++ service's history.json
    getThreatHistory: () => ipcRenderer.invoke('get-threat-history'),

    // Listen for real-time threat updates pushed from the C++ service
    onThreatUpdate: (callback) => ipcRenderer.on('threat-update', (_, data) => callback(data)),
});
