const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const net = require('net');


let mainWindow;

// ─── Window Creation ──────────────────────────────────────────────────────────

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 700,
        frame: false,               // Custom titlebar (you already have one in HTML)
        backgroundColor: '#050505', // Prevents white flash on load
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,  // Renderer can't access Node directly (security)
            nodeIntegration: false,
        }
    });

    mainWindow.loadFile('index.html');

    // Uncomment when debugging:
    // mainWindow.webContents.openDevTools();
}

function sendToCppPipe(message, pipeName = 'UiPipe') {
    const pipePath = `\\\\.\\pipe\\${pipeName}`;

    const client = net.connect(pipePath, () => {
        console.log('Connected to C++ Pipe');
        // Sending the message with a newline (standard for C++ getline)
        client.write(message + '\n');
    });

    client.on('error', (err) => {
        console.error('Pipe Connection Error:', err.message);
    });

    client.on('end', () => {
        console.log('Disconnected from Pipe');
    });

    // Optional: Close connection after sending
    client.end();
}

app.whenReady().then(() => {
    createWindow();
    watchThreatLog();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});




// ─── Window Controls ──────────────────────────────────────────────────────────
// These receive signals from your existing HTML titlebar buttons

ipcMain.on('window-minimize', () => mainWindow.minimize());
ipcMain.on('window-maximize', () => {
    mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
});
ipcMain.on('window-close', () => mainWindow.close());

// ─── C++ Communication ──────────────────────────────────────────────────────
ipcMain.on('communication', (data) => {
    sendToCppPipe(data); 
});


// ─── File / Folder Picker (for Manual Scan page) ─────────────────────────────

ipcMain.handle('pick-file', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Select File to Scan',
        properties: ['openFile'],
        filters: [{ name: 'All Files', extensions: ['*'] }]
    });
    return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('pick-folder', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Select Folder to Scan',
        properties: ['openDirectory']
    });
    return result.canceled ? null : result.filePaths[0];
});


// ─── Threat History ───────────────────────────────────────────────────────────
// Reads from the same JSON file your C++ service writes to

const logPath = path.join(
    process.env.APPDATA || '',
    'AegisCore',
    'history.json'
);

ipcMain.handle('get-threat-history', () => {
    try {
        if (!fs.existsSync(logPath)) return [];
        return JSON.parse(fs.readFileSync(logPath, 'utf8'));
    } catch (e) {
        console.error('Failed to read threat history:', e);
        return [];
    }
});

// Watch the log file - push live updates to the renderer when C++ writes new threats
function watchThreatLog() {
    if (!fs.existsSync(logPath)) return;

    fs.watch(logPath, (event) => {
        if (event === 'change' && mainWindow) {
            try {
                const data = JSON.parse(fs.readFileSync(logPath, 'utf8'));
                mainWindow.webContents.send('threat-update', data);
            } catch (e) {
                console.error('Failed to parse threat update:', e);
            }
        }
    });
}
