// in main.js
const fs = require('fs');
const path = require('path');
const logPath = path.join(process.env.APPDATA, 'AegisCore/history.json');

fs.watch(logPath, (event) => {
    if (event === 'change') {
        const data = fs.readFileSync(logPath, 'utf8');
        mainWindow.webContents.send('new-threat-data', JSON.parse(data));
    }
});