const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// ADMIN PASSWORD - CHANGE THIS
const ADMIN_PASSWORD = process.env.ADMIN_PASS || "change_me_admin_password";
const SECRET = process.env.SECRET_KEY || "your_super_secret_salt";

// In-memory database (use JSON file for persistence on Render)
let KEYS = {};

// Load keys from file on startup
const KEYS_FILE = path.join(__dirname, 'keys.json');
if (fs.existsSync(KEYS_FILE)) {
    KEYS = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
}

// Save keys to file
const saveKeys = () => {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(KEYS, null, 2));
};

// Generate random key
const generateKey = () => {
    const part1 = crypto.randomBytes(4).toString('hex').toUpperCase();
    const part2 = crypto.randomBytes(4).toString('hex').toUpperCase();
    const part3 = crypto.randomBytes(4).toString('hex').toUpperCase();
    const part4 = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `${part1}-${part2}-${part3}-${part4}`;
};

// HMAC verification
const verifySignature = (key, hwid, timestamp, sig) => {
    const data = `${key}:${hwid}:${timestamp}`;
    const expected = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
};

const getChallenge = () => Math.floor(Date.now() / 1000 / 30);

// ============ WEB PANEL ROUTES ============

// Admin login page
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Key Management System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: rgba(255,255,255,0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 90%;
            max-width: 500px;
        }
        h1 { color: #333; margin-bottom: 30px; text-align: center; }
        input[type="password"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 10px;
            font-size: 16px;
            margin-bottom: 20px;
        }
        button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            cursor: pointer;
            font-weight: bold;
        }
        button:hover { opacity: 0.9; }
        .error { color: #e74c3c; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Admin Login</h1>
        <form action="/admin" method="POST">
            <input type="password" name="password" placeholder="Enter admin password" required>
            <button type="submit">Login</button>
        </form>
        <div class="error" id="error"></div>
    </div>
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        if(urlParams.get('error')) {
            document.getElementById('error').textContent = 'Invalid password';
        }
    </script>
</body>
</html>
    `);
});

// Admin panel
app.post('/admin', (req, res) => {
    if (req.body.password !== ADMIN_PASSWORD) {
        return res.redirect('/?error=1');
    }
    
    const keyList = Object.entries(KEYS).map(([key, data]) => {
        const expired = Date.now() / 1000 > data.exp;
        return `
            <tr style="background: ${expired ? '#ffe6e6' : '#e6ffe6'};">
                <td style="padding: 10px; font-family: monospace; font-size: 14px;">${key}</td>
                <td style="padding: 10px;">${new Date(data.exp * 1000).toLocaleString()}</td>
                <td style="padding: 10px;">${data.hwid || 'Not locked'}</td>
                <td style="padding: 10px;">${expired ? '❌ Expired' : '✅ Active'}</td>
                <td style="padding: 10px;">
                    <form action="/delete" method="POST" style="display:inline;">
                        <input type="hidden" name="key" value="${key}">
                        <input type="hidden" name="password" value="${ADMIN_PASSWORD}">
                        <button style="padding: 5px 10px; background: #e74c3c; border: none; color: white; border-radius: 5px; cursor: pointer;">Delete</button>
                    </form>
                </td>
            </tr>
        `;
    }).join('');

    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Key Management Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .panel {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        table { width: 100%; border-collapse: collapse; }
        th { background: #667eea; color: white; padding: 15px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        input, select {
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            margin-right: 10px;
        }
        .btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        .btn:hover { opacity: 0.8; }
        .stats {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-box {
            flex: 1;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number { font-size: 36px; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔑 Key Management System</h1>
        <p>Total Keys: ${Object.keys(KEYS).length}</p>
    </div>

    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">${Object.values(KEYS).filter(k => Date.now()/1000 < k.exp).length}</div>
            <div class="stat-label">Active Keys</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">${Object.values(KEYS).filter(k => Date.now()/1000 >= k.exp).length}</div>
            <div class="stat-label">Expired Keys</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">${Object.values(KEYS).filter(k => k.hwid).length}</div>
            <div class="stat-label">HWID Locked</div>
        </div>
    </div>

    <div class="panel">
        <h2>Generate New Key</h2>
        <form action="/generate" method="POST" style="margin-top: 20px;">
            <input type="hidden" name="password" value="${ADMIN_PASSWORD}">
            <select name="duration" required>
                <option value="86400">1 Day</option>
                <option value="604800">7 Days</option>
                <option value="2592000">30 Days</option>
                <option value="7776000">90 Days</option>
                <option value="31536000">1 Year</option>
                <option value="315360000">Lifetime (10 years)</option>
            </select>
            <button type="submit" class="btn">Generate Key</button>
        </form>
    </div>

    <div class="panel">
        <h2>Active Keys</h2>
        <table>
            <tr>
                <th>Key</th>
                <th>Expires</th>
                <th>HWID</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
            ${keyList || '<tr><td colspan="5" style="text-align: center; padding: 20px;">No keys generated yet</td></tr>'}
        </table>
    </div>
</body>
</html>
    `);
});

// Generate key
app.post('/generate', (req, res) => {
    if (req.body.password !== ADMIN_PASSWORD) {
        return res.redirect('/?error=1');
    }
    
    const key = generateKey();
    const duration = parseInt(req.body.duration);
    
    KEYS[key] = {
        exp: Math.floor(Date.now() / 1000) + duration,
        hwid: null,
        created: Math.floor(Date.now() / 1000)
    };
    
    saveKeys();
    res.redirect('/admin?password=' + ADMIN_PASSWORD);
});

// Delete key
app.post('/delete', (req, res) => {
    if (req.body.password !== ADMIN_PASSWORD) {
        return res.redirect('/?error=1');
    }
    
    delete KEYS[req.body.key];
    saveKeys();
    res.redirect('/admin?password=' + ADMIN_PASSWORD);
});

// ============ API ROUTES (for Python client) ============

app.post('/v1/auth', (req, res) => {
    try {
        const { k, h, t, s } = req.body;
        
        const currentChallenge = getChallenge();
        if (Math.abs(parseInt(t) - currentChallenge) > 2) {
            return res.status(403).json({ e: 1 });
        }
        
        if (!verifySignature(k, h, t, s)) {
            return res.status(403).json({ e: 2 });
        }
        
        if (!KEYS[k]) {
            return res.status(403).json({ e: 3 });
        }
        
        const keyData = KEYS[k];
        
        if (Date.now() / 1000 > keyData.exp) {
            return res.status(403).json({ e: 4 });
        }
        
        if (keyData.hwid === null) {
            KEYS[k].hwid = h;
            saveKeys();
        } else if (keyData.hwid !== h) {
            return res.status(403).json({ e: 5 });
        }
        
        return res.status(200).json({ 
            v: 1, 
            d: Math.floor(Date.now() / 1000) + 3600 
        });
        
    } catch (err) {
        return res.status(500).json({ e: 99 });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', keys: Object.keys(KEYS).length });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});