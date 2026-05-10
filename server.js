const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const ADMIN_PASSWORD = process.env.ADMIN_PASS || "change_me_admin_password";
const SECRET = process.env.SECRET_KEY || "your_super_secret_salt";

let KEYS = {};
let SESSIONS = {};

const KEYS_FILE = path.join(__dirname, 'keys.json');
if (fs.existsSync(KEYS_FILE)) {
    KEYS = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
}

const saveKeys = () => fs.writeFileSync(KEYS_FILE, JSON.stringify(KEYS, null, 2));

const generateKey = () => {
    const part = () => crypto.randomBytes(4).toString('hex').toUpperCase();
    return `${part()}-${part()}-${part()}-${part()}`;
};

const verifySignature = (key, hwid, timestamp, sig) => {
    const data = `${key}:${hwid}:${timestamp}`;
    const expected = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
    try {
        return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
    } catch { return false; }
};

const getChallenge = () => Math.floor(Date.now() / 1000 / 30);

// Rate limiting
const rateLimitMap = {};
const rateLimit = (ip) => {
    const now = Date.now();
    if (!rateLimitMap[ip]) rateLimitMap[ip] = [];
    rateLimitMap[ip] = rateLimitMap[ip].filter(t => now - t < 60000);
    if (rateLimitMap[ip].length >= 10) return false;
    rateLimitMap[ip].push(now);
    return true;
};

// ── Web Panel ──────────────────────────────────────────────────────────────────

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html><html><head><title>Key Management System</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',sans-serif; background:linear-gradient(135deg,#667eea,#764ba2); min-height:100vh; display:flex; justify-content:center; align-items:center; }
.container { background:rgba(255,255,255,0.95); padding:40px; border-radius:20px; box-shadow:0 20px 60px rgba(0,0,0,0.3); width:90%; max-width:500px; }
h1 { color:#333; margin-bottom:30px; text-align:center; }
input[type="password"] { width:100%; padding:15px; border:2px solid #ddd; border-radius:10px; font-size:16px; margin-bottom:20px; }
button { width:100%; padding:15px; background:linear-gradient(135deg,#667eea,#764ba2); color:white; border:none; border-radius:10px; font-size:16px; cursor:pointer; font-weight:bold; }
.error { color:#e74c3c; text-align:center; margin-top:10px; }
</style></head><body>
<div class="container">
<h1>🔐 Admin Login</h1>
<form action="/admin" method="POST">
<input type="password" name="password" placeholder="Enter admin password" required>
<button type="submit">Login</button>
</form>
<div class="error" id="error"></div>
</div>
<script>if(new URLSearchParams(window.location.search).get('error')) document.getElementById('error').textContent='Invalid password';</script>
</body></html>`);
});

app.post('/admin', (req, res) => {
    if (req.body.password !== ADMIN_PASSWORD) return res.redirect('/?error=1');

    const keyList = Object.entries(KEYS).map(([key, data]) => {
        const expired = Date.now() / 1000 > data.exp;
        return `<tr style="background:${expired ? '#ffe6e6' : '#e6ffe6'};">
            <td style="padding:10px;font-family:monospace">${key}</td>
            <td style="padding:10px">${new Date(data.exp * 1000).toLocaleString()}</td>
            <td style="padding:10px">${data.hwid || 'Not locked'}</td>
            <td style="padding:10px">${data.uses || 0}</td>
            <td style="padding:10px">${expired ? '❌ Expired' : '✅ Active'}</td>
            <td style="padding:10px">
                <form action="/delete" method="POST" style="display:inline">
                    <input type="hidden" name="key" value="${key}">
                    <input type="hidden" name="password" value="${ADMIN_PASSWORD}">
                    <button style="padding:5px 10px;background:#e74c3c;border:none;color:white;border-radius:5px;cursor:pointer">Delete</button>
                </form>
                <form action="/resetHwid" method="POST" style="display:inline">
                    <input type="hidden" name="key" value="${key}">
                    <input type="hidden" name="password" value="${ADMIN_PASSWORD}">
                    <button style="padding:5px 10px;background:#f39c12;border:none;color:white;border-radius:5px;cursor:pointer">Reset HWID</button>
                </form>
            </td>
        </tr>`;
    }).join('');

    res.send(`
<!DOCTYPE html><html><head><title>Key Management Panel</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',sans-serif; background:#f5f5f5; padding:20px; }
.header { background:linear-gradient(135deg,#667eea,#764ba2); color:white; padding:30px; border-radius:10px; margin-bottom:20px; }
.panel { background:white; padding:30px; border-radius:10px; box-shadow:0 5px 15px rgba(0,0,0,0.1); margin-bottom:20px; }
table { width:100%; border-collapse:collapse; }
th { background:#667eea; color:white; padding:15px; text-align:left; }
td { padding:10px; border-bottom:1px solid #ddd; }
input,select { padding:10px; border:2px solid #ddd; border-radius:5px; margin-right:10px; }
.btn { padding:10px 20px; background:#667eea; color:white; border:none; border-radius:5px; cursor:pointer; font-weight:bold; }
.stats { display:flex; gap:20px; margin-bottom:20px; }
.stat-box { flex:1; background:white; padding:20px; border-radius:10px; box-shadow:0 5px 15px rgba(0,0,0,0.1); text-align:center; }
.stat-number { font-size:36px; font-weight:bold; color:#667eea; }
</style></head><body>
<div class="header"><h1>🔑 Key Management System</h1><p>Total Keys: ${Object.keys(KEYS).length}</p></div>
<div class="stats">
    <div class="stat-box"><div class="stat-number">${Object.values(KEYS).filter(k=>Date.now()/1000<k.exp).length}</div><div>Active</div></div>
    <div class="stat-box"><div class="stat-number">${Object.values(KEYS).filter(k=>Date.now()/1000>=k.exp).length}</div><div>Expired</div></div>
    <div class="stat-box"><div class="stat-number">${Object.values(KEYS).filter(k=>k.hwid).length}</div><div>HWID Locked</div></div>
</div>
<div class="panel">
<h2>Generate New Key</h2>
<form action="/generate" method="POST" style="margin-top:20px">
    <input type="hidden" name="password" value="${ADMIN_PASSWORD}">
    <select name="duration" required>
        <option value="86400">1 Day</option>
        <option value="604800">7 Days</option>
        <option value="2592000">30 Days</option>
        <option value="7776000">90 Days</option>
        <option value="31536000">1 Year</option>
        <option value="315360000">Lifetime</option>
    </select>
    <button type="submit" class="btn">Generate Key</button>
</form>
</div>
<div class="panel">
<h2>Keys</h2>
<table>
    <tr><th>Key</th><th>Expires</th><th>HWID</th><th>Uses</th><th>Status</th><th>Actions</th></tr>
    ${keyList || '<tr><td colspan="6" style="text-align:center;padding:20px">No keys yet</td></tr>'}
</table>
</div></body></html>`);
});

app.post('/generate', (req, res) => {
    if (req.body.password !== ADMIN_PASSWORD) return res.redirect('/?error=1');
    const key = generateKey();
    KEYS[key] = { exp: Math.floor(Date.now()/1000) + parseInt(req.body.duration), hwid: null, created: Math.floor(Date.now()/1000), uses: 0 };
    saveKeys();
    res.redirect('/admin?password=' + ADMIN_PASSWORD);
});

app.post('/delete', (req, res) => {
    if (req.body.password !== ADMIN_PASSWORD) return res.redirect('/?error=1');
    delete KEYS[req.body.key];
    saveKeys();
    res.redirect('/admin?password=' + ADMIN_PASSWORD);
});

app.post('/resetHwid', (req, res) => {
    if (req.body.password !== ADMIN_PASSWORD) return res.redirect('/?error=1');
    if (KEYS[req.body.key]) { KEYS[req.body.key].hwid = null; saveKeys(); }
    res.redirect('/admin?password=' + ADMIN_PASSWORD);
});

// ── API ────────────────────────────────────────────────────────────────────────

app.post('/v1/auth', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (!rateLimit(ip)) return res.status(429).json({ e: 6 });

    try {
        const { k, h, t, s } = req.body;

        if (!k || !h || !t || !s) return res.status(403).json({ e: 0 });

        const currentChallenge = getChallenge();
        if (Math.abs(parseInt(t) - currentChallenge) > 1)
            return res.status(403).json({ e: 1 });

        if (!verifySignature(k, h, t, s))
            return res.status(403).json({ e: 2 });

        if (!KEYS[k]) return res.status(403).json({ e: 3 });

        const keyData = KEYS[k];
        if (Date.now() / 1000 > keyData.exp) return res.status(403).json({ e: 4 });

        if (keyData.hwid === null) {
            KEYS[k].hwid = h;
        } else if (keyData.hwid !== h) {
            return res.status(403).json({ e: 5 });
        }

        // Generate session token
        const token = crypto.randomBytes(32).toString('hex');
        const expiry = Math.floor(Date.now() / 1000) + 3600;
        KEYS[k].uses = (KEYS[k].uses || 0) + 1;
        SESSIONS[token] = { key: k, exp: expiry, hwid: h };
        saveKeys();

        return res.status(200).json({ v: 1, d: expiry, token });

    } catch (err) {
        return res.status(500).json({ e: 99 });
    }
});

app.post('/v1/validate', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (!rateLimit(ip)) return res.status(429).json({ e: 6 });

    const { token, h } = req.body;
    if (!token || !h) return res.status(403).json({ e: 0 });

    const session = SESSIONS[token];
    if (!session) return res.status(403).json({ e: 1 });
    if (Date.now() / 1000 > session.exp) { delete SESSIONS[token]; return res.status(403).json({ e: 2 }); }
    if (session.hwid !== h) return res.status(403).json({ e: 3 });

    return res.status(200).json({ ok: 1 });
});

app.get('/health', (req, res) => res.json({ status: 'ok', keys: Object.keys(KEYS).length }));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
