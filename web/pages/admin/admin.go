package admin

import (
	"fmt"
	"net/http"
	"runtime"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	// Sub-user → show user account info panel at /ad
	if user := snd.GetSessionUser(r); user != nil {
		renderUserInfoPage(w, r, user)
		return
	}

	snd.UpdateStats()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	snd.GlobalStatsMu.Lock()
	totalFiles := snd.GlobalStats.TotalFiles
	totalSize := snd.GlobalStats.TotalSize
	totalRequests := snd.GlobalStats.TotalRequests
	snd.GlobalStatsMu.Unlock()

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - ` + snd.Cfg.SiteName + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #fafafa; color: #1a1a1a; }
        .container { max-width: 1200px; margin: 0 auto; padding: 32px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid #e0e0e0; }
        h1 { font-size: 24px; font-weight: 500; }
        .header-actions { display: flex; gap: 8px; }
        .btn { padding: 8px 16px; background: #1a1a1a; color: white; text-decoration: none; border: none; cursor: pointer; font-size: 14px; border-radius: 4px; }
        .btn:hover { background: #333; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: white; padding: 24px; border: 1px solid #e0e0e0; border-radius: 4px; }
        .stat-label { font-size: 13px; color: #666; margin-bottom: 8px; }
        .stat-value { font-size: 32px; font-weight: 500; }
        .card { background: white; padding: 24px; border: 1px solid #e0e0e0; margin-bottom: 16px; border-radius: 4px; }
        .card h2 { font-size: 18px; font-weight: 500; margin-bottom: 16px; }
        .info-row { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: #666; }
        .info-value { font-weight: 500; }
        .bench-grid { display: grid; gap: 10px; }
        .bench-btn { width: 100%; padding: 12px; background: white; border: 1px solid #e0e0e0; cursor: pointer; font-size: 14px; text-align: left; border-radius: 4px; }
        .bench-btn:hover { background: #f5f5f5; }
        .bench-results { margin-top: 16px; padding: 16px; background: #f5f5f5; border: 1px solid #e0e0e0; font-family: monospace; font-size: 13px; white-space: pre-wrap; display: none; border-radius: 4px; }
        .session-item { display: flex; justify-content: space-between; align-items: center; padding: 16px; border-bottom: 1px solid #f0f0f0; }
        .session-item:last-child { border-bottom: none; }
        .session-info { flex: 1; }
        .session-badge { display: inline-block; padding: 2px 8px; background: #e8f5e9; color: #2e7d32; font-size: 11px; border-radius: 10px; margin-left: 8px; }
        .kick-btn { padding: 6px 14px; background: #d32f2f; color: white; border: none; cursor: pointer; font-size: 12px; border-radius: 4px; flex-shrink: 0; }
        .kick-btn:hover { background: #b71c1c; }
        .kick-btn:disabled { background: #ccc; cursor: not-allowed; }
        .logs-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .logs-table th { padding: 8px 12px; background: #f5f5f5; text-align: left; font-weight: 500; border-bottom: 1px solid #e0e0e0; }
        .logs-table td { padding: 8px 12px; border-bottom: 1px solid #f5f5f5; font-family: monospace; }
        .logs-table tr:last-child td { border-bottom: none; }
        .logs-wrapper { max-height: 360px; overflow-y: auto; }
        .tabs { display: flex; gap: 0; border-bottom: 1px solid #e0e0e0; flex-wrap: wrap; }
        .tab { padding: 12px 20px; cursor: pointer; font-size: 14px; color: #666; border-bottom: 2px solid transparent; margin-bottom: -1px; }
        .tab.active { color: #1a1a1a; border-bottom-color: #1a1a1a; font-weight: 500; }
        .tab:hover { color: #1a1a1a; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .toggle-switch { position: relative; display: inline-block; width: 44px; height: 24px; }
        .toggle-switch input { opacity: 0; width: 0; height: 0; }
        .toggle-slider { position: absolute; cursor: pointer; inset: 0; background: #ccc; border-radius: 24px; transition: 0.3s; }
        .toggle-slider:before { content: ""; position: absolute; height: 18px; width: 18px; left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.3s; }
        input:checked + .toggle-slider { background: #4caf50; }
        input:checked + .toggle-slider:before { transform: translateX(20px); }
        @media (max-width: 768px) { .container { padding: 20px 16px; } .header { flex-wrap: wrap; gap: 12px; } .stat-value { font-size: 26px; } }

        /* Liquid Glass overrides for admin */
        body.th-liquid .card, body.th-liquid .stat-card {
            background: rgba(255,255,255,0.08) !important;
            backdrop-filter: blur(24px) saturate(180%) !important;
            -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
            border-color: rgba(255,255,255,0.18) !important;
            box-shadow: 0 8px 32px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.3) !important;
        }
        body.th-liquid .header { background: rgba(255,255,255,0.07) !important; backdrop-filter: blur(20px) !important; border-color: rgba(255,255,255,0.14) !important; }
        body.th-liquid .info-label, body.th-liquid .stat-label { color: rgba(255,255,255,0.65) !important; }
        body.th-liquid .stat-value, body.th-liquid h1, body.th-liquid h2 { color: rgba(255,255,255,0.92) !important; }
        body.th-liquid input, body.th-liquid select, body.th-liquid textarea { background: rgba(255,255,255,0.10) !important; border-color: rgba(255,255,255,0.2) !important; color: #fff !important; }
        body.th-liquid .bench-btn, body.th-liquid .bench-results { background: rgba(255,255,255,0.08) !important; border-color: rgba(255,255,255,0.15) !important; color: rgba(255,255,255,0.85) !important; }
        body.th-liquid .logs-table th { background: rgba(255,255,255,0.12) !important; color: rgba(255,255,255,0.85) !important; }
        body.th-liquid .logs-table td { color: rgba(255,255,255,0.75) !important; }
        body.th-liquid .tab { color: rgba(255,255,255,0.55) !important; }
        body.th-liquid .tab.active { color: rgba(255,255,255,0.95) !important; border-bottom-color: rgba(255,255,255,0.7) !important; }
        body.th-liquid:not(.th-rainbow):not(.th-dark) { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%) !important; }
        body.th-dark .card, body.th-dark .stat-card { background: #181818 !important; border-color: #2a2a2a !important; }
        body.th-dark .header { background: #111 !important; border-color: #2a2a2a !important; }
        body.th-dark .tab { color: #888 !important; }
        body.th-dark .tab.active { color: #ddd !important; border-bottom-color: #ddd !important; }
        body.th-dark input, body.th-dark select, body.th-dark textarea { background: #111 !important; border-color: #333 !important; color: #ddd !important; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Admin Dashboard</h1>
        <div class="header-actions">
            <a href="/" class="btn">Home</a>
            <a href="/logout" class="btn">Logout</a>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card"><div class="stat-label">Total Files</div><div class="stat-value">` + fmt.Sprintf("%d", totalFiles) + `</div></div>
        <div class="stat-card"><div class="stat-label">Storage Used</div><div class="stat-value">` + snd.FormatBytes(totalSize) + `</div></div>
        <div class="stat-card"><div class="stat-label">Total Requests</div><div class="stat-value">` + fmt.Sprintf("%d", totalRequests) + `</div></div>
    </div>

    <div class="card">
        <div class="tabs">
            <div class="tab active" data-tab="system" onclick="switchTab('system')">System</div>
            <div class="tab" data-tab="users" onclick="switchTab('users')">Users</div>
            <div class="tab" data-tab="sessions" onclick="switchTab('sessions')">Sessions</div>
            <div class="tab" data-tab="logs" onclick="switchTab('logs')">Access Logs</div>
            <div class="tab" data-tab="benchmark" onclick="switchTab('benchmark')">Benchmark</div>
            <div class="tab" data-tab="nodes" onclick="switchTab('nodes')">Storage Nodes</div>
            <div class="tab" data-tab="ddos" onclick="switchTab('ddos')">Anti-DDoS</div>
            <div class="tab" data-tab="settings" onclick="switchTab('settings')">Settings</div>
        </div>

        <!-- System Tab -->
        <div id="tab-system" class="tab-content active" style="margin-top:16px;">
            <div class="info-row"><span class="info-label">OS</span><span class="info-value">` + runtime.GOOS + `</span></div>
            <div class="info-row"><span class="info-label">Architecture</span><span class="info-value">` + runtime.GOARCH + `</span></div>
            <div class="info-row"><span class="info-label">Go Version</span><span class="info-value">` + runtime.Version() + `</span></div>
            <div class="info-row"><span class="info-label">Goroutines</span><span class="info-value">` + fmt.Sprintf("%d", runtime.NumGoroutine()) + `</span></div>
            <div class="info-row"><span class="info-label">Memory Alloc</span><span class="info-value">` + fmt.Sprintf("%.2f MB", float64(m.Alloc)/1048576) + `</span></div>
            <div class="info-row"><span class="info-label">GC Runs</span><span class="info-value">` + fmt.Sprintf("%d", m.NumGC) + `</span></div>
            <div class="info-row"><span class="info-label">Site Name</span><span class="info-value">` + snd.Cfg.SiteName + `</span></div>
            <div class="info-row"><span class="info-label">Version</span><span class="info-value">` + snd.VERSION + `</span></div>
        </div>

        <!-- Users Tab -->
        <div id="tab-users" class="tab-content" style="margin-top:16px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h3 style="font-size:15px;font-weight:500;">User Accounts</h3>
                <button class="btn" onclick="openCreateUserModal()">+ Create User</button>
            </div>
            <div id="usersTableContainer">
                <table class="logs-table" style="width:100%">
                    <thead><tr><th>Username</th><th>Email</th><th>Storage Used / Limit</th><th>Requests</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody id="usersTableBody"><tr><td colspan="6" style="padding:16px;color:#999;">Loading...</td></tr></tbody>
                </table>
            </div>
        </div>

        <!-- Sessions Tab -->
        <div id="tab-sessions" class="tab-content" style="margin-top:16px;">
            <div class="sessions-list" id="sessionsList">Loading sessions...</div>
        </div>

        <!-- Logs Tab -->
        <div id="tab-logs" class="tab-content" style="margin-top:16px;">
            <div class="logs-wrapper">
                <table class="logs-table">
                    <thead><tr><th>Time</th><th>IP</th><th>Action</th><th>Path</th></tr></thead>
                    <tbody id="logsTableBody"><tr><td colspan="4" style="padding:16px;color:#999;">Loading...</td></tr></tbody>
                </table>
            </div>
        </div>

        <!-- Benchmark Tab -->
        <div id="tab-benchmark" class="tab-content" style="margin-top:16px;">
            <div class="bench-grid">
                <button class="bench-btn" onclick="runPingTest()">▶ Test Ping</button>
                <button class="bench-btn" onclick="runDownloadTest()">▶ Test Download Speed</button>
                <button class="bench-btn" onclick="runUploadTest()">▶ Test Upload Speed</button>
                <button class="bench-btn" onclick="runDiskTest()">▶ Test Disk Speed</button>
                <button class="bench-btn" onclick="runCPUTest()">▶ Test CPU</button>
                <button class="bench-btn" onclick="runMemoryTest()">▶ Test Memory</button>
            </div>
            <div class="bench-results" id="benchmarkResults"></div>
        </div>

        <!-- Storage Nodes Tab -->
        <div id="tab-nodes" class="tab-content" style="margin-top:16px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <h3 style="font-size:15px;font-weight:500;">Storage Node Management</h3>
                <button class="btn" onclick="openNodeModal()">+ Add Node</button>
            </div>
            <div id="nodesContainer"><div style="color:#999;padding:16px;">Loading...</div></div>
        </div>

        <!-- Anti-DDoS Tab -->
        <div id="tab-ddos" class="tab-content" style="margin-top:16px;">
            <div id="ddosContent"><div style="color:#999;padding:16px;">Loading...</div></div>
        </div>

        <!-- Settings Tab -->
        <div id="tab-settings" class="tab-content" style="margin-top:16px;">
            <div id="adminSettingsContent">
                <div class="info-row">
                    <span class="info-label">Background URL</span>
                    <input type="text" id="as-bg" placeholder="https://..." style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;width:300px;">
                </div>
                <div class="info-row">
                    <span class="info-label">Background Music URL</span>
                    <input type="text" id="as-music" placeholder="https://..." style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;width:300px;">
                </div>
                <div class="info-row">
                    <span class="info-label">Language</span>
                    <select id="as-lang" style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;">
                        <option value="en">English</option>
                        <option value="vi">Tiếng Việt</option>
                        <option value="zh">中文</option>
                        <option value="ja">日本語</option>
                    </select>
                </div>
                <div class="info-row">
                    <span class="info-label">Allow User Theme</span>
                    <label class="toggle-switch"><input type="checkbox" id="as-allow-theme"><span class="toggle-slider"></span></label>
                </div>
                <div class="info-row">
                    <span class="info-label">Show Direct Links</span>
                    <label class="toggle-switch"><input type="checkbox" id="as-direct-links"><span class="toggle-slider"></span></label>
                </div>
                <div style="margin-top:20px;">
                    <button class="btn" onclick="saveAdminSettings()">Save Settings</button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- User Modal -->
<div id="userModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:200;align-items:center;justify-content:center;">
    <div style="background:white;padding:32px;min-width:400px;max-width:520px;width:100%;max-height:90vh;overflow-y:auto;border-radius:8px;">
        <h2 id="userModalTitle" style="font-size:18px;font-weight:500;margin-bottom:20px;">Create User</h2>
        <input type="hidden" id="userUUID">
        <div style="margin-bottom:14px"><label style="display:block;font-size:13px;color:#555;margin-bottom:5px">Username *</label><input type="text" id="userUsername" style="width:100%;padding:9px 12px;border:1px solid #d0d0d0;font-size:14px;border-radius:4px;" placeholder="username"></div>
        <div style="margin-bottom:14px"><label style="display:block;font-size:13px;color:#555;margin-bottom:5px">Email</label><input type="email" id="userEmail" style="width:100%;padding:9px 12px;border:1px solid #d0d0d0;font-size:14px;border-radius:4px;" placeholder="user@example.com"></div>
        <div style="margin-bottom:14px"><label id="userPasswordLabel" style="display:block;font-size:13px;color:#555;margin-bottom:5px">Password *</label><input type="password" id="userPassword" style="width:100%;padding:9px 12px;border:1px solid #d0d0d0;font-size:14px;border-radius:4px;" placeholder="••••••••"></div>
        <div style="margin-bottom:14px">
            <label style="display:block;font-size:13px;color:#555;margin-bottom:5px">Storage Limit</label>
            <div style="display:flex;gap:8px;align-items:center">
                <input type="number" id="userStorageValue" min="0" step="0.1" style="flex:1;padding:9px 12px;border:1px solid #d0d0d0;font-size:14px;border-radius:4px;" placeholder="Unlimited" oninput="updateStorageLimitInput()">
                <select id="userStorageUnit" style="padding:9px 10px;border:1px solid #d0d0d0;font-size:14px;background:white;border-radius:4px;" onchange="updateStorageLimitInput()">
                    <option value="GB">GB</option><option value="MB">MB</option><option value="KB">KB</option>
                </select>
            </div>
            <input type="hidden" id="userStorageLimit" value="-1">
            <div style="font-size:11px;color:#888;margin-top:4px">Leave blank for unlimited</div>
        </div>
        <div style="margin-bottom:14px;display:flex;align-items:center;gap:10px"><input type="checkbox" id="userActive" checked><label for="userActive" style="font-size:14px;cursor:pointer">Account Active</label></div>
        <div style="margin-bottom:14px;display:flex;align-items:center;gap:10px"><input type="checkbox" id="userIsAdmin"><label for="userIsAdmin" style="font-size:14px;cursor:pointer">Grant Admin Privileges</label></div>
        <div id="regenTokenRow" style="display:none;margin-bottom:14px;align-items:center;gap:10px"><input type="checkbox" id="regenToken"><label for="regenToken" style="font-size:14px;cursor:pointer">Regenerate API Token</label></div>
        <div id="userTokenResult" style="display:none;background:#e8f5e9;border:1px solid #a5d6a7;padding:12px;margin-bottom:14px;border-radius:4px;">
            <div style="font-size:12px;color:#2e7d32;margin-bottom:6px;font-weight:500">New API Token:</div>
            <div id="userTokenValue" style="font-family:monospace;font-size:12px;word-break:break-all"></div>
            <button onclick="navigator.clipboard.writeText(document.getElementById('userTokenValue').textContent)" style="margin-top:8px;padding:4px 10px;background:#2e7d32;color:white;border:none;cursor:pointer;font-size:12px;border-radius:4px;">Copy Token</button>
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:20px;">
            <button onclick="closeUserModal()" style="padding:9px 18px;background:none;border:1px solid #ddd;cursor:pointer;font-size:14px;border-radius:4px;">Cancel</button>
            <button onclick="saveUser()" style="padding:9px 18px;background:#1a1a1a;color:white;border:none;cursor:pointer;font-size:14px;border-radius:4px;">Save</button>
        </div>
    </div>
</div>

<!-- Node Modal -->
<div id="nodeModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:200;align-items:center;justify-content:center;">
    <div style="background:#fff;border-radius:8px;padding:28px;width:440px;max-width:92vw;max-height:80vh;overflow-y:auto;">
        <h2 id="nodeModalTitle" style="font-size:18px;font-weight:500;margin-bottom:20px;">Add Storage Node</h2>
        <div style="margin-bottom:14px;"><label style="font-size:13px;color:#666;">Name *</label><input type="text" id="nodeName" style="width:100%;padding:9px 12px;border:1px solid #d0d0d0;font-size:14px;margin-top:4px;border-radius:4px;" placeholder="Node name"></div>
        <div id="nodeIPRow" style="margin-bottom:14px;"><label style="font-size:13px;color:#666;">IP Address *</label><input type="text" id="nodeIP" style="width:100%;padding:9px 12px;border:1px solid #d0d0d0;font-size:14px;margin-top:4px;border-radius:4px;" placeholder="192.168.1.100"></div>
        <div style="margin-bottom:14px;"><label style="font-size:13px;color:#666;">Port</label><input type="text" id="nodePort" style="width:100%;padding:9px 12px;border:1px solid #d0d0d0;font-size:14px;margin-top:4px;border-radius:4px;" placeholder="8080"></div>
        <div style="margin-bottom:14px;"><label style="font-size:13px;color:#666;">Notes</label><textarea id="nodeNotes" style="width:100%;padding:9px 12px;border:1px solid #d0d0d0;font-size:14px;margin-top:4px;height:60px;resize:vertical;border-radius:4px;"></textarea></div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:20px;">
            <button onclick="closeNodeModal()" style="padding:9px 18px;background:none;border:1px solid #ddd;cursor:pointer;border-radius:4px;">Cancel</button>
            <button onclick="saveNode()" style="padding:9px 18px;background:#1a1a1a;color:white;border:none;cursor:pointer;border-radius:4px;">Save</button>
        </div>
    </div>
</div>

<script>
// ─── Tab Switching ────────────────────────────────────────────────────────────
function switchTab(name) {
    document.querySelectorAll('.tabs .tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    const target = document.getElementById('tab-' + name);
    if (target) target.classList.add('active');
    if (name === 'users') loadUsers();
    if (name === 'sessions') loadSessions();
    if (name === 'logs') loadLogs();
    if (name === 'nodes') loadNodes();
    if (name === 'ddos') loadDDoS();
    if (name === 'settings') loadAdminSettings();
}

// ─── User Management ──────────────────────────────────────────────────────────
let editingUser = null;
const userDataMap = {};

async function loadUsers() {
    try {
        const res = await fetch('/admin/users');
        const users = await res.json();
        const tbody = document.getElementById('usersTableBody');
        if (!users || !users.length) {
            tbody.innerHTML = '<tr><td colspan="6" style="padding:16px;color:#999;">No users yet.</td></tr>';
            return;
        }
        users.forEach(u => { userDataMap[u.uuid] = u; });
        tbody.innerHTML = users.map(u => {
            const used = formatBytes(u.used_storage);
            const limit = u.storage_limit <= 0 ? 'Unlimited' : formatBytes(u.storage_limit);
            const status = u.is_active ? '<span style="color:#2e7d32;font-weight:500">Active</span>' : '<span style="color:#c62828;font-weight:500">Disabled</span>';
            const adminBadge = u.is_admin ? ' <span style="background:#e3f2fd;color:#1565c0;font-size:11px;padding:2px 6px;border-radius:10px;font-weight:500">ADMIN</span>' : '';
            return '<tr>' +
                '<td><strong>' + escapeHtml(u.username) + '</strong>' + adminBadge + '<br><small style="color:#888;font-family:monospace">' + u.uuid + '</small></td>' +
                '<td>' + escapeHtml(u.email || '—') + '</td>' +
                '<td>' + used + ' / ' + limit + '</td>' +
                '<td>' + u.request_count + '</td>' +
                '<td>' + status + '</td>' +
                '<td style="display:flex;gap:4px;flex-wrap:wrap">' +
                '<button class="kick-btn edit-user-btn" style="background:#1a1a1a" data-uuid="' + u.uuid + '">Edit</button>' +
                '<button class="kick-btn" onclick="confirmDeleteUser(\'' + u.uuid + '\',\'' + escapeHtml(u.username) + '\')">Delete</button>' +
                '</td></tr>';
        }).join('');
        tbody.querySelectorAll('.edit-user-btn').forEach(btn => {
            btn.addEventListener('click', function() { openEditUserModal(this.dataset.uuid); });
        });
    } catch(e) {
        document.getElementById('usersTableBody').innerHTML = '<tr><td colspan="6" style="color:#d32f2f;padding:16px">Failed: ' + (e.message||'') + '</td></tr>';
    }
}

function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const k = 1024, sizes = ['B','KB','MB','GB','TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k,i)).toFixed(2)) + ' ' + sizes[i];
}

function bytesToUnit(bytes) {
    if (!bytes || bytes <= 0) return {val: -1, unit: 'GB'};
    if (bytes >= 1073741824) return {val: (bytes/1073741824), unit: 'GB'};
    if (bytes >= 1048576) return {val: (bytes/1048576), unit: 'MB'};
    return {val: (bytes/1024), unit: 'KB'};
}

function updateStorageLimitInput() {
    const val = parseFloat(document.getElementById('userStorageValue').value);
    const unit = document.getElementById('userStorageUnit').value;
    let bytes = -1;
    if (!isNaN(val) && val > 0) {
        const mult = unit === 'GB' ? 1073741824 : unit === 'MB' ? 1048576 : 1024;
        bytes = Math.round(val * mult);
    }
    document.getElementById('userStorageLimit').value = bytes;
}

function openCreateUserModal() {
    editingUser = null;
    document.getElementById('userModalTitle').textContent = 'Create User';
    ['userUUID','userUsername','userEmail','userPassword'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('userPasswordLabel').textContent = 'Password *';
    document.getElementById('userStorageValue').value = '';
    document.getElementById('userStorageUnit').value = 'GB';
    document.getElementById('userStorageLimit').value = '-1';
    document.getElementById('userActive').checked = true;
    document.getElementById('userIsAdmin').checked = false;
    document.getElementById('regenTokenRow').style.display = 'none';
    document.getElementById('userTokenResult').style.display = 'none';
    document.getElementById('userModal').style.display = 'flex';
}

function openEditUserModal(uuid) {
    const u = userDataMap[uuid];
    if (!u) { alert('User not found. Refresh.'); return; }
    editingUser = u;
    document.getElementById('userModalTitle').textContent = 'Edit User: ' + u.username;
    document.getElementById('userUUID').value = u.uuid;
    document.getElementById('userUsername').value = u.username;
    document.getElementById('userEmail').value = u.email || '';
    document.getElementById('userPassword').value = '';
    document.getElementById('userPasswordLabel').textContent = 'New Password (blank = keep)';
    const {val, unit} = bytesToUnit(u.storage_limit);
    document.getElementById('userStorageValue').value = val > 0 ? val : '';
    document.getElementById('userStorageUnit').value = unit;
    updateStorageLimitInput();
    document.getElementById('userActive').checked = u.is_active;
    document.getElementById('userIsAdmin').checked = !!u.is_admin;
    document.getElementById('regenTokenRow').style.display = 'flex';
    document.getElementById('regenToken').checked = false;
    document.getElementById('userTokenResult').style.display = 'none';
    document.getElementById('userModal').style.display = 'flex';
}

async function saveUser() {
    const uuid = document.getElementById('userUUID').value;
    const body = {
        uuid, username: document.getElementById('userUsername').value.trim(),
        email: document.getElementById('userEmail').value.trim(),
        password: document.getElementById('userPassword').value,
        storage_limit: parseInt(document.getElementById('userStorageLimit').value) || -1,
        is_active: document.getElementById('userActive').checked,
        is_admin: document.getElementById('userIsAdmin').checked,
        regen_token: document.getElementById('regenToken') && document.getElementById('regenToken').checked,
    };
    if (!body.username) { showConfirm('Username required', null, null, true); return; }
    const url = uuid ? '/admin/users/update' : '/admin/users/create';
    if (!uuid && !body.password) { showConfirm('Password required for new users', null, null, true); return; }
    if (uuid) {
        showConfirm('Save changes to "' + body.username + '"?', async () => {
            await doSaveUser(url, body);
        });
        return;
    }
    await doSaveUser(url, body);
}

async function doSaveUser(url, body) {
    const res = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const data = await res.json();
    if (!data.success) { showConfirm(data.message || 'Failed to save', null, null, true); return; }
    if (data.api_token) {
        document.getElementById('userTokenResult').style.display = 'block';
        document.getElementById('userTokenValue').textContent = data.api_token;
    } else { loadUsers(); closeUserModal(); }
    loadUsers();
}

function closeUserModal() { document.getElementById('userModal').style.display = 'none'; }

async function confirmDeleteUser(uuid, username) {
    showConfirm('Delete user "' + username + '"? This cannot be undone.', async () => {
        showConfirm('Also delete all files of "' + username + '"?', 
            async () => doDeleteUser(uuid, true),
            async () => doDeleteUser(uuid, false)
        );
    });
}
async function doDeleteUser(uuid, deleteFiles) {
    const res = await fetch('/admin/users/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({uuid, delete_files: deleteFiles}) });
    const data = await res.json();
    if (data.success) { loadUsers(); showToast('User deleted'); }
    else showToast('Failed to delete user');
}

// ─── Sessions ─────────────────────────────────────────────────────────────────
async function loadSessions() {
    try {
        const res = await fetch('/sessions');
        const sessions = await res.json();
        const list = document.getElementById('sessionsList');
        if (!sessions || !sessions.length) { list.innerHTML = '<div style="padding:16px;color:#999;">No active sessions</div>'; return; }
        list.innerHTML = sessions.map(s =>
            '<div class="session-item">' +
            '<div class="session-info"><strong>' + escapeHtml(s.ip) + '</strong>' +
            (s.username ? ' <span style="color:#0066cc;font-size:11px;background:#e3f2fd;padding:2px 6px;border-radius:10px;">' + escapeHtml(s.username) + '</span>' : '') +
            (s.is_current ? '<span class="session-badge">Current</span>' : '') +
            '<div style="color:#666;margin-top:4px;">' + escapeHtml(s.os||'') + ' / ' + escapeHtml(s.browser||'') + '</div>' +
            '<div style="color:#999;font-size:11px;margin-top:2px;">Login: ' + s.login_time + ' | Last: ' + s.last_access + '</div></div>' +
            '<button class="kick-btn" onclick="kickSession(\'' + s.session_id.replace(/'/g,"\\'") + '\',this)"' + (s.is_current ? ' disabled' : '') + '>Kick</button>' +
            '</div>'
        ).join('');
    } catch { document.getElementById('sessionsList').innerHTML = '<div style="padding:16px;color:#d32f2f;">Failed to load sessions</div>'; }
}

async function kickSession(sessionId, btn) {
    btn.disabled = true; btn.textContent = '...';
    try {
        await fetch('/kick-session', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({session_id: sessionId}) });
        btn.closest('.session-item').remove();
    } catch { btn.disabled = false; btn.textContent = 'Kick'; }
}

// ─── Logs ─────────────────────────────────────────────────────────────────────
async function loadLogs() {
    try {
        const res = await fetch('/access-logs');
        const logs = await res.json();
        const tbody = document.getElementById('logsTableBody');
        if (!logs || !logs.length) { tbody.innerHTML = '<tr><td colspan="4" style="padding:16px;color:#999;">No logs</td></tr>'; return; }
        tbody.innerHTML = [...logs].reverse().map(l =>
            '<tr><td>' + new Date(l.timestamp).toLocaleString() + '</td><td>' + escapeHtml(l.ip) + '</td><td>' + escapeHtml(l.action) + '</td><td>' + escapeHtml(l.path) + '</td></tr>'
        ).join('');
    } catch { document.getElementById('logsTableBody').innerHTML = '<tr><td colspan="4" style="padding:16px;color:#d32f2f;">Failed to load logs</td></tr>'; }
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────
function showResult(text) { const r = document.getElementById('benchmarkResults'); r.style.display = 'block'; r.textContent = text; }

async function runPingTest() {
    showResult('Running ping test...');
    const pings = [];
    for (let i = 0; i < 10; i++) { const s = performance.now(); await fetch('/benchmark/ping'); pings.push(performance.now() - s); }
    const avg = pings.reduce((a,b)=>a+b,0)/pings.length;
    showResult('Ping Test\nAvg: ' + avg.toFixed(2) + ' ms\nMin: ' + Math.min(...pings).toFixed(2) + ' ms\nMax: ' + Math.max(...pings).toFixed(2) + ' ms');
}
async function runDownloadTest() {
    showResult('Testing download...'); const size=10;
    const s=performance.now(); const r=await fetch('/benchmark/download?size='+size); await r.blob();
    const dur=(performance.now()-s)/1000;
    showResult('Download Test\nSize: '+size+' MB\nTime: '+dur.toFixed(2)+' s\nSpeed: '+(size/dur).toFixed(2)+' MB/s');
}
async function runUploadTest() {
    showResult('Testing upload...'); const size=10*1024*1024; const data=new Uint8Array(size);
    const s=performance.now(); await fetch('/benchmark/upload',{method:'POST',body:data});
    const dur=(performance.now()-s)/1000;
    showResult('Upload Test\nSize: 10 MB\nTime: '+dur.toFixed(2)+' s\nSpeed: '+(size/1024/1024/dur).toFixed(2)+' MB/s');
}
async function runDiskTest() { showResult('Testing disk...'); const r=await fetch('/benchmark/disk'); const d=await r.json(); showResult('Disk Test\nWrite: '+d.write_speed.toFixed(2)+' MB/s\nRead: '+d.read_speed.toFixed(2)+' MB/s'); }
async function runCPUTest() { showResult('Testing CPU...'); const r=await fetch('/benchmark/cpu'); const d=await r.json(); showResult('CPU Test\nIterations: '+d.iterations.toLocaleString()+'\nTime: '+d.duration_ms+' ms'); }
async function runMemoryTest() { showResult('Testing memory...'); const r=await fetch('/benchmark/memory'); const d=await r.json(); showResult('Memory\nAlloc: '+d.alloc_mb+' MB\nSys: '+d.sys_mb+' MB\nGoroutines: '+d.goroutines+'\nGC Runs: '+d.num_gc); }

// ─── Storage Node Management ──────────────────────────────────────────────────
let nodeModalMode = 'create', editingNodeId = null;

async function loadNodes() {
    const c = document.getElementById('nodesContainer');
    try {
        const res = await fetch('/admin/nodes');
        const nodes = await res.json();
        if (!nodes || !nodes.length) { c.innerHTML = '<div style="color:#999;padding:16px;">No nodes configured.</div>'; return; }
        let html = '<table class="logs-table" style="width:100%"><thead><tr><th>Name</th><th>IP:Port</th><th>Primary</th><th>Backup</th><th>Actions</th></tr></thead><tbody>';
        nodes.forEach(n => {
            html += '<tr>';
            html += '<td><strong>' + escapeHtml(n.name) + '</strong>' + (n.is_default ? ' <span style="background:#e8f5e9;color:#2e7d32;font-size:11px;padding:2px 6px;border-radius:10px;">Default</span>' : '') + '</td>';
            html += '<td style="font-family:monospace;">' + escapeHtml(n.ip) + ':' + escapeHtml(n.port||'') + '</td>';
            html += '<td><label class="toggle-switch"><input type="checkbox"' + (n.is_primary?' checked':'') + ' onchange="setPrimaryNode(\'' + n.id + '\',this.checked)"><span class="toggle-slider"></span></label></td>';
            html += '<td><label class="toggle-switch"><input type="checkbox"' + (n.backup_mode?' checked':'') + ' onchange="setNodeBackup(\'' + n.id + '\',this.checked)"><span class="toggle-slider"></span></label></td>';
            html += '<td><button class="btn" style="padding:4px 10px;font-size:12px;margin-right:4px;" onclick="openNodeModal(\'' + n.id + '\')">Edit</button>';
            if (!n.is_default) html += '<button class="btn" style="padding:4px 10px;font-size:12px;background:#d32f2f;" onclick="deleteNode(\'' + n.id + '\')">Delete</button>';
            html += '</td></tr>';
        });
        html += '</tbody></table>';
        c.innerHTML = html;
    } catch(e) { c.innerHTML = '<div style="color:#d32f2f;padding:16px;">Failed to load nodes: ' + e.message + '</div>'; }
}

function openNodeModal(id) {
    editingNodeId = id || null;
    nodeModalMode = id ? 'edit' : 'create';
    document.getElementById('nodeModalTitle').textContent = id ? 'Edit Node' : 'Add Storage Node';
    ['nodeName','nodeIP','nodePort','nodeNotes'].forEach(i => document.getElementById(i).value = '');
    if (id) {
        fetch('/admin/nodes').then(r=>r.json()).then(nodes => {
            const n = nodes.find(x=>x.id===id);
            if (!n) return;
            document.getElementById('nodeName').value = n.name;
            document.getElementById('nodeIP').value = n.ip;
            document.getElementById('nodePort').value = n.port||'';
            document.getElementById('nodeNotes').value = n.notes||'';
            document.getElementById('nodeIPRow').style.display = n.is_default ? 'none' : '';
        });
    } else { document.getElementById('nodeIPRow').style.display = ''; }
    document.getElementById('nodeModal').style.display = 'flex';
}

function closeNodeModal() { document.getElementById('nodeModal').style.display = 'none'; }

async function saveNode() {
    const body = { name: document.getElementById('nodeName').value.trim(), ip: document.getElementById('nodeIP').value.trim(), port: document.getElementById('nodePort').value.trim(), notes: document.getElementById('nodeNotes').value.trim() };
    const url = editingNodeId ? '/admin/nodes/update' : '/admin/nodes/create';
    if (editingNodeId) body.id = editingNodeId;
    const res = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    if (res.ok) { closeNodeModal(); loadNodes(); showToast('Node saved'); }
    else showToast('Failed to save node');
}

async function deleteNode(id) {
    if (!confirm('Delete this node?')) return;
    await fetch('/admin/nodes/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id}) });
    loadNodes();
}

async function setPrimaryNode(id, isPrimary) {
    await fetch('/admin/nodes/set-primary', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: isPrimary ? id : ''}) });
    loadNodes();
    showToast(isPrimary ? 'Primary node set' : 'Primary cleared');
}

async function setNodeBackup(id, backup) {
    const res = await fetch('/admin/nodes');
    const nodes = await res.json();
    const n = nodes.find(x=>x.id===id);
    if (!n) return;
    n.backup_mode = backup;
    await fetch('/admin/nodes/update', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(n) });
}

// ─── Anti-DDoS ────────────────────────────────────────────────────────────────
async function loadDDoS() {
    const c = document.getElementById('ddosContent');
    try {
        const res = await fetch('/admin/ddos/stats');
        const data = await res.json();
        const cfg = data.config || {};
        const bans = data.bans || [];
        const traffic = data.traffic || [];

        let html = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">';
        html += '<div style="border:1px solid #e0e0e0;border-radius:4px;padding:16px;">';
        html += '<h4 style="margin-bottom:12px;font-size:14px;font-weight:500;">Configuration</h4>';
        html += '<div class="info-row"><span class="info-label">Enabled</span><label class="toggle-switch"><input type="checkbox" id="ddos-enabled"' + (cfg.enabled?' checked':'') + '><span class="toggle-slider"></span></label></div>';
        html += '<div class="info-row"><span class="info-label">Rate Window (sec)</span><input type="number" id="ddos-window" value="' + (cfg.rate_window_sec||60) + '" style="width:80px;padding:4px 8px;border:1px solid #d0d0d0;border-radius:4px;"></div>';
        html += '<div class="info-row"><span class="info-label">Max Req/Window</span><input type="number" id="ddos-max" value="' + (cfg.max_requests_per_window||300) + '" style="width:80px;padding:4px 8px;border:1px solid #d0d0d0;border-radius:4px;"></div>';
        html += '<div class="info-row"><span class="info-label">Ban Duration (min)</span><input type="number" id="ddos-ban-dur" value="' + (cfg.ban_duration_min||60) + '" style="width:80px;padding:4px 8px;border:1px solid #d0d0d0;border-radius:4px;"></div>';
        html += '<div style="margin-top:12px;"><button class="btn" onclick="saveDDoSConfig()">Save Config</button></div>';
        html += '</div>';

        html += '<div style="border:1px solid #e0e0e0;border-radius:4px;padding:16px;">';
        html += '<h4 style="margin-bottom:12px;font-size:14px;font-weight:500;">Banned IPs (' + bans.length + ')</h4>';
        if (bans.length) {
            html += '<div style="max-height:200px;overflow-y:auto;">';
            bans.forEach(b => {
                html += '<div class="info-row"><span class="info-label" style="font-family:monospace;">' + escapeHtml(b.ip) + '</span>';
                html += '<div style="display:flex;gap:6px;align-items:center;"><span style="font-size:11px;color:#999;">' + new Date(b.expires_at).toLocaleString() + '</span>';
                html += '<button class="btn" style="padding:3px 8px;font-size:11px;" onclick="unbanIP(\'' + escapeHtml(b.ip) + '\')">Unban</button></div></div>';
            });
            html += '</div>';
        } else { html += '<div style="color:#999;font-size:13px;">No banned IPs</div>'; }
        html += '<div style="margin-top:12px;display:flex;gap:8px;">';
        html += '<input type="text" id="manualBanIP" placeholder="IP to ban" style="flex:1;padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;font-size:13px;">';
        html += '<button class="btn" style="background:#d32f2f;" onclick="manualBan()">Ban IP</button></div>';
        html += '</div></div>';

        html += '<div style="border:1px solid #e0e0e0;border-radius:4px;padding:16px;margin-top:16px;">';
        html += '<h4 style="margin-bottom:12px;font-size:14px;font-weight:500;">Traffic (14 days)</h4>';
        html += '<canvas id="ddosChart" width="600" height="160" style="width:100%;height:160px;"></canvas>';
        html += '</div>';

        c.innerHTML = html;
        // FIX: setTimeout(80) is unreliable when the tab switches from display:none to display:block.
        // The browser needs two animation frames to perform layout and paint before offsetWidth is valid.
        const _drawChart = () => drawDDoSChart(traffic);
        requestAnimationFrame(() => requestAnimationFrame(_drawChart));
        // Re-draw on window resize
        window.removeEventListener('resize', window._ddosChartResize);
        window._ddosChartResize = _drawChart;
        window.addEventListener('resize', window._ddosChartResize);
    } catch(e) { c.innerHTML = '<div style="color:#d32f2f;padding:16px;">Failed to load DDoS data: ' + e.message + '</div>'; }
}

function drawDDoSChart(traffic) {
    const canvas = document.getElementById('ddosChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.offsetWidth || canvas.parentElement && canvas.parentElement.offsetWidth || 600;
    const H = 160;
    canvas.width = W; canvas.height = H;
    ctx.clearRect(0, 0, W, H);

    if (!traffic || !traffic.length) {
        ctx.fillStyle = '#999'; ctx.font = '13px sans-serif'; ctx.textAlign = 'center';
        ctx.fillText('No traffic data', W/2, H/2); return;
    }

    const maxBytes = Math.max(1, ...traffic.map(d => Math.max(d.upload||0, d.download||0)));
    const pad = {l:40, r:10, t:10, b:30};
    const cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    const barW = cw / traffic.length;

    traffic.forEach((d, i) => {
        const x = pad.l + i * barW;
        const upH = ((d.upload||0) / maxBytes) * ch;
        const dnH = ((d.download||0) / maxBytes) * ch;
        ctx.fillStyle = 'rgba(33,150,243,0.7)';
        ctx.fillRect(x+2, pad.t + ch - upH, barW*0.45, upH);
        ctx.fillStyle = 'rgba(76,175,80,0.7)';
        ctx.fillRect(x + barW*0.5, pad.t + ch - dnH, barW*0.45, dnH);
        if (i % 3 === 0) {
            ctx.fillStyle = '#999'; ctx.font = '9px sans-serif'; ctx.textAlign = 'center';
            ctx.fillText(d.date ? d.date.slice(5) : '', x + barW/2, H - 8);
        }
    });

    ctx.strokeStyle = '#e0e0e0'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pad.l, pad.t); ctx.lineTo(pad.l, pad.t+ch); ctx.lineTo(pad.l+cw, pad.t+ch); ctx.stroke();

    // Legend
    ctx.fillStyle = 'rgba(33,150,243,0.7)'; ctx.fillRect(pad.l, 0, 10, 8);
    ctx.fillStyle = '#555'; ctx.font = '10px sans-serif'; ctx.textAlign = 'left'; ctx.fillText('Upload', pad.l+13, 8);
    ctx.fillStyle = 'rgba(76,175,80,0.7)'; ctx.fillRect(pad.l+60, 0, 10, 8);
    ctx.fillStyle = '#555'; ctx.fillText('Download', pad.l+73, 8);
}

async function saveDDoSConfig() {
    const enabledEl = document.getElementById('ddos-enabled');
    if (!enabledEl) { showToast('Error: DDoS panel not loaded'); return; }
    const cfg = {
        enabled: enabledEl.checked,
        rate_window_sec: parseInt(document.getElementById('ddos-window').value)||60,
        max_requests_per_window: parseInt(document.getElementById('ddos-max').value)||300,
        ban_duration_min: parseInt(document.getElementById('ddos-ban-dur').value)||60
    };
    const res = await fetch('/admin/ddos/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(cfg) });
    if (res.ok) showToast('DDoS config saved (enabled=' + cfg.enabled + ')');
    else showToast('Failed to save DDoS config');
}

async function unbanIP(ip) {
    await fetch('/admin/ddos/unban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ip}) });
    loadDDoS(); showToast('IP unbanned');
}

async function manualBan() {
    const ip = document.getElementById('manualBanIP').value.trim();
    if (!ip) return;
    await fetch('/admin/ddos/ban', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ip}) });
    loadDDoS(); showToast('IP banned');
}

// ─── Admin Settings ───────────────────────────────────────────────────────────
async function loadAdminSettings() {
    try {
        const res = await fetch('/admin/settings');
        const s = await res.json();
        document.getElementById('as-bg').value = s.background_url||'';
        document.getElementById('as-music').value = s.bg_music_url||'';
        document.getElementById('as-lang').value = s.language||'en';
        document.getElementById('as-allow-theme').checked = !!s.allow_user_theme;
        document.getElementById('as-direct-links').checked = !!s.show_direct_links;
        applyBgMusic(s.bg_music_url);
    } catch {}
}

async function saveAdminSettings() {
    const s = {
        background_url: document.getElementById('as-bg').value,
        bg_music_url: document.getElementById('as-music').value,
        language: document.getElementById('as-lang').value,
        allow_user_theme: document.getElementById('as-allow-theme').checked,
        show_direct_links: document.getElementById('as-direct-links').checked
    };
    const res = await fetch('/admin/settings/save', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(s) });
    if (res.ok) { showToast('Settings saved'); applyBgMusic(s.bg_music_url); }
    else showToast('Failed to save settings');
}

function applyBgMusic(url) {
    let audio = document.getElementById('bgMusicPlayer');
    if (!url) { if (audio) { audio.pause(); audio.remove(); } return; }
    if (!audio) { audio = document.createElement('audio'); audio.id = 'bgMusicPlayer'; audio.loop = true; audio.volume = 0.3; document.body.appendChild(audio); }
    if (audio.src !== url) { audio.src = url; audio.play().catch(()=>{}); }
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function escapeHtml(text) { const d = document.createElement('div'); d.textContent = text||''; return d.innerHTML; }

function closeConfirmModal() {
    var m = document.getElementById('_confirmModal');
    if (m) m.style.display = 'none';
}

function closeConfirmModal() {
    var m = document.getElementById('_confirmModal');
    if (m) m.style.display = 'none';
}

function showConfirm(message, onYes, onNo, alertOnly) {
    let modal = document.getElementById('_confirmModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = '_confirmModal';
        modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:500;align-items:center;justify-content:center;';
        modal.innerHTML = '<div style="background:#fff;border-radius:8px;padding:28px;min-width:320px;max-width:420px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);">' +
            '<div id="_confirmMsg" style="font-size:15px;color:#1a1a1a;margin-bottom:20px;line-height:1.5;"></div>' +
            '<div id="_confirmBtns" style="display:flex;gap:10px;justify-content:center;"></div>' +
            '</div>';
        document.body.appendChild(modal);
        modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
    }
    document.getElementById('_confirmMsg').textContent = message;
    const btns = document.getElementById('_confirmBtns');
    if (alertOnly) {
        btns.innerHTML = '<button onclick="closeConfirmModal()" style="padding:8px 24px;background:#1a1a1a;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px;">OK</button>';
    } else {
        const noLabel = onNo ? 'No' : 'Cancel';
        btns.innerHTML = '<button id="_cBtnNo" style="padding:8px 20px;background:#f5f5f5;color:#333;border:1px solid #ddd;border-radius:4px;cursor:pointer;font-size:14px;">' + noLabel + '</button>' +
            '<button id="_cBtnYes" style="padding:8px 20px;background:#1a1a1a;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px;">Yes</button>';
        document.getElementById('_cBtnYes').onclick = () => { modal.style.display = 'none'; if (onYes) onYes(); };
        document.getElementById('_cBtnNo').onclick = () => { modal.style.display = 'none'; if (onNo) onNo(); };
    }
    modal.style.display = 'flex';
}

function showToast(msg) {
    let t = document.getElementById('_adminToast');
    if (!t) { t = document.createElement('div'); t.id = '_adminToast'; t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#1a1a1a;color:#fff;padding:10px 22px;border-radius:8px;font-size:13px;z-index:999;opacity:0;pointer-events:none;transition:opacity 0.2s;'; document.body.appendChild(t); }
    t.textContent = msg; t.style.opacity = '1';
    setTimeout(() => { t.style.opacity = '0'; }, 2500);
}

// Modal keyboard / click-outside close
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('userModal').addEventListener('click', e => { if (e.target === document.getElementById('userModal')) closeUserModal(); });
    document.getElementById('nodeModal').addEventListener('click', e => { if (e.target === document.getElementById('nodeModal')) closeNodeModal(); });
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeUserModal(); closeNodeModal(); } });
</script>
` + snd.ThemeSnippet("account") + `
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// ─── User Info Page (sub-users at /ad) ───────────────────────────────────────
func renderUserInfoPage(w http.ResponseWriter, r *http.Request, user *snd.UserAccount) {
	usedStorage := snd.CalcUserStorage(user.UUID)
	storageRemain := int64(-1)
	limitStr := "Unlimited"
	usedPct := 0.0
	if user.StorageLimit > 0 {
		storageRemain = user.StorageLimit - usedStorage
		if storageRemain < 0 { storageRemain = 0 }
		limitStr = snd.FormatBytes(user.StorageLimit)
		usedPct = float64(usedStorage) / float64(user.StorageLimit) * 100
		if usedPct > 100 { usedPct = 100 }
	}

	quotaBarColor := "#1a1a1a"
	if usedPct > 80 { quotaBarColor = "#c62828" } else if usedPct > 60 { quotaBarColor = "#f57c00" }

	quotaCard := ""
	if user.StorageLimit > 0 {
		quotaCard = fmt.Sprintf(`
        <div class="stat-card">
            <div class="stat-label">Storage Remaining</div>
            <div class="stat-value">%s</div>
            <div class="stat-sub">Used %s of %s (%.1f%%)</div>
            <div style="margin-top:10px;background:#f0f0f0;height:8px;border-radius:4px;overflow:hidden;">
                <div style="background:%s;height:100%%;width:%.1f%%;border-radius:4px;transition:width 0.3s;"></div>
            </div>
        </div>`,
			snd.FormatBytes(storageRemain),
			snd.FormatBytes(usedStorage), limitStr, usedPct, quotaBarColor, usedPct,
		)
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Account - ` + snd.Cfg.SiteName + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #fafafa; color: #1a1a1a; }
        .container { max-width: 900px; margin: 0 auto; padding: 32px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid #e0e0e0; }
        h1 { font-size: 22px; font-weight: 500; }
        .header-actions { display: flex; gap: 8px; }
        .btn { padding: 8px 16px; background: #1a1a1a; color: white; text-decoration: none; border: none; cursor: pointer; font-size: 14px; border-radius: 4px; }
        .btn:hover { background: #333; }
        .btn-red { background: #c62828; }
        .btn-red:hover { background: #b71c1c; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: white; padding: 22px; border: 1px solid #e0e0e0; border-radius: 4px; }
        .stat-label { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
        .stat-value { font-size: 28px; font-weight: 500; word-break: break-word; }
        .stat-sub { font-size: 12px; color: #888; margin-top: 4px; }
        .card { background: white; border: 1px solid #e0e0e0; padding: 24px; margin-bottom: 16px; border-radius: 4px; }
        .card h2 { font-size: 16px; font-weight: 500; margin-bottom: 16px; }
        .info-row { display: flex; justify-content: space-between; align-items: center; padding: 11px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: #666; }
        .info-value { font-weight: 500; font-family: monospace; font-size: 13px; max-width: 60%; text-align: right; word-break: break-all; }
        .token-row { display: flex; gap: 8px; align-items: center; }
        .token-input { flex: 1; padding: 8px 12px; border: 1px solid #d0d0d0; font-family: monospace; font-size: 12px; background: #fafafa; border-radius: 4px; }
        .cp-section { margin-top: 20px; padding-top: 20px; border-top: 1px solid #f0f0f0; }
        .cp-toggle-btn { padding: 8px 16px; background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 4px; cursor: pointer; font-size: 13px; color: #444; }
        .cp-toggle-btn:hover { background: #ececec; }
        .cp-form { margin-top: 14px; display: none; flex-direction: column; gap: 12px; max-width: 420px; }
        .cp-form.open { display: flex; }
        .cp-field label { display: block; font-size: 12px; font-weight: 500; color: #555; margin-bottom: 4px; }
        .cp-field input { width: 100%; padding: 9px 11px; border: 1px solid #d0d0d0; font-size: 14px; border-radius: 4px; outline: none; }
        .cp-field input:focus { border-color: #1a1a1a; }
        .cp-actions { display: flex; gap: 8px; }
        .cp-save-btn { padding: 8px 20px; background: #1565c0; color: #fff; border: none; border-radius: 4px; font-size: 13px; cursor: pointer; }
        .cp-save-btn:hover { background: #0d47a1; }
        .cp-cancel-btn { padding: 8px 16px; background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 4px; font-size: 13px; cursor: pointer; color: #555; }
        .cp-msg { font-size: 13px; padding: 8px 12px; border-radius: 4px; display: none; }
        .cp-msg.error { background: #ffebee; color: #c62828; }
        .cp-msg.success { background: #e8f5e9; color: #2e7d32; }
        #toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: #1a1a1a; color: #fff; padding: 10px 22px; border-radius: 8px; font-size: 13px; z-index: 999; opacity: 0; pointer-events: none; transition: opacity 0.2s; white-space: nowrap; }
        #toast.show { opacity: 1; }
        .toggle-switch { position: relative; display: inline-block; width: 44px; height: 24px; }
        .toggle-switch input { opacity: 0; width: 0; height: 0; }
        .toggle-slider { position: absolute; cursor: pointer; inset: 0; background: #ccc; border-radius: 24px; transition: 0.3s; }
        .toggle-slider:before { content: ""; position: absolute; height: 18px; width: 18px; left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.3s; }
        input:checked + .toggle-slider { background: #4caf50; }
        input:checked + .toggle-slider:before { transform: translateX(20px); }

        /* Liquid Glass */
        body.th-liquid .card, body.th-liquid .stat-card {
            background: rgba(255,255,255,0.08) !important;
            backdrop-filter: blur(24px) saturate(180%) !important;
            -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
            border-color: rgba(255,255,255,0.18) !important;
            box-shadow: 0 8px 32px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.3) !important;
        }
        body.th-liquid .header { background: rgba(255,255,255,0.07) !important; backdrop-filter: blur(20px) !important; border-color: rgba(255,255,255,0.14) !important; }
        body.th-liquid .info-label, body.th-liquid .stat-label { color: rgba(255,255,255,0.65) !important; }
        body.th-liquid .stat-value, body.th-liquid h1, body.th-liquid h2 { color: rgba(255,255,255,0.92) !important; }
        body.th-liquid .info-value, body.th-liquid .stat-sub { color: rgba(255,255,255,0.75) !important; }
        body.th-liquid input, body.th-liquid .token-input { background: rgba(255,255,255,0.10) !important; border-color: rgba(255,255,255,0.2) !important; color: #fff !important; }
        body.th-liquid .cp-toggle-btn { background: rgba(255,255,255,0.10) !important; border-color: rgba(255,255,255,0.2) !important; color: rgba(255,255,255,0.85) !important; }
        body.th-liquid:not(.th-rainbow):not(.th-dark) { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%) !important; }
        body.th-dark .card, body.th-dark .stat-card { background: #181818 !important; border-color: #2a2a2a !important; }
        body.th-dark .header { background: #111 !important; border-color: #2a2a2a !important; }
        body.th-dark input, body.th-dark .token-input { background: #111 !important; border-color: #333 !important; color: #ddd !important; }
        body.th-dark .cp-toggle-btn { background: #222 !important; border-color: #333 !important; color: #ccc !important; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>My Account</h1>
        <div class="header-actions">
            <a href="/" class="btn">← Files</a>
            <a href="/logout" class="btn btn-red">Logout</a>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Username</div>
            <div class="stat-value">` + user.Username + `</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Storage Used</div>
            <div class="stat-value">` + snd.FormatBytes(usedStorage) + `</div>
            <div class="stat-sub">Limit: ` + limitStr + `</div>
        </div>
        ` + quotaCard + `
    </div>

    <div class="card">
        <h2>Account Info</h2>
        <div class="info-row"><span class="info-label">Username</span><span class="info-value">` + user.Username + `</span></div>
        <div class="info-row"><span class="info-label">Email</span><span class="info-value">` + orDash(user.Email) + `</span></div>
        <div class="info-row"><span class="info-label">UUID</span><span class="info-value" style="font-size:11px">` + user.UUID + `</span></div>
        <div class="info-row"><span class="info-label">Status</span><span class="info-value" style="color:#2e7d32">Active</span></div>
        <div class="info-row"><span class="info-label">Created</span><span class="info-value">` + user.CreatedAt.Format("2006-01-02 15:04:05") + `</span></div>
    </div>

    <div class="card">
        <h2>API Token</h2>
        <div class="token-row">
            <input type="password" id="tokenInput" class="token-input" value="` + user.APIToken + `" readonly>
            <button class="btn" onclick="toggleToken()">Show</button>
            <button class="btn" onclick="copyToken()">Copy</button>
        </div>
        <div style="font-size:12px;color:#888;margin-top:8px;">
            File URL: <code>/raw/&lt;filename&gt;?u=` + user.UUID + `&amp;token=TOKEN</code>
        </div>
    </div>

    <!-- Settings -->
    <div class="card">
        <h2>Settings</h2>
        <div class="info-row">
            <span class="info-label">Background URL</span>
            <input type="text" id="us-bg" placeholder="https://..." style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;width:260px;">
        </div>
        <div class="info-row">
            <span class="info-label">Background Music URL</span>
            <input type="text" id="us-music" placeholder="https://..." style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;width:260px;">
        </div>
        <div class="info-row">
            <span class="info-label">Language</span>
            <select id="us-lang" style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;">
                <option value="en">English</option>
                <option value="vi">Tiếng Việt</option>
                <option value="zh">中文</option>
                <option value="ja">日本語</option>
            </select>
        </div>
        <div class="info-row">
            <span class="info-label">Show Direct Links</span>
            <label class="toggle-switch"><input type="checkbox" id="us-direct-links"><span class="toggle-slider"></span></label>
        </div>
        <div style="margin-top:16px;">
            <button class="btn" onclick="saveUserSettings()">Save Settings</button>
        </div>
    </div>

    <!-- Change Password -->
    <div class="card">
        <h2>Account Settings</h2>
        <button class="cp-toggle-btn" onclick="toggleCpForm()" id="cpToggleBtn">Change Password</button>
        <div class="cp-form" id="cpForm">
            <div class="cp-field"><label>Current Password</label><input type="password" id="cpCurrent" placeholder="Enter current password"></div>
            <div class="cp-field"><label>New Password</label><input type="password" id="cpNew" placeholder="At least 6 characters"></div>
            <div class="cp-field"><label>Confirm New Password</label><input type="password" id="cpConfirm" placeholder="Repeat new password"></div>
            <div class="cp-msg" id="cpMsg"></div>
            <div class="cp-actions">
                <button class="cp-save-btn" id="cpSaveBtn" onclick="submitCp()">Save Password</button>
                <button class="cp-cancel-btn" onclick="toggleCpForm()">Cancel</button>
            </div>
        </div>
    </div>
</div>

<div id="toast"></div>

<script>
/* ── User Settings ── */
async function loadUserSettings() {
    try {
        const res = await fetch('/user/settings');
        const data = await res.json();
        const s = data.settings || data;
        document.getElementById('us-bg').value = s.background_url||'';
        document.getElementById('us-music').value = s.bg_music_url||'';
        document.getElementById('us-lang').value = s.language||'en';
        document.getElementById('us-direct-links').checked = !!s.show_direct_links;
        if (s.bg_music_url) applyBgMusic(s.bg_music_url);
    } catch(e) { console.error('loadUserSettings:', e); }
}

async function saveUserSettings() {
    const s = {
        background_url: document.getElementById('us-bg').value,
        bg_music_url: document.getElementById('us-music').value,
        language: document.getElementById('us-lang').value,
        show_direct_links: document.getElementById('us-direct-links').checked
    };
    const res = await fetch('/user/settings/save', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(s) });
    if (res.ok) { showToast('Settings saved'); applyBgMusic(s.bg_music_url); }
    else showToast('Failed to save settings');
}

function applyBgMusic(url) {
    let audio = document.getElementById('bgMusicPlayer');
    if (!url) { if (audio) { audio.pause(); audio.remove(); } return; }
    if (!audio) { audio = document.createElement('audio'); audio.id = 'bgMusicPlayer'; audio.loop = true; audio.volume = 0.3; document.body.appendChild(audio); }
    if (audio.src !== url) { audio.src = url; audio.play().catch(()=>{}); }
}

/* ── Change Password ── */
function toggleCpForm() {
    const f = document.getElementById('cpForm');
    const open = f.classList.toggle('open');
    document.getElementById('cpToggleBtn').textContent = open ? 'Cancel' : 'Change Password';
    if (open) document.getElementById('cpCurrent').focus();
    const msg = document.getElementById('cpMsg'); msg.style.display = 'none'; msg.className = 'cp-msg';
}

function submitCp() {
    const cur = document.getElementById('cpCurrent').value;
    const nw  = document.getElementById('cpNew').value;
    const cf  = document.getElementById('cpConfirm').value;
    const btn = document.getElementById('cpSaveBtn');
    document.getElementById('cpMsg').style.display = 'none';
    if (!cur || !nw || !cf) { showCpMsg('All fields are required.', false); return; }
    if (nw.length < 6) { showCpMsg('New password must be at least 6 characters.', false); return; }
    if (nw !== cf) { showCpMsg('Passwords do not match.', false); return; }
    btn.disabled = true; btn.textContent = 'Saving...';
    fetch('/user/change-password', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({current_password: cur, new_password: nw}) })
    .then(r => r.json()).then(d => {
        btn.disabled = false; btn.textContent = 'Save Password';
        if (d.success) { ['cpCurrent','cpNew','cpConfirm'].forEach(id => document.getElementById(id).value=''); showCpMsg('Password changed!', true); showToast('Password changed'); }
        else showCpMsg(d.message || 'Failed.', false);
    }).catch(() => { btn.disabled = false; btn.textContent = 'Save Password'; showCpMsg('Network error.', false); });
}

function showCpMsg(text, ok) {
    const msg = document.getElementById('cpMsg');
    msg.textContent = text; msg.className = 'cp-msg ' + (ok ? 'success' : 'error'); msg.style.display = 'block';
}

function toggleToken() { const inp = document.getElementById('tokenInput'); inp.type = inp.type === 'password' ? 'text' : 'password'; }
function copyToken() { navigator.clipboard.writeText(document.getElementById('tokenInput').value); showToast('Token copied'); }

function showToast(msg) {
    const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2500);
}

loadUserSettings();
</script>
` + snd.ThemeSnippet("account") + `
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
