package admin

import (
	"fmt"
	"net/http"
	"runtime"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	// Sub-user without admin flag → show their own account info panel at /ad
	if user := snd.GetSessionUser(r); user != nil && !user.IsAdmin {
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
                <button class="btn" onclick="promptAddNode()">+ Add Node</button>
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
                        ` + snd.BuildLangOptionsHTML("en") + `
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
                <div class="info-row">
                    <span class="info-label">Hide Footer</span>
                    <label class="toggle-switch"><input type="checkbox" id="as-hide-footer"><span class="toggle-slider"></span></label>
                </div>
                <div class="info-row" style="align-items:flex-start;">
                    <span class="info-label" style="padding-top:6px;">Custom CSS</span>
                    <textarea id="as-custom-css" rows="6" placeholder="/* your custom CSS here */" style="padding:8px 10px;border:1px solid #d0d0d0;border-radius:4px;width:340px;font-family:monospace;font-size:12px;resize:vertical;"></textarea>
                </div>
                <div style="margin-top:4px;padding-left:0;">
                    <div style="font-size:12px;color:#888;font-weight:600;margin-bottom:10px;margin-top:16px;">Embed / OG Meta (share page)</div>
                    <div class="info-row">
                        <span class="info-label">Embed Loader (CSA.js)</span>
                        <label class="toggle-switch"><input type="checkbox" id="as-embed-loader"><span class="toggle-slider"></span></label>
                    </div>
                    <div style="font-size:11px;color:#aaa;margin:-6px 0 10px 0;padding-left:0;">Enable the CSA.js embed-loader script on all pages. Disable to stop injecting the external script.</div>
                    <div class="info-row">
                        <span class="info-label">Embed Title</span>
                        <input type="text" id="as-embed-title" placeholder="Leave empty for default" style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;width:300px;">
                    </div>
                    <div class="info-row">
                        <span class="info-label">Embed Description</span>
                        <input type="text" id="as-embed-desc" placeholder="File sharing powered by servernotdie" style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;width:300px;">
                    </div>
                    <div class="info-row">
                        <span class="info-label">Embed Image URL</span>
                        <input type="text" id="as-embed-img" placeholder="https://..." style="padding:6px 10px;border:1px solid #d0d0d0;border-radius:4px;width:300px;">
                    </div>
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
        <div id="currentTokenRow" style="display:none;margin-bottom:14px;">
            <label style="display:block;font-size:13px;color:#555;margin-bottom:5px">Current API Token</label>
            <div style="display:flex;gap:6px;align-items:center;">
                <input type="password" id="currentTokenValue" readonly style="flex:1;padding:8px 10px;border:1px solid #d0d0d0;font-size:12px;font-family:monospace;background:#fafafa;border-radius:4px;">
                <button type="button" onclick="document.getElementById('currentTokenValue').type=document.getElementById('currentTokenValue').type==='password'?'text':'password'" style="padding:8px 10px;border:1px solid #d0d0d0;background:#fff;cursor:pointer;font-size:12px;border-radius:4px;white-space:nowrap">Show</button>
                <button type="button" onclick="navigator.clipboard.writeText(document.getElementById('currentTokenValue').value);showToast('Token copied')" style="padding:8px 10px;border:1px solid #d0d0d0;background:#fff;cursor:pointer;font-size:12px;border-radius:4px;white-space:nowrap">Copy</button>
            </div>
        </div>
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

    <script src="/lib/utils.js"></script>
    <script src="/lib/admin.js"></script>
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
                ` + snd.BuildLangOptionsHTML(user.Settings.Language) + `
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
/* ── Toast ── */
function showToast(msg, type) {
    var t = document.getElementById('toast');
    t.textContent = msg;
    t.style.opacity = '1';
    setTimeout(function() { t.style.opacity = '0'; }, 2500);
}

/* ── Token visibility ── */
function toggleToken() {
    var inp = document.getElementById('tokenInput');
    var btn = inp.nextElementSibling;
    if (inp.type === 'password') { inp.type = 'text'; btn.textContent = 'Hide'; }
    else { inp.type = 'password'; btn.textContent = 'Show'; }
}
function copyToken() {
    var val = document.getElementById('tokenInput').value;
    navigator.clipboard.writeText(val).then(function() { showToast('Token copied!'); }).catch(function() {
        var t = document.createElement('textarea');
        t.value = val; document.body.appendChild(t); t.select();
        document.execCommand('copy'); document.body.removeChild(t);
        showToast('Token copied!');
    });
}

/* ── Settings load/save ── */
(function loadSettings() {
    fetch('/user/settings').then(function(r) { return r.json(); }).then(function(data) {
        var s = data.settings || data;
        var bg = document.getElementById('us-bg');
        var music = document.getElementById('us-music');
        var lang = document.getElementById('us-lang');
        var dl = document.getElementById('us-direct-links');
        if (bg)    bg.value    = s.background_url || '';
        if (music) music.value = s.bg_music_url   || '';
        if (lang)  lang.value  = s.language        || 'en';
        if (dl)    dl.checked  = !!s.show_direct_links;
    }).catch(function() {});
})();

function saveUserSettings() {
    var s = {
        background_url:    (document.getElementById('us-bg')    || {}).value || '',
        bg_music_url:      (document.getElementById('us-music') || {}).value || '',
        language:          (document.getElementById('us-lang')  || {}).value || 'en',
        show_direct_links: !!(document.getElementById('us-direct-links') || {}).checked
    };
    fetch('/user/settings/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(s)
    }).then(function(r) {
        if (r.ok) showToast('Settings saved');
        else showToast('Failed to save settings');
    }).catch(function() { showToast('Failed to save settings'); });
}

/* ── Change Password ── */
function toggleCpForm() {
    var f = document.getElementById('cpForm');
    var open = f.classList.toggle('open');
    document.getElementById('cpToggleBtn').textContent = open ? 'Cancel' : 'Change Password';
    if (open) document.getElementById('cpCurrent').focus();
    var msg = document.getElementById('cpMsg');
    msg.style.display = 'none'; msg.className = 'cp-msg';
}
function showCpMsg(msg, success) {
    var el = document.getElementById('cpMsg');
    el.textContent = msg;
    el.className = 'cp-msg ' + (success ? 'success' : 'error');
    el.style.display = 'block';
}
function submitCp() {
    var cur = document.getElementById('cpCurrent').value;
    var nw  = document.getElementById('cpNew').value;
    var cf  = document.getElementById('cpConfirm').value;
    var btn = document.getElementById('cpSaveBtn');
    document.getElementById('cpMsg').style.display = 'none';
    if (!cur || !nw || !cf) { showCpMsg('All fields are required.', false); return; }
    if (nw.length < 6)      { showCpMsg('New password must be at least 6 characters.', false); return; }
    if (nw !== cf)          { showCpMsg('Passwords do not match.', false); return; }
    btn.disabled = true; btn.textContent = 'Saving...';
    fetch('/user/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current: cur, new_password: nw })
    }).then(function(r) { return r.json(); }).then(function(d) {
        btn.disabled = false; btn.textContent = 'Save Password';
        if (d.success) {
            showCpMsg('Password changed successfully!', true);
            document.getElementById('cpCurrent').value = '';
            document.getElementById('cpNew').value = '';
            document.getElementById('cpConfirm').value = '';
        } else {
            showCpMsg(d.error || 'Failed to change password.', false);
        }
    }).catch(function() {
        btn.disabled = false; btn.textContent = 'Save Password';
        showCpMsg('Network error. Please try again.', false);
    });
}
</script>

` + snd.ThemeSnippet("account") + `
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
