package admin

import (
	"fmt"
	"net/http"
	"runtime"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
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
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #fafafa;
            color: #1a1a1a;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 32px; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid #e0e0e0;
        }
        h1 { font-size: 24px; font-weight: 500; }
        .header-actions { display: flex; gap: 8px; }
        .btn {
            padding: 8px 16px;
            background: #1a1a1a;
            color: white;
            text-decoration: none;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }
        .btn:hover { background: #333; }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: white;
            padding: 24px;
            border: 1px solid #e0e0e0;
        }
        .stat-label { font-size: 13px; color: #666; margin-bottom: 8px; }
        .stat-value { font-size: 32px; font-weight: 500; }

        .card {
            background: white;
            padding: 24px;
            border: 1px solid #e0e0e0;
            margin-bottom: 16px;
        }
        .card h2 { font-size: 18px; font-weight: 500; margin-bottom: 16px; }

        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
            font-size: 14px;
        }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: #666; }
        .info-value { font-weight: 500; }

        .bench-grid { display: grid; gap: 10px; }
        .bench-btn {
            width: 100%;
            padding: 11px;
            background: #1a1a1a;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 14px;
            text-align: left;
        }
        .bench-btn:hover { background: #333; }
        .bench-results {
            display: none;
            margin-top: 16px;
            padding: 16px;
            background: #fafafa;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            font-family: 'SF Mono', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            min-height: 80px;
        }

        .sessions-list { font-size: 13px; }
        .session-item {
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }
        .session-item:last-child { border-bottom: none; }
        .session-info { flex: 1; min-width: 0; }
        .session-badge {
            display: inline-block;
            padding: 2px 8px;
            background: #4caf50;
            color: white;
            font-size: 11px;
            border-radius: 3px;
            margin-left: 8px;
        }
        .kick-btn {
            padding: 6px 12px;
            background: #d32f2f;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 12px;
            flex-shrink: 0;
        }
        .kick-btn:hover { background: #b71c1c; }
        .kick-btn:disabled { background: #ccc; cursor: not-allowed; }

        .logs-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .logs-table th { padding: 8px 12px; background: #f5f5f5; text-align: left; font-weight: 500; border-bottom: 1px solid #e0e0e0; }
        .logs-table td { padding: 8px 12px; border-bottom: 1px solid #f5f5f5; font-family: monospace; }
        .logs-table tr:last-child td { border-bottom: none; }
        .logs-wrapper { max-height: 360px; overflow-y: auto; }

        .tabs { display: flex; gap: 0; margin-bottom: 0; border-bottom: 1px solid #e0e0e0; }
        .tab {
            padding: 12px 20px;
            cursor: pointer;
            font-size: 14px;
            color: #666;
            border-bottom: 2px solid transparent;
            margin-bottom: -1px;
        }
        .tab.active { color: #1a1a1a; border-bottom-color: #1a1a1a; font-weight: 500; }
        .tab:hover { color: #1a1a1a; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        @media (max-width: 768px) {
            .container { padding: 20px 16px; }
            .header { flex-wrap: wrap; gap: 12px; }
            .stat-value { font-size: 26px; }
        }
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
            <div class="stat-card">
                <div class="stat-label">Total Files</div>
                <div class="stat-value">` + fmt.Sprintf("%d", totalFiles) + `</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Storage Used</div>
                <div class="stat-value">` + snd.FormatBytes(totalSize) + `</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value">` + fmt.Sprintf("%d", totalRequests) + `</div>
            </div>
        </div>

        <div class="card">
            <div class="tabs">
                <div class="tab active" onclick="switchTab('system')">System</div>
                <div class="tab" onclick="switchTab('sessions')">Sessions</div>
                <div class="tab" onclick="switchTab('logs')">Access Logs</div>
                <div class="tab" onclick="switchTab('benchmark')">Benchmark</div>
            </div>

            <div id="tab-system" class="tab-content active" style="margin-top:16px;">
                <div class="info-row">
                    <span class="info-label">Operating System</span>
                    <span class="info-value">` + runtime.GOOS + `</span>
                </div>
                <div class="info-row">
                    <span class="info-label">CPU Cores</span>
                    <span class="info-value">` + fmt.Sprintf("%d", runtime.NumCPU()) + `</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Memory Allocated</span>
                    <span class="info-value">` + snd.FormatBytes(int64(m.Alloc)) + `</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Total Memory Allocated</span>
                    <span class="info-value">` + snd.FormatBytes(int64(m.TotalAlloc)) + `</span>
                </div>
                <div class="info-row">
                    <span class="info-label">System Memory</span>
                    <span class="info-value">` + snd.FormatBytes(int64(m.Sys)) + `</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Goroutines</span>
                    <span class="info-value">` + fmt.Sprintf("%d", runtime.NumGoroutine()) + `</span>
                </div>
                <div class="info-row">
                    <span class="info-label">GC Runs</span>
                    <span class="info-value">` + fmt.Sprintf("%d", m.NumGC) + `</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Go Version</span>
                    <span class="info-value">` + runtime.Version() + `</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Server Version</span>
                    <span class="info-value">ServerNotDie v` + snd.VERSION + `</span>
                </div>
            </div>

            <div id="tab-sessions" class="tab-content" style="margin-top:16px;">
                <div class="sessions-list" id="sessionsList">Loading sessions...</div>
            </div>

            <div id="tab-logs" class="tab-content" style="margin-top:16px;">
                <div class="logs-wrapper">
                    <table class="logs-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>IP</th>
                                <th>Action</th>
                                <th>Path</th>
                            </tr>
                        </thead>
                        <tbody id="logsTableBody">
                            <tr><td colspan="4" style="padding:16px;color:#999;">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="tab-benchmark" class="tab-content" style="margin-top:16px;">
                <div class="bench-grid">
                    <button class="bench-btn" onclick="runPingTest()">Test Ping</button>
                    <button class="bench-btn" onclick="runDownloadTest()">Test Download Speed</button>
                    <button class="bench-btn" onclick="runUploadTest()">Test Upload Speed</button>
                    <button class="bench-btn" onclick="runDiskTest()">Test Disk Speed</button>
                    <button class="bench-btn" onclick="runCPUTest()">Test CPU</button>
                    <button class="bench-btn" onclick="runMemoryTest()">Test Memory</button>
                </div>
                <div class="bench-results" id="benchmarkResults"></div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(name) {
            document.querySelectorAll('.tab').forEach((t, i) => {
                const names = ['system','sessions','logs','benchmark'];
                t.classList.toggle('active', names[i] === name);
            });
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById('tab-' + name).classList.add('active');
            if (name === 'sessions') loadSessions();
            if (name === 'logs') loadLogs();
        }

        async function loadSessions() {
            try {
                const res = await fetch('/sessions');
                const sessions = await res.json();
                const list = document.getElementById('sessionsList');
                if (!sessions || !sessions.length) {
                    list.innerHTML = '<div style="padding:16px;color:#999;">No active sessions</div>';
                    return;
                }
                list.innerHTML = sessions.map(s =>
                    '<div class="session-item">' +
                    '<div class="session-info">' +
                    '<strong>' + escapeHtml(s.ip) + '</strong>' +
                    (s.is_current ? '<span class="session-badge">Current</span>' : '') +
                    '<div style="color:#666;margin-top:4px;">' + escapeHtml(s.os) + ' / ' + escapeHtml(s.browser) + '</div>' +
                    '<div style="color:#999;font-size:11px;margin-top:2px;">Login: ' + s.login_time + ' | Last: ' + s.last_access + '</div>' +
                    '</div>' +
                    '<button class="kick-btn" onclick="kickSession(\'' + s.session_id.replace(/'/g,"\\'") + '\',this)"' + (s.is_current ? ' disabled title="Cannot kick current session"' : '') + '>Kick</button>' +
                    '</div>'
                ).join('');
            } catch {
                document.getElementById('sessionsList').innerHTML = '<div style="padding:16px;color:#d32f2f;">Failed to load sessions</div>';
            }
        }

        async function kickSession(sessionId, btn) {
            btn.disabled = true;
            btn.textContent = '...';
            try {
                await fetch('/kick-session', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({session_id: sessionId})
                });
                btn.closest('.session-item').remove();
            } catch {
                btn.disabled = false;
                btn.textContent = 'Kick';
            }
        }

        async function loadLogs() {
            try {
                const res = await fetch('/access-logs');
                const logs = await res.json();
                const tbody = document.getElementById('logsTableBody');
                if (!logs || !logs.length) {
                    tbody.innerHTML = '<tr><td colspan="4" style="padding:16px;color:#999;">No access logs</td></tr>';
                    return;
                }
                tbody.innerHTML = [...logs].reverse().map(l =>
                    '<tr>' +
                    '<td>' + new Date(l.timestamp).toLocaleString() + '</td>' +
                    '<td>' + escapeHtml(l.ip) + '</td>' +
                    '<td>' + escapeHtml(l.action) + '</td>' +
                    '<td>' + escapeHtml(l.path) + '</td>' +
                    '</tr>'
                ).join('');
            } catch {
                document.getElementById('logsTableBody').innerHTML =
                    '<tr><td colspan="4" style="padding:16px;color:#d32f2f;">Failed to load logs</td></tr>';
            }
        }

        function showResult(text) {
            const r = document.getElementById('benchmarkResults');
            r.style.display = 'block';
            r.textContent = text;
        }

        async function runPingTest() {
            showResult('Running ping test...');
            const pings = [];
            for (let i = 0; i < 10; i++) {
                const s = performance.now();
                await fetch('/benchmark/ping');
                pings.push(performance.now() - s);
            }
            const avg = pings.reduce((a,b) => a+b, 0) / pings.length;
            showResult('Ping Test Results:\nAverage: ' + avg.toFixed(2) + ' ms\nMin: ' + Math.min(...pings).toFixed(2) + ' ms\nMax: ' + Math.max(...pings).toFixed(2) + ' ms');
        }

        async function runDownloadTest() {
            showResult('Testing download speed...');
            const size = 10;
            const s = performance.now();
            const r = await fetch('/benchmark/download?size=' + size);
            await r.blob();
            const dur = (performance.now() - s) / 1000;
            showResult('Download Test Results:\nSize: ' + size + ' MB\nDuration: ' + dur.toFixed(2) + ' s\nSpeed: ' + (size/dur).toFixed(2) + ' MB/s');
        }

        async function runUploadTest() {
            showResult('Testing upload speed...');
            const size = 10 * 1024 * 1024;
            const data = new Uint8Array(size);
            const s = performance.now();
            await fetch('/benchmark/upload', {method:'POST', body:data});
            const dur = (performance.now() - s) / 1000;
            showResult('Upload Test Results:\nSize: 10 MB\nDuration: ' + dur.toFixed(2) + ' s\nSpeed: ' + (size/1024/1024/dur).toFixed(2) + ' MB/s');
        }

        async function runDiskTest() {
            showResult('Testing disk speed...');
            const r = await fetch('/benchmark/disk');
            const d = await r.json();
            showResult('Disk Test Results:\nWrite Speed: ' + d.write_speed.toFixed(2) + ' MB/s\nRead Speed: ' + d.read_speed.toFixed(2) + ' MB/s\nWrite Time: ' + d.write_time.toFixed(3) + ' s\nRead Time: ' + d.read_time.toFixed(3) + ' s');
        }

        async function runCPUTest() {
            showResult('Testing CPU...');
            const r = await fetch('/benchmark/cpu');
            const d = await r.json();
            showResult('CPU Test Results:\nIterations: ' + d.iterations.toLocaleString() + '\nDuration: ' + d.duration_ms + ' ms');
        }

        async function runMemoryTest() {
            showResult('Testing memory...');
            const r = await fetch('/benchmark/memory');
            const d = await r.json();
            showResult('Memory Stats:\nAllocated: ' + d.alloc_mb + ' MB\nTotal Allocated: ' + d.total_alloc_mb + ' MB\nSystem: ' + d.sys_mb + ' MB\nGoroutines: ' + d.goroutines + '\nGC Runs: ' + d.num_gc);
        }

        function escapeHtml(text) {
            const d = document.createElement('div');
            d.textContent = text || '';
            return d.innerHTML;
        }
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
