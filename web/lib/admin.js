// admin.js
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
    if (name === 'seclog') loadSecurityLogs();
    if (name === 'allowlist') loadAllowlist();
}

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
    document.getElementById('currentTokenRow').style.display = 'none';
    document.getElementById('userModal').style.display = 'flex';
}

function openEditUserModal(uuid) {
    const u = userDataMap[uuid];
    if (!u) { alert(_t('admin_user_not_found','User not found. Refresh.')); return; }
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
    // Show current token (available from list API for true admins)
    const tokenRow = document.getElementById('currentTokenRow');
    const tokenInput = document.getElementById('currentTokenValue');
    if (u.api_token && u.api_token !== '[redacted]') {
        tokenInput.value = u.api_token;
        tokenInput.type = 'password';
        tokenRow.style.display = 'block';
    } else {
        tokenRow.style.display = 'none';
    }
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
    if (!body.username) { showConfirm(_t('validation_username_required','Username required'), null, null, true); return; }
    const url = uuid ? '/admin/users/update' : '/admin/users/create';
    if (!uuid && !body.password) { showConfirm(_t('validation_password_required','Password required for new users'), null, null, true); return; }
    if (uuid) {
        showConfirm(_t('confirm_save_user','Save changes to "{username}"?').replace('{username}', body.username), async () => {
            await doSaveUser(url, body);
        });
        return;
    }
    await doSaveUser(url, body);
}

async function doSaveUser(url, body) {
    const res = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const data = await res.json();
    if (!data.success) { showConfirm(data.message || _t('toast_error_save','Failed to save'), null, null, true); return; }
    if (data.api_token) {
        document.getElementById('userTokenResult').style.display = 'block';
        document.getElementById('userTokenValue').textContent = data.api_token;
    }
    closeUserModal();
    await loadUsers();
    // Notify admin that privilege changes take effect on next login for the affected user
    if (body.is_admin !== undefined && body.uuid) {
        const cached = userDataMap[body.uuid];
        const wasAdmin = cached ? !!cached.is_admin : false;
        if (body.is_admin !== wasAdmin) {
            showToast((body.is_admin ? ' Admin granted' : ' Admin revoked') + ' — user must re-login to apply');
        }
    }
}

function closeUserModal() { document.getElementById('userModal').style.display = 'none'; }

async function confirmDeleteUser(uuid, username) {
    showConfirm(_t('confirm_delete_user','Delete user "{username}"? This cannot be undone.').replace('{username}', username), async () => {
        showConfirm(_t('confirm_delete_files_also','Also delete all files of "{username}"?').replace('{username}', username), 
            async () => doDeleteUser(uuid, true),
            async () => doDeleteUser(uuid, false)
        );
    });
}
async function doDeleteUser(uuid, deleteFiles) {
    const res = await fetch('/admin/users/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({uuid, delete_files: deleteFiles}) });
    const data = await res.json();
    if (data.success) { loadUsers(); showToast(_t('toast_user_deleted','User deleted')); }
    else showToast(_t('toast_error_delete_user','Failed to delete user'));
}

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
            html += '<td style="font-family:monospace;">' + escapeHtml(n.ip) + (n.port ? ':' + escapeHtml(n.port) : '') + '</td>';
            html += '<td><label class="toggle-switch"><input type="checkbox"' + (n.is_primary?' checked':'') + ' onchange="setPrimaryNode(\'' + n.id + '\',this.checked)"><span class="toggle-slider"></span></label></td>';
            html += '<td><label class="toggle-switch"><input type="checkbox"' + (n.backup_mode?' checked':'') + ' onchange="setNodeBackup(\'' + n.id + '\',this.checked)"><span class="toggle-slider"></span></label></td>';
            html += '<td style="display:flex;gap:4px;align-items:center;">';
            html += '<button class="btn" style="padding:4px 10px;font-size:12px;" onclick="openNodeModal(\'' + n.id + '\')">Edit</button>';
            if (!n.is_default) html += '<button class="btn" style="padding:4px 10px;font-size:12px;background:#d32f2f;" onclick="deleteNode(\'' + n.id + '\')">Delete</button>';
            html += '<button class="btn" style="padding:4px 8px;font-size:16px;background:#555;" title="Node Info" onclick="openNodeInfoModal(\'' + n.id + '\')">⋮</button>';
            html += '</td></tr>';
        });
        html += '</tbody></table>';
        c.innerHTML = html;
    } catch(e) { c.innerHTML = '<div style="color:#d32f2f;padding:16px;">Failed to load nodes: ' + e.message + '</div>'; }
}

function promptAddNode() {
    const existing = document.getElementById('_addNodeChoiceModal');
    if (existing) existing.remove();
    const modal = document.createElement('div');
    modal.id = '_addNodeChoiceModal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45)';
    modal.innerHTML = [
        '<div style="background:#fff;border-radius:8px;padding:28px 24px;min-width:320px;max-width:92vw;box-shadow:0 8px 32px rgba(0,0,0,0.2)">',
        '<div style="font-size:16px;font-weight:600;margin-bottom:8px">Add Storage Node</div>',
        '<div style="font-size:13px;color:#666;margin-bottom:20px">How would you like to add the node?</div>',
        '<div style="display:flex;flex-direction:column;gap:10px">',
        '<button id="_anc-manual" style="padding:12px 16px;border:1px solid #ddd;border-radius:6px;background:#f9f9f9;cursor:pointer;font-size:14px;text-align:left;">',
        '<strong>[edit] Manual</strong><br><span style="font-size:12px;color:#888;">Enter IP, port and name manually</span></button>',
        '<button id="_anc-quick" style="padding:12px 16px;border:none;border-radius:6px;background:#1a1a1a;color:#fff;cursor:pointer;font-size:14px;text-align:left;">',
        '<strong>[flash] Quick Setup</strong><br><span style="font-size:12px;color:#aaa;">Generate a one-line setup command for the remote node</span></button>',
        '</div>',
        '<div style="margin-top:14px;text-align:right;"><button onclick="document.getElementById(\'_addNodeChoiceModal\').remove()" style="padding:6px 14px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:13px">Cancel</button></div>',
        '</div>'
    ].join('');
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    document.getElementById('_anc-manual').onclick = () => { modal.remove(); openNodeModal(null); };
    document.getElementById('_anc-quick').onclick = () => { modal.remove(); openQuickSetupModal(); };
}

function openQuickSetupModal() {
    const existing = document.getElementById('_quickSetupModal');
    if (existing) existing.remove();
    // Detect current origin as the main node URL
    const mainURL = window.location.origin;
    const modal = document.createElement('div');
    modal.id = '_quickSetupModal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45)';
    modal.innerHTML = [
        '<div style="background:#fff;border-radius:8px;padding:28px 24px;min-width:360px;max-width:96vw;box-shadow:0 8px 32px rgba(0,0,0,0.2)">',
        '<div style="font-size:16px;font-weight:600;margin-bottom:16px">[flash] Quick Node Setup</div>',
        '<div style="margin-bottom:12px;">',
        '<label style="font-size:13px;color:#555;">Binary filename (leave blank for <code>snd-archive</code>)</label>',
        '<input id="_qs-filename" type="text" placeholder="snd-archive" style="width:100%;padding:8px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;margin-top:6px;box-sizing:border-box;">',
        '</div>',
        '<div style="margin-bottom:16px;">',
        '<label style="font-size:13px;color:#555;">Private key (AES-256) — leave blank to auto-generate</label>',
        '<input id="_qs-key" type="text" placeholder="auto-generate" style="width:100%;padding:8px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;margin-top:6px;box-sizing:border-box;font-family:monospace;">',
        '</div>',
        '<button id="_qs-gen" style="padding:9px 20px;border:none;border-radius:4px;background:#1a1a1a;color:#fff;cursor:pointer;font-size:14px;margin-bottom:16px;">Generate command</button>',
        '<div id="_qs-result" style="display:none;">',
        '<label style="font-size:13px;color:#555;margin-bottom:6px;display:block;">Run this on the remote node:</label>',
        '<div style="position:relative;">',
        '<pre id="_qs-cmd" style="background:#111;color:#0f0;padding:14px;border-radius:6px;font-size:12px;word-break:break-all;white-space:pre-wrap;margin:0;overflow-x:auto;"></pre>',
        '<button onclick="navigator.clipboard.writeText(document.getElementById(\'_qs-cmd\').textContent).then(()=>showToast(\'Copied!\'))" style="position:absolute;top:6px;right:6px;padding:3px 10px;font-size:11px;border:none;border-radius:3px;background:#333;color:#fff;cursor:pointer;">Copy</button>',
        '</div>',
        '<div style="font-size:12px;color:#888;margin-top:8px;">The remote node will send this key to <strong>' + mainURL + '/api/v9/connect</strong> and receive a public key in return. It will then auto-connect on every restart.</div>',
        '</div>',
        '<div style="margin-top:16px;text-align:right;">',
        '<button onclick="document.getElementById(\'_quickSetupModal\').remove()" style="padding:7px 16px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:13px">Close</button>',
        '</div>',
        '</div>'
    ].join('');
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });

    document.getElementById('_qs-gen').onclick = () => {
        const bin  = (document.getElementById('_qs-filename').value.trim() || 'snd-archive').replace(/[^\w\-\.]/g, '');
        let   key  = document.getElementById('_qs-key').value.trim();
        if (!key) {
            // generate 32-byte hex key (AES-256)
            const arr = new Uint8Array(32);
            crypto.getRandomValues(arr);
            key = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
            document.getElementById('_qs-key').value = key;
        }
        const cmd = './' + bin + ' --cf --key ' + key + ' --node ' + mainURL;
        document.getElementById('_qs-cmd').textContent = cmd;
        document.getElementById('_qs-result').style.display = 'block';
    };
}

async function openNodeInfoModal(nodeId) {
    const existing = document.getElementById('_nodeInfoModal');
    if (existing) existing.remove();
    const modal = document.createElement('div');
    modal.id = '_nodeInfoModal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45)';
    modal.innerHTML = [
        '<div style="background:#fff;border-radius:8px;padding:28px 24px;min-width:340px;max-width:96vw;box-shadow:0 8px 32px rgba(0,0,0,0.2);max-height:90vh;overflow-y:auto">',
        '<div style="font-size:16px;font-weight:600;margin-bottom:4px">Node Info</div>',
        '<div id="_ni-body" style="font-size:13px;color:#555;margin-top:12px;">',
        '<div style="display:flex;align-items:center;gap:8px;color:#888;"><div class="snd-skel" style="width:100%;height:14px;border-radius:3px"></div></div>',
        '</div>',
        '<div style="margin-top:20px;text-align:right;"><button onclick="document.getElementById(\'_nodeInfoModal\').remove()" style="padding:7px 16px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:13px">Close</button></div>',
        '</div>'
    ].join('');
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });

    try {
        const res = await fetch('/admin/nodes/info?id=' + encodeURIComponent(nodeId));
        const d = await res.json();
        const fmtBytes = b => {
            if (!b) return '0 B';
            const u = ['B','KB','MB','GB','TB','PB'], i = Math.min(5, Math.floor(Math.log2(Math.max(b,1))/10));
            return (b / Math.pow(1024,i)).toFixed(i > 1 ? 1 : 0) + ' ' + u[i];
        };
        const fmtUptime = s => {
            if (!s) return '—';
            const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
            return (d > 0 ? d + 'd ' : '') + (h > 0 ? h + 'h ' : '') + m + 'm';
        };
        const row = (label, val, color) => '<div style="display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #f0f0f0;">' +
            '<span style="color:#888;font-size:13px;">' + label + '</span>' +
            '<span style="font-size:13px;font-weight:500;' + (color ? 'color:' + color + ';' : '') + '">' + val + '</span></div>';

        let html = '';
        html += row('Node',    escapeHtml(d.node_name || '—'));
        html += row('IP',      '<code style="font-size:12px;">' + escapeHtml(d.public_ip || d.node_ip || '—') + '</code>');
        html += row('CPU',     (d.cpu_cores || '?') + ' cores @ ' + (d.cpu_percent != null ? d.cpu_percent.toFixed(1) + '%' : '—'),
                    d.cpu_percent > 80 ? '#c62828' : d.cpu_percent > 60 ? '#f57c00' : '#2e7d32');
        const ramUsed = d.ram_used || 0, ramTotal = d.ram_total || 0;
        const ramPct  = ramTotal > 0 ? (ramUsed / ramTotal * 100) : 0;
        html += row('RAM',     fmtBytes(ramUsed) + ' / ' + fmtBytes(ramTotal) + ' (' + ramPct.toFixed(0) + '%)',
                    ramPct > 85 ? '#c62828' : ramPct > 65 ? '#f57c00' : '#2e7d32');
        html += row('Uptime',  fmtUptime(d.uptime_seconds));

        if (d.disks && d.disks.length) {
            html += '<div style="font-size:12px;font-weight:600;color:#555;margin:12px 0 4px;">Physical Disks</div>';
            d.disks.forEach(disk => {
                const pct = disk.total > 0 ? (disk.used / disk.total * 100) : 0;
                const col = pct > 90 ? '#c62828' : pct > 70 ? '#f57c00' : '#2e7d32';
                // Show device name (e.g. /dev/sda1) as title, mount point as subtitle
                const devLabel = disk.device ? escapeHtml(disk.device) : escapeHtml(disk.path);
                const mountLabel = disk.device ? escapeHtml(disk.path) : '';
                html += '<div style="padding:6px 0;border-bottom:1px solid #f5f5f5;">';
                html += '<div style="display:flex;justify-content:space-between;margin-bottom:2px;">';
                html += '<span style="font-size:12px;font-family:monospace;color:#333;font-weight:500;">' + devLabel + '</span>';
                html += '<span style="font-size:12px;color:#333;">' + fmtBytes(disk.used) + ' / ' + fmtBytes(disk.total) + '</span>';
                html += '</div>';
                if (mountLabel) html += '<div style="font-size:11px;color:#888;margin-bottom:4px;">mounted at ' + mountLabel + '</div>';
                else html += '<div style="margin-bottom:4px;"></div>';
                html += '<div style="background:#eee;border-radius:3px;height:5px;overflow:hidden;">';
                html += '<div style="background:' + col + ';width:' + pct.toFixed(1) + '%;height:100%;border-radius:3px;transition:width .3s;"></div></div></div>';
            });
        }

        document.getElementById('_ni-body').innerHTML = html;
    } catch(e) {
        document.getElementById('_ni-body').innerHTML = '<div style="color:#c62828;">Failed to load node info: ' + e.message + '</div>';
    }
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
    if (res.ok) { closeNodeModal(); loadNodes(); showToast(_t('toast_node_saved','Node saved')); }
    else showToast(_t('toast_error_save_node','Failed to save node'));
}

async function deleteNode(id) {
    if (!confirm(_t('confirm_delete_node','Delete this node?'))) return;
    await fetch('/admin/nodes/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id}) });
    loadNodes();
}

async function setPrimaryNode(id, isPrimary) {
    await fetch('/admin/nodes/set-primary', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: isPrimary ? id : ''}) });
    loadNodes();
    showToast(isPrimary ? _t('toast_primary_node_set','Primary node set') : _t('toast_primary_cleared','Primary cleared'));
}

async function setNodeBackup(id, backup) {
    const res = await fetch('/admin/nodes');
    const nodes = await res.json();
    const n = nodes.find(x=>x.id===id);
    if (!n) return;
    n.backup_mode = backup;
    await fetch('/admin/nodes/update', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(n) });
}

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
        html += '<canvas id="ddosChart" width="600" height="200" style="width:100%;height:200px;cursor:crosshair"></canvas>';
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

function formatBytesChart(bytes) {
    if (bytes === 0) return '0 B';
    var units = ['B','KB','MB','GB','TB','PB'];
    var i = Math.floor(Math.log2(Math.max(bytes,1)) / 10);
    i = Math.min(i, units.length - 1);
    var val = bytes / Math.pow(1024, i);
    return (val % 1 === 0 ? val : val.toFixed(val < 10 ? 2 : 1)) + ' ' + units[i];
}

function drawDDoSChart(traffic) {
    var canvas = document.getElementById('ddosChart');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var W = canvas.offsetWidth || (canvas.parentElement && canvas.parentElement.offsetWidth) || 600;
    var H = 200;
    canvas.width  = W * (window.devicePixelRatio || 1);
    canvas.height = H * (window.devicePixelRatio || 1);
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
    ctx.clearRect(0, 0, W, H);

    if (!traffic || !traffic.length) {
        ctx.fillStyle = '#999'; ctx.font = '13px sans-serif'; ctx.textAlign = 'center';
        ctx.fillText('No traffic data', W / 2, H / 2); return;
    }

    var maxBytes = Math.max(1, Math.max.apply(null, traffic.map(function(d) {
        return Math.max(d.upload || 0, d.download || 0);
    })));

    // Choose unit dynamically
    var unitIdx = Math.floor(Math.log2(Math.max(maxBytes, 1)) / 10);
    unitIdx = Math.min(unitIdx, 5);
    var unitNames = ['B','KB','MB','GB','TB','PB'];
    var unitDiv   = Math.pow(1024, unitIdx);
    var unitLabel = unitNames[unitIdx];

    var pad = { l: 52, r: 12, t: 24, b: 36 };
    var cw = W - pad.l - pad.r;
    var ch = H - pad.t - pad.b;
    var barW = cw / traffic.length;

    // Y-axis grid + labels (5 ticks)
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'right';
    for (var tick = 0; tick <= 4; tick++) {
        var yFrac = tick / 4;
        var yPx   = pad.t + ch - yFrac * ch;
        var val   = maxBytes * yFrac / unitDiv;
        var label = (val % 1 === 0 ? val : val.toFixed(val < 10 ? 1 : 0)) + ' ' + unitLabel;
        ctx.fillStyle = '#aaa';
        ctx.fillText(label, pad.l - 4, yPx + 4);
        ctx.strokeStyle = tick === 0 ? '#bbb' : '#ececec';
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(pad.l, yPx); ctx.lineTo(pad.l + cw, yPx); ctx.stroke();
    }

    // Bars
    traffic.forEach(function(d, i) {
        var x   = pad.l + i * barW;
        var upH = ((d.upload   || 0) / maxBytes) * ch;
        var dnH = ((d.download || 0) / maxBytes) * ch;
        ctx.fillStyle = 'rgba(33,150,243,0.75)';
        ctx.fillRect(x + 2, pad.t + ch - upH, barW * 0.45 - 1, upH);
        ctx.fillStyle = 'rgba(76,175,80,0.75)';
        ctx.fillRect(x + barW * 0.5, pad.t + ch - dnH, barW * 0.45 - 1, dnH);
        // X-axis date label (every 2nd or 3rd bar)
        if (traffic.length <= 14 || i % 2 === 0) {
            ctx.fillStyle = '#999'; ctx.font = '9px sans-serif'; ctx.textAlign = 'center';
            ctx.fillText(d.date ? d.date.slice(5) : '', x + barW / 2, H - 6);
        }
    });

    // Axes border
    ctx.strokeStyle = '#ccc'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pad.l, pad.t); ctx.lineTo(pad.l, pad.t + ch); ctx.lineTo(pad.l + cw, pad.t + ch); ctx.stroke();

    // Legend
    ctx.fillStyle = 'rgba(33,150,243,0.75)'; ctx.fillRect(pad.l, 6, 10, 8);
    ctx.fillStyle = '#555'; ctx.font = '10px sans-serif'; ctx.textAlign = 'left'; ctx.fillText('Upload', pad.l + 13, 14);
    ctx.fillStyle = 'rgba(76,175,80,0.75)'; ctx.fillRect(pad.l + 64, 6, 10, 8);
    ctx.fillStyle = '#555'; ctx.fillText('Download', pad.l + 77, 14);

        // Remove old tooltip handler and attach fresh one
    canvas._ddosTraffic = traffic;
    canvas._ddosPad = pad;
    canvas._ddosCh  = ch;
    canvas._ddosMax = maxBytes;
    canvas._ddosBarW = barW;
    if (!canvas._ddosHoverBound) {
        canvas._ddosHoverBound = true;
        canvas.addEventListener('mousemove', function(e) {
            var rect = canvas.getBoundingClientRect();
            var mx   = e.clientX - rect.left;
            var my   = e.clientY - rect.top;
            var _pad  = canvas._ddosPad, _bw = canvas._ddosBarW, _ch = canvas._ddosCh;
            var _max  = canvas._ddosMax, _data = canvas._ddosTraffic;
            if (!_data) return;
            var idx = Math.floor((mx - _pad.l) / _bw);
            var tip = document.getElementById('ddos-chart-tooltip');
            if (idx < 0 || idx >= _data.length || mx < _pad.l || my < _pad.t || my > _pad.t + _ch) {
                if (tip) tip.style.display = 'none'; return;
            }
            var d = _data[idx];
            if (!tip) {
                tip = document.createElement('div');
                tip.id = 'ddos-chart-tooltip';
                tip.style.cssText = 'position:fixed;pointer-events:none;background:rgba(30,30,30,0.92);color:#fff;font-size:12px;padding:7px 11px;border-radius:6px;z-index:9999;line-height:1.6;box-shadow:0 2px 8px rgba(0,0,0,0.3)';
                document.body.appendChild(tip);
            }
            tip.innerHTML = '<strong>' + (d.date || '') + '</strong><br>' +
                '<span style="color:#64b5f6">^ Upload:</span> '   + formatBytesChart(d.upload   || 0) + '<br>' +
                '<span style="color:#81c784">v Download:</span> ' + formatBytesChart(d.download || 0);
            tip.style.display = 'block';
            tip.style.left = (e.clientX + 12) + 'px';
            tip.style.top  = (e.clientY - 10) + 'px';
        });
        canvas.addEventListener('mouseleave', function() {
            var tip = document.getElementById('ddos-chart-tooltip');
            if (tip) tip.style.display = 'none';
        });
    }
}

async function saveDDoSConfig() {
    const enabledEl = document.getElementById('ddos-enabled');
    if (!enabledEl) { showToast(_t('admin_error_ddos_panel','Error: DDoS panel not loaded')); return; }
    const cfg = {
        enabled: enabledEl.checked,
        rate_window_sec: parseInt(document.getElementById('ddos-window').value)||60,
        max_requests_per_window: parseInt(document.getElementById('ddos-max').value)||300,
        ban_duration_min: parseInt(document.getElementById('ddos-ban-dur').value)||60
    };
    const res = await fetch('/admin/ddos/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(cfg) });
    if (res.ok) showToast('DDoS config saved (enabled=' + cfg.enabled + ')');
    else showToast(_t('toast_error_ddos','Failed to save DDoS config'));
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

async function loadAdminSettings() {
    try {
        const res = await fetch('/admin/settings');
        const s = await res.json();
        document.getElementById('as-bg').value = s.background_url||'';
        document.getElementById('as-music').value = s.bg_music_url||'';
        document.getElementById('as-lang').value = s.language||'en';
        document.getElementById('as-allow-theme').checked = !!s.allow_user_theme;
        document.getElementById('as-direct-links').checked = !!s.show_direct_links;
        const hf = document.getElementById('as-hide-footer');
        if (hf) hf.checked = !!s.hide_footer;
        const aq = document.getElementById('as-allow-qr');
        if (aq) { aq.checked = !!s.allow_qr; document.getElementById('as-qr-logo-row').style.display = s.allow_qr ? '' : 'none'; aq.onchange = function() { document.getElementById('as-qr-logo-row').style.display = this.checked ? '' : 'none'; }; }
        const ql = document.getElementById('as-qr-logo');
        if (ql) ql.value = s.qr_logo_url || '';
        const sup = document.getElementById('as-show-user-public');
        if (sup) sup.checked = !!s.show_user_public_on_share;
        const cc = document.getElementById('as-custom-css');
        if (cc) cc.value = s.custom_css||'';
        const et = document.getElementById('as-embed-title');
        if (et) et.value = s.embed_title||'';
        const ed = document.getElementById('as-embed-desc');
        if (ed) ed.value = s.embed_description||'';
        const ei = document.getElementById('as-embed-img');
        if (ei) ei.value = s.embed_image_url||'';
        const el = document.getElementById('as-embed-loader');
        if (el) el.checked = s.embed_loader_enabled !== false; // default true
        applyBgMusic(s.bg_music_url);
    } catch {}
}

async function saveAdminSettings() {
    const s = {
        background_url: document.getElementById('as-bg').value,
        bg_music_url: document.getElementById('as-music').value,
        language: document.getElementById('as-lang').value,
        allow_user_theme: document.getElementById('as-allow-theme').checked,
        show_direct_links: document.getElementById('as-direct-links').checked,
        hide_footer: !!(document.getElementById('as-hide-footer') || {}).checked,
        allow_qr: !!(document.getElementById('as-allow-qr') || {}).checked,
        qr_logo_url: (document.getElementById('as-qr-logo') || {}).value || '',
        show_user_public_on_share: !!(document.getElementById('as-show-user-public') || {}).checked,
        custom_css: (document.getElementById('as-custom-css') || {}).value || '',
        embed_title: (document.getElementById('as-embed-title') || {}).value || '',
        embed_description: (document.getElementById('as-embed-desc') || {}).value || '',
        embed_image_url: (document.getElementById('as-embed-img') || {}).value || '',
        embed_loader_enabled: !!(document.getElementById('as-embed-loader') || {checked:true}).checked
    };
    const res = await fetch('/admin/settings/save', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(s) });
    if (res.ok) {
        applyBgMusic(s.bg_music_url);
        // Apply custom CSS live
        let styleTag = document.getElementById('_adminCustomCSS');
        if (!styleTag) { styleTag = document.createElement('style'); styleTag.id = '_adminCustomCSS'; document.head.appendChild(styleTag); }
        styleTag.textContent = s.custom_css || '';
        showSaveSuccessPopup(_t('toast_settings_saved', 'Settings saved successfully'));
    } else {
        showSaveErrorPopup(_t('toast_error_settings', 'Failed to save settings'));
    }
}

function showSaveSuccessPopup(msg) {
    _showSavePopup(msg, true);
}

function showSaveErrorPopup(msg) {
    _showSavePopup(msg, false);
}

function _showSavePopup(msg, success) {
    const existing = document.getElementById('_savePopup');
    if (existing) existing.remove();
    const popup = document.createElement('div');
    popup.id = '_savePopup';
    const bgColor   = success ? '#e8f5e9' : '#ffebee';
    const borderColor = success ? '#a5d6a7' : '#ef9a9a';
    const iconColor = success ? '#2e7d32' : '#c62828';
    const icon = success ? 'Settings Saved' : 'Save Failed';
    popup.style.cssText = [
        'position:fixed',
        'top:50%',
        'left:50%',
        'transform:translate(-50%,-50%) scale(0.85)',
        'z-index:10000',
        'background:#fff',
        'border-radius:10px',
        'box-shadow:0 8px 40px rgba(0,0,0,0.22)',
        'padding:32px 40px',
        'min-width:280px',
        'max-width:360px',
        'text-align:center',
        'opacity:0',
        'transition:opacity 0.2s,transform 0.2s',
        'pointer-events:auto'
    ].join(';');
    popup.innerHTML =
        '<div style="width:52px;height:52px;border-radius:50%;background:' + bgColor + ';border:2px solid ' + borderColor + ';display:flex;align-items:center;justify-content:center;margin:0 auto 16px;">' +
        '<span style="font-size:22px;color:' + iconColor + ';font-weight:700;">' + (success ? '&#10003;' : '&#10007;') + '</span>' +
        '</div>' +
        '<div style="font-size:16px;font-weight:600;color:#1a1a1a;margin-bottom:6px;">' + icon + '</div>' +
        '<div style="font-size:13px;color:#555;margin-bottom:20px;">' + escapeHtml(msg) + '</div>' +
        '<button id="_savePopupOK" style="padding:8px 28px;background:#1a1a1a;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer;">OK</button>';
    // Backdrop
    const backdrop = document.createElement('div');
    backdrop.id = '_savePopupBackdrop';
    backdrop.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.32);z-index:9999;';
    backdrop.onclick = function() { popup.remove(); backdrop.remove(); };
    document.body.appendChild(backdrop);
    document.body.appendChild(popup);
    requestAnimationFrame(function() {
        popup.style.opacity = '1';
        popup.style.transform = 'translate(-50%,-50%) scale(1)';
    });
    document.getElementById('_savePopupOK').onclick = function() { popup.remove(); backdrop.remove(); };
    // Auto-dismiss after 3s on success
    if (success) {
        setTimeout(function() {
            popup.style.opacity = '0';
            popup.style.transform = 'translate(-50%,-50%) scale(0.85)';
            setTimeout(function() { if (popup.parentNode) popup.remove(); if (backdrop.parentNode) backdrop.remove(); }, 200);
        }, 3000);
    }
}

function applyBgMusic(url) {
    let audio = document.getElementById('bgMusicPlayer');
    if (!url) { if (audio) { audio.pause(); audio.remove(); } return; }
    if (!audio) { audio = document.createElement('audio'); audio.id = 'bgMusicPlayer'; audio.loop = true; audio.volume = 0.3; document.body.appendChild(audio); }
    if (audio.src !== url) { audio.src = url; audio.play().catch(()=>{}); }
}

function escapeHtml(text) { const d = document.createElement('div'); d.textContent = text||''; return d.innerHTML; }

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
        // Show QR row only when admin has enabled QR globally
        const qrRow = document.getElementById('us-qr-row');
        const qrChk = document.getElementById('us-enable-qr');
        if (qrRow && qrChk) {
            qrRow.style.display = data.allow_qr ? '' : 'none';
            qrChk.checked = !!s.enable_qr;
        }
        if (s.bg_music_url) applyBgMusic(s.bg_music_url);
    } catch(e) { console.error('loadUserSettings:', e); }
}

async function saveUserSettings() {
    const s = {
        background_url: document.getElementById('us-bg').value,
        bg_music_url: document.getElementById('us-music').value,
        language: document.getElementById('us-lang').value,
        show_direct_links: document.getElementById('us-direct-links').checked,
        enable_qr: !!(document.getElementById('us-enable-qr') || {}).checked
    };
    const res = await fetch('/user/settings/save', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(s) });
    if (res.ok) { showToast(_t('toast_settings_saved','Settings saved')); applyBgMusic(s.bg_music_url); }
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
    if (!cur || !nw || !cf) { showCpMsg(_t('validation_fields_required','All fields are required.'), false); return; }
    if (nw.length < 6) { showCpMsg('New password must be at least 6 characters.', false); return; }
    if (nw !== cf) { showCpMsg(_t('validation_passwords_no_match','Passwords do not match.'), false); return; }
    btn.disabled = true; btn.textContent = _t('account_saving','Saving...');
    fetch('/user/change-password', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({current_password: cur, new_password: nw}) })
    .then(r => r.json()).then(d => {
        btn.disabled = false; btn.textContent = _t('account_save_password','Save Password');
        if (d.success) { ['cpCurrent','cpNew','cpConfirm'].forEach(id => document.getElementById(id).value=''); showCpMsg(_t('toast_password_changed','Password changed!'), true); showToast(_t('toast_password_changed','Password changed')); }
        else showCpMsg(d.message || _t('toast_error_save','Failed.'), false);
    }).catch(() => { btn.disabled = false; btn.textContent = _t('account_save_password','Save Password'); showCpMsg(_t('toast_error_network','Network error.'), false); });
}

function showCpMsg(text, ok) {
    const msg = document.getElementById('cpMsg');
    msg.textContent = text; msg.className = 'cp-msg ' + (ok ? 'success' : 'error'); msg.style.display = 'block';
}

function toggleToken() { const inp = document.getElementById('tokenInput'); inp.type = inp.type === 'password' ? 'text' : 'password'; }
function copyToken() { navigator.clipboard.writeText(document.getElementById('tokenInput').value); showToast(_t('toast_token_copied','Token copied')); }

function showToast(msg) {
    const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2500);
}

loadUserSettings();

// ─── Security Log ──────────────────────────────────────────────────────────────

const _secEvtLabels = {
    login_fail:   { label: 'Login Fail',    color: '#e65100', bg: '#fff3e0' },
    login_ban:    { label: 'Login Ban',     color: '#b71c1c', bg: '#ffebee' },
    ddos_ban:     { label: 'DDoS Ban',      color: '#880e4f', bg: '#fce4ec' },
    ddos_block:   { label: 'DDoS Block',    color: '#6a1b9a', bg: '#f3e5f5' },
    archive_bomb: { label: 'Archive Bomb',  color: '#1b5e20', bg: '#e8f5e9' },
};

async function loadSecurityLogs() {
    const tbody = document.getElementById('seclogTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6" style="padding:16px;color:#999;">Loading…</td></tr>';
    try {
        const res = await fetch('/admin/security-logs');
        const events = await res.json();
        const filter = (document.getElementById('seclogFilter') || {}).value || '';
        const filtered = filter ? events.filter(e => e.event_type === filter) : events;
        if (!filtered.length) {
            tbody.innerHTML = '<tr><td colspan="6" style="padding:16px;color:#999;">No events' + (filter ? ' for this filter' : '') + '.</td></tr>';
            return;
        }
        tbody.innerHTML = filtered.map(e => {
            const meta = _secEvtLabels[e.event_type] || { label: e.event_type, color: '#555', bg: '#f5f5f5' };
            const time = new Date(e.time).toLocaleString();
            const badge = '<span style="display:inline-block;padding:2px 7px;border-radius:10px;font-size:11px;font-weight:600;background:' + meta.bg + ';color:' + meta.color + ';">' + meta.label + '</span>';
            const allowBtn = (e.event_type === 'login_ban' || e.event_type === 'ddos_ban')
                ? '<button onclick="quickAllow(\'' + escapeHtml(e.ip) + '\')" style="padding:2px 8px;font-size:11px;border:1px solid #4caf50;color:#2e7d32;background:#fff;border-radius:3px;cursor:pointer;" title="Add to Allowlist">Allow</button>'
                : '';
            return '<tr>'
                + '<td style="font-family:monospace;font-size:11px;white-space:nowrap;">' + time + '</td>'
                + '<td style="font-family:monospace;font-weight:500;">' + escapeHtml(e.ip) + '</td>'
                + '<td>' + badge + '</td>'
                + '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(e.reason) + '">' + escapeHtml(e.reason) + '</td>'
                + '<td style="color:#888;">' + escapeHtml(e.username || '—') + '</td>'
                + '<td>' + allowBtn + '</td>'
                + '</tr>';
        }).join('');
    } catch(e) {
        if (tbody) tbody.innerHTML = '<tr><td colspan="6" style="color:#d32f2f;padding:12px;">Failed to load: ' + e.message + '</td></tr>';
    }
}

async function quickAllow(ip) {
    _showAllowModal('Add to Allowlist: ' + ip, ip, '', async (newIp, label) => {
        try {
            const res = await fetch('/admin/allowlist/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: newIp, label: label || '' })
            });
            const d = await res.json();
            if (d.success) { showSaveSuccessPopup('Added ' + newIp + ' to allowlist'); loadSecurityLogs(); }
            else showSaveErrorPopup('Failed: ' + (d.error || 'unknown'));
        } catch(e) { showSaveErrorPopup('Network error'); }
    });
}

// ─── Allowlist ──────────────────────────────────────────────────────────────

async function loadAllowlist() {
    const container = document.getElementById('allowlistContainer');
    if (!container) return;
    container.innerHTML = '<div style="color:#999;padding:16px;">Loading…</div>';
    try {
        const res = await fetch('/admin/allowlist');
        const entries = await res.json();
        if (!entries || !entries.length) {
            container.innerHTML = '<div style="color:#999;padding:16px;">No trusted IPs configured. Click "+ Add IP" to add one.</div>';
            return;
        }
        let html = '<table class="logs-table" style="width:100%;">'
            + '<thead><tr><th>IP / CIDR / Prefix</th><th>Label</th><th>Added</th><th style="width:150px;">Actions</th></tr></thead><tbody>';
        entries.forEach(e => {
            const added = e.created_at ? new Date(e.created_at).toLocaleDateString() : '—';
            html += '<tr>'
                + '<td style="font-family:monospace;font-weight:500;">' + escapeHtml(e.ip) + '</td>'
                + '<td>' + escapeHtml(e.label || '—') + '</td>'
                + '<td style="color:#888;font-size:12px;">' + added + '</td>'
                + '<td style="display:flex;gap:6px;">'
                + '<button class="btn" style="padding:4px 10px;font-size:12px;" onclick="promptEditAllowEntry(\'' + escapeHtml(e.id) + '\',\'' + escapeHtml(e.ip) + '\',\'' + escapeHtml(e.label||'') + '\')">Edit</button>'
                + '<button class="btn" style="padding:4px 10px;font-size:12px;background:#d32f2f;" onclick="deleteAllowEntry(\'' + escapeHtml(e.id) + '\',\'' + escapeHtml(e.ip) + '\')">Delete</button>'
                + '</td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    } catch(e) {
        container.innerHTML = '<div style="color:#d32f2f;padding:12px;">Failed to load: ' + e.message + '</div>';
    }
}

function _showAllowModal(title, ipVal, labelVal, onSave) {
    const existing = document.getElementById('_allowModal');
    if (existing) existing.remove();
    const modal = document.createElement('div');
    modal.id = '_allowModal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45)';
    modal.innerHTML = `
        <div style="background:#fff;border-radius:8px;padding:28px 24px;min-width:340px;max-width:90vw;box-shadow:0 8px 32px rgba(0,0,0,0.2);">
            <div style="font-size:16px;font-weight:600;margin-bottom:16px;">${escapeHtml(title)}</div>
            <label style="font-size:13px;color:#555;display:block;margin-bottom:4px;">IP / CIDR / Prefix</label>
            <input id="_allowIp" type="text" value="${escapeHtml(ipVal)}"
                placeholder="e.g. 203.0.113.42 or 192.168. or 10.0.0.0/8"
                style="width:100%;padding:9px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;box-sizing:border-box;margin-bottom:12px;font-family:monospace;">
            <label style="font-size:13px;color:#555;display:block;margin-bottom:4px;">Label (optional)</label>
            <input id="_allowLabel" type="text" value="${escapeHtml(labelVal)}"
                placeholder="e.g. Office IP, Home server..."
                style="width:100%;padding:9px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;box-sizing:border-box;margin-bottom:18px;">
            <div style="font-size:11px;color:#888;margin-bottom:16px;">
                Supports exact IPs, prefixes (e.g. <code>192.168.</code>), and CIDR blocks.
                Matching IPs bypass DDoS rate-limiting completely.
            </div>
            <div style="display:flex;gap:8px;justify-content:flex-end;">
                <button onclick="document.getElementById('_allowModal').remove()"
                    style="padding:7px 18px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:13px;">Cancel</button>
                <button id="_allowSaveBtn"
                    style="padding:7px 18px;border:none;border-radius:4px;background:#1a1a1a;color:#fff;cursor:pointer;font-size:13px;">Save</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
    document.getElementById('_allowSaveBtn').addEventListener('click', () => {
        const ip = document.getElementById('_allowIp').value.trim();
        const label = document.getElementById('_allowLabel').value.trim();
        if (!ip) { showConfirm('IP is required', null, null, true); return; }
        modal.remove();
        onSave(ip, label);
    });
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    setTimeout(() => { const inp = document.getElementById('_allowIp'); if (inp) inp.focus(); }, 50);
}

function promptAddAllowEntry() {
    _showAllowModal('Add Trusted IP', '', '', async (ip, label) => {
        try {
            const res = await fetch('/admin/allowlist/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, label })
            });
            const d = await res.json();
            if (d.success) { showSaveSuccessPopup('Added ' + ip + ' to allowlist'); loadAllowlist(); }
            else showSaveErrorPopup('Failed: ' + (d.error || 'unknown'));
        } catch(e) { showSaveErrorPopup('Network error'); }
    });
}

function promptEditAllowEntry(id, ip, label) {
    _showAllowModal('Edit Trusted IP', ip, label, async (newIp, newLabel) => {
        try {
            const res = await fetch('/admin/allowlist/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id, ip: newIp, label: newLabel })
            });
            const d = await res.json();
            if (d.success) { showSaveSuccessPopup('Saved changes for ' + newIp); loadAllowlist(); }
            else showSaveErrorPopup('Failed: ' + (d.error || 'unknown'));
        } catch(e) { showSaveErrorPopup('Network error'); }
    });
}

async function deleteAllowEntry(id, ip) {
    showConfirm('Remove ' + ip + ' from allowlist?', async () => {
        try {
            const res = await fetch('/admin/allowlist/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id })
            });
            const d = await res.json();
            if (d.success) { showSaveSuccessPopup('Removed ' + ip + ' from allowlist'); loadAllowlist(); }
            else showSaveErrorPopup('Failed: ' + (d.error || 'unknown'));
        } catch(e) { showSaveErrorPopup('Network error'); }
    });
}
