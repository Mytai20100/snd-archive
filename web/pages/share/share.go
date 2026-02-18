package share

import (
	"net/http"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>Public Files - ` + snd.Cfg.SiteName + `</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #fafafa;
            color: #1a1a1a;
            line-height: 1.6;
            padding-bottom: 60px;
        }
        .container { max-width: 1000px; margin: 0 auto; background: #fff; }
        .header {
            background: #fff;
            border-bottom: 1px solid #e0e0e0;
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
        .header h1 { font-size: 20px; font-weight: 500; }
        .header-sub { font-size: 13px; color: #888; margin-top: 2px; }
        .header-actions { display: flex; gap: 8px; align-items: center; }
        .btn {
            padding: 8px 16px;
            background: #1a1a1a;
            color: white;
            text-decoration: none;
            border: none;
            cursor: pointer;
            font-size: 13px;
            display: inline-block;
        }
        .btn:hover { background: #333; }

        .search-bar {
            padding: 16px 20px;
            border-bottom: 1px solid #e0e0e0;
            background: #fafafa;
        }
        .search-bar input {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #d0d0d0;
            font-size: 14px;
            outline: none;
            border-radius: 4px;
        }
        .search-bar input:focus { border-color: #1a1a1a; }

        .files-section { padding: 20px; }
        .file-item {
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 12px;
            align-items: center;
            padding: 16px 12px;
            border-bottom: 1px solid #f0f0f0;
            transition: background 0.15s;
        }
        .file-item:hover { background: #fafafa; }
        .file-info { min-width: 0; }
        .file-name {
            font-size: 14px;
            font-weight: 500;
            color: #1a1a1a;
            margin-bottom: 4px;
            word-break: break-word;
        }
        .file-type-badge {
            display: inline-block;
            padding: 2px 7px;
            font-size: 10px;
            background: #e0e0e0;
            color: #666;
            border-radius: 3px;
            margin-left: 6px;
            text-transform: uppercase;
        }
        .file-meta { font-size: 11px; color: #999; margin-top: 4px; }
        .file-url {
            font-size: 11px;
            color: #0066cc;
            margin-top: 4px;
            font-family: monospace;
            word-break: break-all;
            cursor: pointer;
        }
        .file-url:hover { text-decoration: underline; }
        .file-actions { display: flex; gap: 8px; flex-shrink: 0; }
        .action-btn {
            padding: 7px 12px;
            background: white;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            color: #1a1a1a;
            text-decoration: none;
            white-space: nowrap;
        }
        .action-btn:hover { background: #fafafa; border-color: #1a1a1a; }

        .empty-state {
            text-align: center;
            padding: 80px 20px;
            color: #999;
        }
        .empty-state .title { font-size: 18px; margin-bottom: 8px; color: #555; }
        .empty-state .subtitle { font-size: 14px; }

        .stats-bar {
            padding: 12px 20px;
            background: #f5f5f5;
            border-bottom: 1px solid #e0e0e0;
            font-size: 13px;
            color: #666;
            display: flex;
            gap: 24px;
        }
        .stats-bar strong { color: #1a1a1a; }

        .footer {
            position: fixed;
            bottom: 0; left: 0; right: 0;
            background: #fff;
            border-top: 1px solid #e0e0e0;
            padding: 10px;
            text-align: center;
            font-size: 12px;
            color: #666;
            z-index: 100;
        }
        .footer strong { color: #1a1a1a; font-weight: 500; }

        .toast {
            position: fixed;
            top: 20px; right: 20px;
            padding: 14px 20px;
            background: #1a1a1a;
            color: white;
            border-radius: 4px;
            font-size: 14px;
            z-index: 2000;
            animation: slideIn 0.3s ease;
        }
        .toast.success { background: #2e7d32; }
        @keyframes slideIn { from { transform: translateX(400px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            overflow-y: auto;
        }
        .modal-content {
            position: relative;
            margin: 40px auto;
            background: white;
            width: 90%;
            max-width: 900px;
            max-height: calc(100vh - 80px);
            display: flex;
            flex-direction: column;
            border-radius: 8px;
        }
        .modal-header {
            padding: 20px 24px;
            background: #fafafa;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-radius: 8px 8px 0 0;
        }
        .modal-header h3 { font-size: 16px; font-weight: 500; }
        .modal-body { flex: 1; overflow: auto; padding: 24px; }
        .close-btn {
            background: none; border: none; color: #666; font-size: 24px; cursor: pointer;
            width: 32px; height: 32px; display: flex; align-items: center; justify-content: center;
        }
        .close-btn:hover { color: #1a1a1a; }
        .media-viewer {
            background: #000;
            min-height: 300px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 4px;
        }
        .media-viewer img { max-width: 100%; max-height: 65vh; object-fit: contain; }
        .media-viewer video, .media-viewer audio { max-width: 100%; outline: none; }

        @media (max-width: 768px) {
            .file-item { grid-template-columns: 1fr; }
            .file-actions { justify-content: flex-start; }
            .stats-bar { flex-wrap: wrap; gap: 12px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>` + snd.Cfg.SiteName + `</h1>
                <div class="header-sub">Public Files</div>
            </div>
            <div class="header-actions">
                <a href="/ac" class="btn">Login</a>
            </div>
        </div>

        <div class="search-bar">
            <input type="text" id="searchInput" placeholder="Search public files..." autocomplete="off" oninput="filterFiles()">
        </div>

        <div class="stats-bar" id="statsBar">
            <span>Loading...</span>
        </div>

        <div class="files-section" id="filesSection">
            <div class="empty-state">
                <div class="title">Loading...</div>
            </div>
        </div>
    </div>

    <!-- View Modal -->
    <div class="modal" id="viewModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="viewTitle">View File</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="viewBody"></div>
        </div>
    </div>

    <div class="footer">
        <strong>ServerNotDie</strong> v` + snd.VERSION + `
    </div>

    <script>
        let allFiles = [];
        let filteredFiles = [];

        async function loadPublicFiles() {
            try {
                const res = await fetch('/files');
                if (!res.ok) throw new Error();
                const data = await res.json();
                const files = (data.files || []).filter(f => f.is_public);
                allFiles = files;
                filteredFiles = files;
                renderFiles(files);
                updateStats(files);
            } catch {
                document.getElementById('filesSection').innerHTML =
                    '<div class="empty-state"><div class="title">Unable to load files</div></div>';
            }
        }

        function updateStats(files) {
            const totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);
            const totalDownloads = files.reduce((sum, f) => sum + (f.download_count || 0), 0);
            document.getElementById('statsBar').innerHTML =
                '<span><strong>' + files.length + '</strong> public files</span>' +
                '<span>Total size: <strong>' + formatFileSize(totalSize) + '</strong></span>' +
                '<span>Total downloads: <strong>' + totalDownloads + '</strong></span>';
        }

        function filterFiles() {
            const q = document.getElementById('searchInput').value.toLowerCase();
            filteredFiles = q ? allFiles.filter(f => f.name.toLowerCase().includes(q)) : allFiles;
            renderFiles(filteredFiles);
        }

        function renderFiles(files) {
            const section = document.getElementById('filesSection');
            if (!files.length) {
                section.innerHTML = '<div class="empty-state"><div class="title">No public files available</div><div class="subtitle">Files marked as public by the administrator will appear here.</div></div>';
                return;
            }

            const badgeStyles = {
                text:    'background:#e8f5e9;color:#2e7d32',
                image:   'background:#e3f2fd;color:#1976d2',
                video:   'background:#fce4ec;color:#c2185b',
                audio:   'background:#f3e5f5;color:#7b1fa2',
                archive: 'background:#fff3e0;color:#f57c00',
                document:'background:#ffebee;color:#d32f2f',
            };

            section.innerHTML = files.map(f => {
                const rawUrl = window.location.origin + '/raw/' + encodeURIComponent(f.name);
                const esc = f.name.replace(/'/g, "\\'");
                const badgeStyle = badgeStyles[f.type] || 'background:#f5f5f5;color:#616161';
                const modDate = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';

                let previewBtn = '';
                if (f.type === 'image' || f.type === 'text' || f.type === 'video' || f.type === 'audio') {
                    previewBtn = '<button class="action-btn" onclick="viewFile(\'' + esc + '\',\'' + f.type + '\')">Preview</button>';
                }

                return '<div class="file-item">' +
                    '<div class="file-info">' +
                    '<div class="file-name">' + escapeHtml(f.name) +
                    '<span class="file-type-badge" style="' + badgeStyle + '">' + f.type + '</span>' +
                    '</div>' +
                    '<div class="file-meta">' + formatFileSize(f.size) + ' - ' + modDate +
                    (f.download_count > 0 ? ' - ' + f.download_count + ' downloads' : '') +
                    '</div>' +
                    '<div class="file-url" onclick="copyLink(\'' + esc + '\')" title="Click to copy">' + escapeHtml(rawUrl) + '</div>' +
                    '</div>' +
                    '<div class="file-actions">' +
                    previewBtn +
                    '<a href="/download/' + encodeURIComponent(f.name) + '" class="action-btn">Download</a>' +
                    '<button class="action-btn" onclick="copyLink(\'' + esc + '\')">Copy link</button>' +
                    '</div>' +
                    '</div>';
            }).join('');
        }

        function copyLink(filename) {
            const url = window.location.origin + '/raw/' + encodeURIComponent(filename);
            navigator.clipboard.writeText(url)
                .then(() => showToast('Link copied!'))
                .catch(() => showToast('Failed to copy'));
        }

        function viewFile(filename, type) {
            const url = '/raw/' + encodeURIComponent(filename);
            const viewBody = document.getElementById('viewBody');
            document.getElementById('viewTitle').textContent = filename;

            if (type === 'text') {
                fetch(url).then(r => r.text()).then(c => {
                    viewBody.innerHTML = '<pre style="background:#fafafa;padding:16px;border-radius:4px;border:1px solid #e0e0e0;font-family:monospace;font-size:13px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;">' + escapeHtml(c) + '</pre>';
                    document.getElementById('viewModal').style.display = 'block';
                });
            } else if (type === 'image') {
                viewBody.innerHTML = '<div class="media-viewer"><img src="' + url + '" alt="' + escapeHtml(filename) + '"></div>';
                document.getElementById('viewModal').style.display = 'block';
            } else if (type === 'video') {
                viewBody.innerHTML = '<div class="media-viewer"><video controls autoplay playsinline style="width:100%;max-height:70vh;"><source src="/stream/' + encodeURIComponent(filename) + '">Video playback not supported.</video></div>';
                document.getElementById('viewModal').style.display = 'block';
            } else if (type === 'audio') {
                viewBody.innerHTML = '<div class="media-viewer" style="background:#fff;"><audio controls autoplay style="width:100%;"><source src="' + url + '"></audio></div>';
                document.getElementById('viewModal').style.display = 'block';
            }
        }

        function closeModal() {
            document.getElementById('viewModal').style.display = 'none';
            document.querySelectorAll('video').forEach(v => v.pause());
            document.querySelectorAll('audio').forEach(a => a.pause());
        }
        window.onclick = function(e) { if (e.target.classList.contains('modal')) closeModal(); };

        function showToast(msg) {
            const t = document.createElement('div');
            t.className = 'toast success';
            t.textContent = msg;
            document.body.appendChild(t);
            setTimeout(() => t.remove(), 3000);
        }

        function escapeHtml(text) {
            const d = document.createElement('div');
            d.textContent = text;
            return d.innerHTML;
        }

        function formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1048576) return (bytes/1024).toFixed(2) + ' KB';
            if (bytes < 1073741824) return (bytes/1048576).toFixed(2) + ' MB';
            return (bytes/1073741824).toFixed(2) + ' GB';
        }

        loadPublicFiles();
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
