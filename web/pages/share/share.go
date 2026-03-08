package share

import (
	"net/http"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	embedTitle := snd.Cfg.EmbedTitle
	if embedTitle == "" {
		embedTitle = "Public Files — " + snd.Cfg.SiteName
	}
	embedDesc := snd.Cfg.EmbedDescription
	if embedDesc == "" {
		embedDesc = "File sharing powered by " + snd.Cfg.SiteName
	}
	embedImage := snd.Cfg.EmbedImageURL
	if embedImage == "" {
		embedImage = snd.Cfg.IconURL
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>Public Files - ` + snd.Cfg.SiteName + `</title>
    <meta property="og:title" content="` + embedTitle + `">
    <meta property="og:description" content="` + embedDesc + `">
    <meta property="og:image" content="` + embedImage + `">
    <meta property="og:type" content="website">
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="` + embedTitle + `">
    <meta name="twitter:description" content="` + embedDesc + `">
    <meta name="twitter:image" content="` + embedImage + `">
    <script>
        (function(){
            var s=document.createElement('script');
            s.src='https://cdn.jsdelivr.net/gh/Mytai20100/csa-js@main/csa.js';
            s.onerror=function(){var f=document.createElement('script');f.src='/lib/csa.js';document.head.appendChild(f);};
            document.head.appendChild(s);
        })();
    </script>
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
            grid-template-columns: auto 1fr auto;
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
        .empty-state { text-align: center; padding: 80px 20px; color: #999; }
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

        /* modal for image / text / audio */
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
        /* csa overrides: no bar, orange accent */
        .csa-bar { display: none !important; }
        .csa-progress-fill { background: #e07820 !important; }
        .csa-progress-thumb { background: #e07820 !important; box-shadow: 0 0 10px rgba(224,120,32,.5) !important; }
        .csa-vol-slider::-webkit-slider-thumb { background: #e07820 !important; }
        .csa-btn:hover { color: #ffaa55 !important; }
        .csa-btn.csa-active { color: #e07820 !important; }
        .csa-ldr-ring { border-top-color: #e07820 !important; }

        @media (max-width: 768px) {
            .file-item { grid-template-columns: auto 1fr; }
            .file-actions { justify-content: flex-start; }
            .stats-bar { flex-wrap: wrap; gap: 12px; }
        }

        /* Liquid Glass */
        body.th-liquid .file-item, body.th-liquid .container, body.th-liquid .header, body.th-liquid .modal-content {
            background: rgba(255,255,255,0.08) !important;
            backdrop-filter: blur(24px) saturate(180%) !important;
            -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
            border-color: rgba(255,255,255,0.18) !important;
            box-shadow: 0 8px 32px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.3) !important;
        }
        body.th-liquid .file-item { border-radius: 12px !important; margin-bottom: 4px !important; }
        body.th-liquid .file-name { color: rgba(255,255,255,0.88) !important; }
        body.th-liquid .file-meta, body.th-liquid .stats-bar { color: rgba(255,255,255,0.55) !important; }
        body.th-liquid .file-url { color: rgba(150,200,255,0.75) !important; }
        body.th-liquid h1, body.th-liquid h2, body.th-liquid h3 { color: rgba(255,255,255,0.92) !important; }
        body.th-liquid .action-btn { background: rgba(255,255,255,0.12) !important; border-color: rgba(255,255,255,0.2) !important; color: rgba(255,255,255,0.85) !important; }
        body.th-liquid:not(.th-rainbow):not(.th-dark) { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%) !important; }
        body.th-dark .file-item { background: #181818 !important; border-color: #2a2a2a !important; }
        body.th-dark .header { background: #111 !important; border-color: #2a2a2a !important; }
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
            <div class="empty-state"><div class="title">Loading...</div></div>
        </div>
    </div>

    <!-- modal: image / text / audio -->
    <div class="modal" id="viewModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="viewTitle">View File</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="viewBody"></div>
        </div>
    </div>

    <div class="footer" id="siteFooter">
        <strong>` + snd.Cfg.SiteName + `</strong> — public files — v` + snd.VERSION + `
    </div>

    <script>
        let allFiles = [];
        let filteredFiles = [];

        async function loadPublicFiles() {
            try {
                const res = await fetch('/public-files');
                if (!res.ok) throw new Error();
                const files = await res.json();
                allFiles = files || [];
                filteredFiles = allFiles;
                renderFiles(allFiles);
                updateStats(allFiles);
            } catch {
                document.getElementById('filesSection').innerHTML =
                    '<div class="empty-state"><div class="title">Unable to load files</div></div>';
            }
        }

        function updateStats(files) {
            const totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);
            const totalDownloads = files.reduce((sum, f) => sum + (f.download_count || 0), 0);
            const admFiles = files.filter(f => !f.user_uuid).length;
            const userFiles = files.filter(f => !!f.user_uuid).length;
            document.getElementById('statsBar').innerHTML =
                '<span><strong>' + files.length + '</strong> public files</span>' +
                '<span>Total size: <strong>' + formatFileSize(totalSize) + '</strong></span>' +
                '<span>Downloads: <strong>' + totalDownloads + '</strong></span>' +
                (userFiles > 0 ? '<span>Admin: <strong>' + admFiles + '</strong> &nbsp;|&nbsp; Users: <strong>' + userFiles + '</strong></span>' : '');
        }

        function filterFiles() {
            const q = document.getElementById('searchInput').value.toLowerCase();
            filteredFiles = q ? allFiles.filter(f => (f.name + ' ' + (f.owner||'')).toLowerCase().includes(q)) : allFiles;
            renderFiles(filteredFiles);
        }

        // ── URL builders ─────────────────────────────────────────────────────
        function buildRawUrl(f) {
            if (f.user_uuid && f.raw_path)
                return window.location.origin + '/raw/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid);
            return window.location.origin + '/raw/' + encodeURIComponent(f.name);
        }
        function buildStreamUrl(f) {
            if (f.user_uuid && f.raw_path)
                return '/stream/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid);
            return '/stream/' + encodeURIComponent(f.name);
        }
        function buildApiViewUrl(f) {
            if (f.user_uuid && f.raw_path)
                return '/api/view/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid);
            return '/api/view/' + encodeURIComponent(f.name);
        }
        function buildThumbnailUrl(f) {
            if (f.user_uuid && f.raw_path)
                return '/thumbnail/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid);
            return '/thumbnail/' + encodeURIComponent(f.name);
        }
        function buildDownloadUrl(f) {
            if (f.user_uuid && f.raw_path)
                return '/download/' + encodeURIComponent(f.raw_path) + '?u=' + f.user_uuid;
            return '/download/' + encodeURIComponent(f.name);
        }

        // ── Render ────────────────────────────────────────────────────────────
        function renderFiles(files) {
            const section = document.getElementById('filesSection');
            if (!files.length) {
                section.innerHTML = '<div class="empty-state"><div class="title">No public files available</div><div class="subtitle">Files marked as public will appear here.</div></div>';
                return;
            }
            const badgeColors = {
                text:    'background:#e8f5e9;color:#2e7d32',
                image:   'background:#e3f2fd;color:#1976d2',
                video:   'background:#fce4ec;color:#c2185b',
                audio:   'background:#f3e5f5;color:#7b1fa2',
                archive: 'background:#fff3e0;color:#f57c00',
                document:'background:#ffebee;color:#d32f2f',
            };
            setPreviewFiles(files);
            section.innerHTML = files.map((f, idx) => {
                const rawUrl = buildRawUrl(f);
                const modDate = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';
                const typeBadge = badgeColors[f.type] || 'background:#f5f5f5;color:#616161';

                // Owner badge: green for user files, blue for admin
                const isUser = !!f.user_uuid;
                const ownerBadge = f.owner
                    ? (isUser
                        ? '<span class="file-type-badge" style="background:#e8f5e9;color:#2e7d32;margin-left:4px;">' + escapeHtml(f.owner) + '</span>'
                        : '<span class="file-type-badge" style="background:#e8eaf6;color:#3949ab;margin-left:4px;">admin</span>')
                    : '';

                const previewBtn = ['image','text','video','audio'].includes(f.type)
                    ? '<button class="action-btn" onclick="openPreviewByIdx(' + idx + ')">Preview</button>'
                    : '';

                const thumbHtml = (f.type === 'image' || f.type === 'video')
                    ? '<div onclick="openPreviewByIdx(' + idx + ')" style="cursor:pointer;width:72px;height:72px;border-radius:8px;overflow:hidden;flex-shrink:0;background:#f0f0f0;">' +
                      '<img src="' + buildThumbnailUrl(f) + '" loading="lazy" alt="" style="width:100%;height:100%;object-fit:cover;" ' +
                      'onerror="this.style.display=\'none\';this.parentNode.style.cssText+=\'background:#f5f5f5;background-image:url(/icons/' + f.type + '.svg);background-repeat:no-repeat;background-position:center;background-size:36px\'">' +
                      '</div>'
                    : '<div onclick="openPreviewByIdx(' + idx + ')" style="cursor:pointer;width:72px;height:72px;border-radius:8px;background:#f5f5f5;display:flex;align-items:center;justify-content:center;flex-shrink:0;">' +
                      '<img src="/icons/' + f.type + '.svg" style="width:36px;height:36px;opacity:0.55;" onerror="this.src=\'/icons/file.svg\'">' +
                      '</div>';

                return '<div class="file-item">' +
                    thumbHtml +
                    '<div class="file-info">' +
                    '<div class="file-name">' + escapeHtml(f.name) +
                    '<span class="file-type-badge" style="' + typeBadge + '">' + f.type + '</span>' +
                    ownerBadge + '</div>' +
                    '<div class="file-meta">' + formatFileSize(f.size) + ' &middot; ' + modDate +
                    (f.download_count > 0 ? ' &middot; ' + f.download_count + ' downloads' : '') + '</div>' +
                    '<div class="file-url" onclick="copyFileLink(' + idx + ')" title="Click to copy">' + escapeHtml(rawUrl) + '</div>' +
                    '</div>' +
                    '<div class="file-actions">' +
                    previewBtn +
                    '<a href="' + buildDownloadUrl(f) + '" class="action-btn">Download</a>' +
                    '<button class="action-btn" onclick="copyFileLink(' + idx + ')">Copy link</button>' +
                    '</div></div>';
            }).join('');
        }

        function copyFileLink(idx) {
            const f = filteredFiles[idx];
            if (!f) return;
            navigator.clipboard.writeText(buildRawUrl(f))
                .then(() => showToast('Link copied!'))
                .catch(() => showToast('Failed to copy'));
        }

        // ── Preview modal ─────────────────────────────────────────────────────
        let _shareFiles = [];
        let _shareIdx = -1;
        function setPreviewFiles(files) { _shareFiles = files; }

        function openPreviewByIdx(idx) {
            _shareIdx = idx;
            const f = _shareFiles[idx];
            if (f) showPreview(f);
        }

        function showPreview(f) {
            const streamUrl = buildStreamUrl(f);
            const apiViewUrl = buildApiViewUrl(f);
            const baseName = f.name.split('/').pop();
            const navBtns = '<div style="text-align:center;margin-top:12px;">' +
                '<button class="action-btn" onclick="advancePreview(-1)">&#8592; Prev</button> ' +
                '<button class="action-btn" onclick="advancePreview(1)">Next &#8594;</button></div>';

            document.getElementById('viewTitle').textContent = baseName;

            if (f.type === 'image') {
                document.getElementById('viewBody').innerHTML =
                    '<div style="text-align:center;padding:8px;">' +
                    '<img src="' + apiViewUrl + '" style="max-width:100%;max-height:70vh;object-fit:contain;" alt="' + escapeHtml(baseName) + '">' +
                    '</div>' + navBtns;
                document.getElementById('viewModal').style.display = 'block';
                return;
            }
            if (f.type === 'video' || f.type === 'audio') {
                const ext = f.name.split('.').pop().toLowerCase();
                let playerHtml;
                if (ext === 'm3u8') {
                    playerHtml = '<video id="hlsPlayer" controls autoplay playsinline style="width:100%;max-height:70vh;background:#000;"></video>' +
                        '<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"><\/script>' +
                        '<script>(function(){var v=document.getElementById(\"hlsPlayer\");if(Hls.isSupported()){var h=new Hls();h.loadSource(\"' + streamUrl + '\");h.attachMedia(v);v.play().catch(()=>{});}else if(v.canPlayType(\"application/vnd.apple.mpegurl\")){v.src=\"' + streamUrl + '\";v.play().catch(()=>{});}v.addEventListener(\"ended\",function(){advancePreview(1);});})();<\/script>';
                } else {
                    const tag = f.type === 'audio' ? 'audio' : 'video';
                    playerHtml = '<' + tag + ' controls autoplay playsinline style="width:100%;max-height:70vh;" onended="advancePreview(1)"><source src="' + streamUrl + '"></' + tag + '>';
                }
                document.getElementById('viewBody').innerHTML = playerHtml + navBtns;
                document.getElementById('viewModal').style.display = 'block';
                return;
            }
            if (f.type === 'text') {
                fetch(buildRawUrl(f)).then(r => r.text()).then(c => {
                    document.getElementById('viewBody').innerHTML =
                        '<pre style="background:#fafafa;padding:16px;border-radius:4px;border:1px solid #e0e0e0;font-family:monospace;font-size:13px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;">' + escapeHtml(c) + '</pre>';
                    document.getElementById('viewModal').style.display = 'block';
                });
                return;
            }
        }

        function advancePreview(dir) {
            if (!_shareFiles.length) return;
            const previewable = ['image','video','audio','text'];
            let next = _shareIdx + dir;
            while (next >= 0 && next < _shareFiles.length) {
                if (previewable.includes(_shareFiles[next].type)) break;
                next += dir;
            }
            if (next < 0 || next >= _shareFiles.length) return;
            _shareIdx = next;
            showPreview(_shareFiles[next]);
        }

        loadPublicFiles();
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}