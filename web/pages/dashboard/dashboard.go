package dashboard

import (
	"fmt"
	"net/http"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		snd.RenderErrorPage(w, http.StatusNotFound, "Page Not Found",
			"The page you're looking for doesn't exist.", "Path: "+r.URL.Path)
		return
	}

	// Sub-users always belong in /my — redirect immediately
	if su := snd.GetSessionUser(r); su != nil {
		http.Redirect(w, r, "/my", http.StatusSeeOther)
		return
	}

	isAuth := snd.IsAuthenticated(r)
	isAdminUser := snd.IsAdminAuthenticated(r)
	authStatus := "false"
	authButtons := `<a href="/ac" class="btn" data-i18n="nav_login">Login</a>`
	uploadSectionDisplay := "none"
	apiTokenSection := ""

	if isAuth {
		authStatus = "true"
		// Only admin reaches here (sub-users are redirected to /my above)
		authButtons = `<button class="btn" onclick="openCreateFolderModal()" data-i18n="nav_new_folder">New Folder</button>
                       <a href="/ad" class="btn" data-i18n="nav_admin">Admin</a>
                       <a href="#" onclick="logout(); return false;" class="btn" data-i18n="nav_logout">Logout</a>`
		_ = isAdminUser
		uploadSectionDisplay = "block"
		apiTokenSection = fmt.Sprintf(`
        <div class="upload-section" id="apiTokenSection" style="background:#fff3e0;border:2px solid #f57c00;position:relative;">
            <button onclick="closeApiTokenSection()" style="position:absolute;top:8px;right:8px;background:none;border:none;font-size:20px;color:#e65100;cursor:pointer;width:28px;height:28px;display:flex;align-items:center;justify-content:center;" title="Hide">&times;</button>
            <div style="padding:12px;">
                <div style="font-size:13px;font-weight:500;color:#e65100;margin-bottom:8px;">API Token</div>
                <div style="display:flex;gap:8px;align-items:center;">
                    <input type="password" id="apiTokenDisplay" value="%s" readonly
                           style="flex:1;padding:8px;border:1px solid #f57c00;font-family:monospace;font-size:12px;">
                    <button class="btn" onclick="toggleTokenVisibility()">Show</button>
                    <button class="btn" onclick="copyToken()">Copy</button>
                </div>
                <div style="font-size:11px;color:#e65100;margin-top:8px;">
                    Token is automatically added to file URLs.
                </div>
            </div>
        </div>`, snd.Cfg.APIToken)
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <title>` + snd.Cfg.SiteName + `</title>
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
        .header-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .keyboard-hint { font-size: 11px; color: #999; white-space: nowrap; }
        .btn {
            padding: 8px 16px;
            background: #1a1a1a;
            color: white;
            text-decoration: none;
            border: none;
            cursor: pointer;
            font-size: 13px;
            display: inline-block;
            white-space: nowrap;
        }
        .btn:hover { background: #333; }
        .upload-section {
            padding: 24px 20px;
            border-bottom: 1px solid #e0e0e0;
            display: ` + uploadSectionDisplay + `;
        }
        .upload-area {
            position: relative;
            width: 100%;
            min-height: 100px;
            border: 2px dashed #d0d0d0;
            background: #fafafa;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            border-radius: 4px;
            transition: border-color 0.2s;
        }
        .upload-area:hover, .upload-area.dragover { border-color: #1a1a1a; }
        .upload-area input[type="file"] { position: absolute; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
        .upload-text { text-align: center; color: #666; font-size: 14px; pointer-events: none; }
        .selected-files {
            margin-top: 12px;
            padding: 12px;
            background: #f5f5f5;
            border: 1px solid #e0e0e0;
            font-size: 13px;
            color: #666;
            max-height: 120px;
            overflow-y: auto;
            display: none;
        }
        .upload-btn {
            margin-top: 12px;
            width: 100%;
            padding: 11px;
            background: #1a1a1a;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 14px;
        }
        .upload-btn:hover { background: #333; }
        .upload-btn:disabled { background: #ccc; cursor: not-allowed; }
        .progress-section {
            padding: 20px;
            display: none;
            background: #fafafa;
            border-bottom: 1px solid #e0e0e0;
        }
        .progress-bar { width: 100%; height: 4px; background: #e0e0e0; }
        .progress-fill { height: 100%; background: #1a1a1a; width: 0%; transition: width 0.3s; }
        .progress-info { display: flex; justify-content: space-between; margin-top: 10px; font-size: 13px; color: #666; }
        .bulk-actions {
            display: none;
            padding: 14px 20px;
            background: #f5f5f5;
            border-bottom: 1px solid #e0e0e0;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }
        .bulk-actions.active { display: flex; }
        .files-section { padding: 20px; }
        .file-item {
            display: grid;
            grid-template-columns: auto auto 1fr auto;
            gap: 12px;
            align-items: start;
            padding: 14px 12px;
            border-bottom: 1px solid #f0f0f0;
            transition: background 0.15s;
        }
        .file-item > input[type="checkbox"] { margin-top: 28px; }
        .file-item .file-actions { padding-top: 4px; }
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
        .file-link { font-size: 11px; color: #0066cc; margin-top: 4px; font-family: monospace; word-break: break-all; cursor: pointer; }
        .file-link:hover { text-decoration: underline; }
        .file-actions { display: flex; gap: 8px; flex-shrink: 0; position: relative; }
        .menu-btn {
            padding: 6px 12px;
            background: white;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            min-width: 36px;
            height: 36px;
        }
        .menu-btn:hover { background: #fafafa; border-color: #1a1a1a; }
        .context-menu {
            display: none;
            position: absolute;
            top: 100%;
            right: 0;
            background: white;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.12);
            min-width: 180px;
            z-index: 1000;
            margin-top: 4px;
        }
        .context-menu.show { display: block; }
        .context-menu-item {
            padding: 11px 16px;
            cursor: pointer;
            font-size: 13px;
            border-bottom: 1px solid #f0f0f0;
        }
        .context-menu-item:last-child { border-bottom: none; }
        .context-menu-item:hover { background: #fafafa; }
        .context-menu-item.danger { color: #d32f2f; }
        .context-menu-item.danger:hover { background: #ffebee; }
        .btn-small {
            padding: 7px 14px;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            background: white;
            cursor: pointer;
            font-size: 13px;
            color: #1a1a1a;
            white-space: nowrap;
        }
        .btn-small:hover { background: #fafafa; border-color: #1a1a1a; }
        .checkbox { width: 18px; height: 18px; cursor: pointer; flex-shrink: 0; }
        .empty-state { text-align: center; padding: 60px 20px; color: #999; font-size: 14px; }
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
        .modal-header h3 { font-size: 16px; font-weight: 500; word-break: break-word; padding-right: 16px; }
        .modal-body { flex: 1; overflow: auto; padding: 24px; }
        .modal-footer {
            padding: 16px 24px;
            background: #fafafa;
            border-top: 1px solid #e0e0e0;
            display: flex;
            gap: 8px;
            justify-content: flex-end;
            border-radius: 0 0 8px 8px;
        }
        .close-btn {
            background: none;
            border: none;
            color: #666;
            font-size: 24px;
            cursor: pointer;
            width: 32px; height: 32px;
            display: flex; align-items: center; justify-content: center;
            flex-shrink: 0;
        }
        .close-btn:hover { color: #1a1a1a; }
        textarea {
            width: 100%;
            min-height: 300px;
            padding: 16px;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            font-family: 'SF Mono', monospace;
            font-size: 13px;
            resize: vertical;
            line-height: 1.6;
        }
        textarea:focus { border-color: #1a1a1a; outline: none; }
        pre {
            background: #fafafa;
            padding: 16px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 13px;
            font-family: 'SF Mono', monospace;
            line-height: 1.6;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
        }
        .media-viewer {
            text-align: center;
            background: #000;
            position: relative;
            min-height: 300px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: auto;
            border-radius: 4px;
            cursor: default;
        }
        .media-viewer-inner {
            position: relative;
            display: inline-block;
            transition: transform 0.3s ease;
            transform-origin: center center;
        }
        .media-viewer img {
            max-width: 100%;
            max-height: 60vh;
            object-fit: contain;
            cursor: zoom-in;
            display: block;
            user-select: none;
        }
        .media-viewer.zoomed { cursor: grab; justify-content: flex-start; align-items: flex-start; }
        .media-viewer.zoomed:active { cursor: grabbing; }
        .media-viewer.zoomed img { cursor: zoom-out; max-width: none; max-height: none; }
        .zoom-hint {
            position: absolute;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 8px 16px;
            border-radius: 16px;
            font-size: 12px;
            pointer-events: none;
            white-space: nowrap;
        }
        .toggle-switch { position: relative; display: inline-block; width: 44px; height: 24px; }
        .toggle-switch input { opacity: 0; width: 0; height: 0; }
        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background: #f44336;
            transition: 0.3s;
            border-radius: 24px;
        }
        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 18px; width: 18px;
            left: 3px; bottom: 3px;
            background: white;
            transition: 0.3s;
            border-radius: 50%;
        }
        input:checked + .toggle-slider { background: #4caf50; }
        input:checked + .toggle-slider:before { transform: translateX(20px); }
        .toggle-slider:after { content: 'Private'; position: absolute; right: 8px; top: 4px; font-size: 9px; color: white; font-weight: 500; }
        input:checked + .toggle-slider:after { content: 'Public'; left: 8px; right: auto; }
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
            max-width: 90%;
        }
        .toast.success { background: #2e7d32; }
        .toast.error { background: #d32f2f; }
        @keyframes slideIn { from { transform: translateX(400px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .search-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.8);
            z-index: 9999;
            align-items: flex-start;
            justify-content: center;
            padding: 20px;
            overflow-y: auto;
        }
        .search-box {
            background: white;
            padding: 24px;
            width: 100%;
            max-width: 600px;
            border-radius: 8px;
            margin-top: 60px;
        }
        .search-input {
            width: 100%;
            padding: 14px;
            font-size: 16px;
            border: 2px solid #e0e0e0;
            border-radius: 4px;
            margin-bottom: 16px;
            outline: none;
        }
        .search-input:focus { border-color: #1a1a1a; }
        .search-results { max-height: 400px; overflow-y: auto; }
        .search-item { padding: 12px; border-bottom: 1px solid #f0f0f0; cursor: pointer; }
        .search-item:hover { background: #fafafa; }
        .search-hint { font-size: 12px; color: #666; margin-top: 8px; text-align: center; }
        .search-highlight { background: #fff9c4 !important; outline: 2px solid #f9a825; }
        .zip-entry { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; font-family: monospace; font-size: 12px; }
        .props-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .props-table td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
        .props-table td:first-child { color: #666; width: 38%; white-space: nowrap; }
        .props-table tr:last-child td { border-bottom: none; }
        .zip-entry:last-child { border-bottom: none; }

        /* csa overrides: no bar, orange accent */
        .csa-bar { display: none !important; }
        .csa-progress-fill { background: #e07820 !important; }
        .csa-progress-thumb { background: #e07820 !important; box-shadow: 0 0 10px rgba(224,120,32,.5) !important; }
        .csa-vol-slider::-webkit-slider-thumb { background: #e07820 !important; }
        .csa-btn:hover { color: #ffaa55 !important; }
        .csa-btn.csa-active { color: #e07820 !important; }
        .csa-ldr-ring { border-top-color: #e07820 !important; }

        @media (max-width: 768px) {
            .keyboard-hint { display: none; }
            .upload-section, .files-section, .bulk-actions, .progress-section { padding: 16px; }
            .file-item { grid-template-columns: auto 1fr; }
            .file-actions { grid-column: 2; width: 100%; justify-content: flex-end; }
            .modal-content { width: 95%; margin: 20px auto; max-height: calc(100vh - 40px); }
        }
    </style>
</head>
<body>
    <div class="search-overlay" id="searchOverlay">
        <div class="search-box">
            <input type="text" class="search-input" id="searchInput" placeholder="Search files..." autocomplete="off">
            <div class="search-results" id="searchResults"></div>
            <div class="search-hint">Press ESC to close</div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1>` + snd.Cfg.SiteName + `</h1>
            <div class="header-actions">
                <span class="keyboard-hint">Ctrl+F: Search | Ctrl+A: Select All</span>
                ` + authButtons + `
            </div>
        </div>
        <div style="padding:12px 20px;background:#f5f5f5;border-bottom:1px solid #e0e0e0;font-size:13px;" id="breadcrumb">
            <span style="color:#666;">Root</span>
        </div>

        <div class="upload-section">
            <div class="upload-area" id="uploadArea">
                <input type="file" id="fileInput" multiple>
                <div class="upload-text" data-i18n="upload_drop_text">Drop files or click to upload (multiple files supported)</div>
            </div>
            <div class="selected-files" id="selectedFiles"></div>
            <button class="upload-btn" onclick="uploadFiles()" data-i18n="file_upload">Upload</button>
        </div>

        ` + apiTokenSection + `

        <div class="progress-section" id="progressSection">
            <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
            <div class="progress-info">
                <span id="progressText">0%</span>
                <span id="speedText">0 MB/s</span>
            </div>
        </div>

        <div class="bulk-actions" id="bulkActions">
            <span id="selectedCount" style="font-size:14px;color:#666;font-weight:500;">0 selected</span>
            <button class="btn-small" onclick="downloadSelectedAsZip()" title="Package selected as ZIP" data-i18n="bulk_zip_download">ZIP Download</button>
            <button class="btn-small" onclick="bulkSetPublic(true)" title="Make selected files public" style="background:#2e7d32;" data-i18n="bulk_make_public">Make Public</button>
            <button class="btn-small" onclick="bulkSetPublic(false)" title="Make selected files private" style="background:#c62828;" data-i18n="bulk_make_private">Make Private</button>
            <button class="btn-small" onclick="bulkDelete()" title="Delete selected files" style="background:#d32f2f;" data-i18n="bulk_delete">Delete</button>
            <button class="btn-small" onclick="deselectAll()" style="background:#555;" data-i18n="bulk_deselect">Deselect All</button>
        </div>

        <div class="files-section" id="filesSection">
            <div class="empty-state">Loading...</div>
        </div>
    </div>

    <!-- View Modal (image / text / zip / archive) -->
    <div class="modal" id="viewModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="viewTitle">View File</h3>
                <button class="close-btn" onclick="closeModal('viewModal')">&times;</button>
            </div>
            <div class="modal-body" id="viewBody"><pre id="viewContent"></pre></div>
        </div>
    </div>

    <!-- Edit Modal -->
    <div class="modal" id="editModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="editTitle">Edit File</h3>
                <button class="close-btn" onclick="closeModal('editModal')">&times;</button>
            </div>
            <div class="modal-body"><textarea id="editContent"></textarea></div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('editModal')">Cancel</button>
                <button class="btn-small" onclick="saveFile()">Save</button>
            </div>
        </div>
    </div>

    <!-- Rename Modal -->
    <div class="modal" id="renameModal">
        <div class="modal-content" style="max-width:500px;">
            <div class="modal-header">
                <h3>Rename File</h3>
                <button class="close-btn" onclick="closeModal('renameModal')">&times;</button>
            </div>
            <div class="modal-body">
                <input type="text" id="renameInput" style="width:100%;padding:12px;border:1px solid #e0e0e0;font-size:14px;border-radius:4px;">
            </div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('renameModal')">Cancel</button>
                <button class="btn-small" onclick="confirmRename()">Rename</button>
            </div>
        </div>
    </div>

    <!-- Properties Modal -->
    <div class="modal" id="propsModal">
        <div class="modal-content" style="max-width:480px;">
            <div class="modal-header">
                <h3 id="propsTitle">Properties</h3>
                <button class="close-btn" onclick="closeModal('propsModal')">&times;</button>
            </div>
            <div class="modal-body" id="propsBody"></div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('propsModal')">Close</button>
            </div>
        </div>
    </div>

    <!-- Create Folder Modal -->
    <div class="modal" id="createFolderModal">
        <div class="modal-content" style="max-width:500px;">
            <div class="modal-header">
                <h3>Create Folder</h3>
                <button class="close-btn" onclick="closeModal('createFolderModal')">&times;</button>
            </div>
            <div class="modal-body">
                <input type="text" id="folderNameInput" placeholder="Enter folder name"
                       style="width:100%;padding:12px;border:1px solid #e0e0e0;font-size:14px;border-radius:4px;">
            </div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('createFolderModal')">Cancel</button>
                <button class="btn-small" onclick="confirmCreateFolder()">Create</button>
            </div>
        </div>
    </div>

    <div class="footer">
        ` + snd.Cfg.SiteName + ` v` + snd.VERSION + `
    </div>

    <script>
        let currentPath = '';
        const isAuthenticated = ` + authStatus + `;
        let startTime, currentEditFile, currentRenameFile;
        let allFiles = [];
        let allFolders = [];
        let selectedFiles = new Set();
        let bulkMode = false;

        // --- API Token section ---
        function closeApiTokenSection() {
            const s = document.getElementById('apiTokenSection');
            if (s) { s.style.display = 'none'; localStorage.setItem('hideApiToken','true'); }
        }
        document.addEventListener('DOMContentLoaded', function() {
            if (localStorage.getItem('hideApiToken') === 'true') {
                const s = document.getElementById('apiTokenSection');
                if (s) s.style.display = 'none';
            }
        });
        function toggleTokenVisibility() {
            const inp = document.getElementById('apiTokenDisplay');
            const btn = event.target;
            if (inp.type === 'password') { inp.type = 'text'; btn.textContent = 'Hide'; }
            else { inp.type = 'password'; btn.textContent = 'Show'; }
        }
        function copyToken() {
            const val = document.getElementById('apiTokenDisplay').value;
            navigator.clipboard.writeText(val).then(() => showToast('API Token copied!','success'))
                .catch(() => showToast('Failed to copy','error'));
        }
        function addTokenToURL(url) {
            const token = document.getElementById('apiTokenDisplay') ?
                          document.getElementById('apiTokenDisplay').value : '` + snd.Cfg.APIToken + `';
            return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
        }

        function getAuthToken() {
            const el = document.getElementById('apiTokenDisplay');
            return el ? el.value : '` + snd.Cfg.APIToken + `';
        }

        // ─── Preview Modal (click on card) ────────────────────────────────────
        // allFiles stores current file list for auto-advance
        let _previewFiles = [];
        let _previewIdx = -1;

        function setPreviewFiles(files) { _previewFiles = files; }

        function openPreviewModal(filename, type) {
            _previewIdx = _previewFiles.findIndex(f => {
                const fn = currentPath ? currentPath + '/' + f.name : f.name;
                return fn === filename;
            });
            showPreview(filename, type);
        }

        function showPreview(filename, type) {
            const rawUrl = '/api/view/' + encodeURIComponent(filename);
            const streamUrl = '/stream/' + encodeURIComponent(filename);
            const baseName = filename.split('/').pop();

            if (type === 'image') {
                document.getElementById('viewTitle').textContent = baseName;
                document.getElementById('viewBody').innerHTML =
                    '<div style="text-align:center;padding:8px;">' +
                    '<img src="' + rawUrl + '" style="max-width:100%;max-height:70vh;object-fit:contain;border-radius:4px;" alt="' + escapeHtml(baseName) + '">' +
                    '</div>' +
                    '<div style="text-align:center;margin-top:12px;">' +
                    '<button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> ' +
                    '<button class="btn" onclick="advancePreview(1)">Next &#8594;</button>' +
                    '</div>';
                document.getElementById('viewModal').style.display = 'block';
                return;
            }

            if (type === 'video' || type === 'audio') {
                const ext = filename.split('.').pop().toLowerCase();
                if (ext === 'm3u8') {
                    // HLS — use native player in modal
                    document.getElementById('viewTitle').textContent = baseName;
                    document.getElementById('viewBody').innerHTML =
                        '<video id="hlsPlayer" controls autoplay playsinline style="width:100%;max-height:70vh;background:#000;border-radius:4px;"></video>' +
                        '<div style="text-align:center;margin-top:12px;">' +
                        '<button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> ' +
                        '<button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
                    document.getElementById('viewModal').style.display = 'block';
                    const v = document.getElementById('hlsPlayer');
                    if (typeof Hls !== 'undefined' && Hls.isSupported()) {
                        const h = new Hls(); h.loadSource(streamUrl); h.attachMedia(v); v.play().catch(()=>{});
                    } else if (v.canPlayType('application/vnd.apple.mpegurl')) {
                        v.src = streamUrl; v.play().catch(()=>{});
                    }
                    v.addEventListener('ended', () => advancePreview(1));
                } else {
                    // Use csa.js player for all other video/audio
                    if (typeof csa !== 'undefined' && csa.player) {
                        csa.player({
                            src: addTokenToURL(streamUrl),
                            title: baseName,
                            mode: 'modal',
                            autoplay: true,
                            loader: 'ring',
                            theme: { accent: '#e07820', accent2: '#ffaa55' },
                            onEnded: () => advancePreview(1)
                        });
                    } else {
                        // Fallback: native player
                        document.getElementById('viewTitle').textContent = baseName;
                        const tag = type === 'audio' ? 'audio' : 'video';
                        const style = type === 'audio' ? 'width:100%;margin:20px 0;' : 'width:100%;max-height:70vh;background:#000;border-radius:4px;';
                        document.getElementById('viewBody').innerHTML =
                            '<' + tag + ' id="mediaPlayer" controls autoplay playsinline style="' + style + '" onended="advancePreview(1)">' +
                            '<source src="' + addTokenToURL(streamUrl) + '">' +
                            '</' + tag + '>' +
                            '<div style="text-align:center;margin-top:12px;">' +
                            '<button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> ' +
                            '<button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
                        document.getElementById('viewModal').style.display = 'block';
                    }
                }
                return;
            }
            // Fallback to original viewFile for other types
            viewFile(filename, type);
        }

        function advancePreview(dir) {
            if (_previewFiles.length === 0) return;
            const mediaTypes = ['image','video','audio'];
            let next = _previewIdx + dir;
            // Find next previewable file
            while (next >= 0 && next < _previewFiles.length) {
                if (mediaTypes.includes(_previewFiles[next].type)) break;
                next += dir;
            }
            if (next < 0 || next >= _previewFiles.length) return;
            _previewIdx = next;
            const f = _previewFiles[next];
            const fn = currentPath ? currentPath + '/' + f.name : f.name;
            showPreview(fn, f.type);
        }


        // --- Navigation ---
        function navigateToFolder(folderName) { currentPath = folderName; loadFiles(); updateBreadcrumb(); }
        function navigateToRoot() { currentPath = ''; loadFiles(); updateBreadcrumb(); }

        function updateBreadcrumb() {
            const bc = document.getElementById('breadcrumb');
            if (!bc) return;
            if (currentPath === '') {
                bc.innerHTML = '<span style="color:#666;">Root</span>';
                return;
            }
            const parts = currentPath.split('/').filter(p => p);
            let html = '<a href="#" onclick="navigateToRoot();return false;" style="color:#0066cc;text-decoration:none;">Root</a>';
            let pathSoFar = '';
            parts.forEach((part, i) => {
                pathSoFar += (pathSoFar ? '/' : '') + part;
                if (i === parts.length - 1) {
                    html += ' / <span style="color:#666;">' + escapeHtml(part) + '</span>';
                } else {
                    const np = pathSoFar;
                    html += ' / <a href="#" onclick="currentPath=\'' + np.replace(/'/g,"\\'") + '\';loadFiles();updateBreadcrumb();return false;" style="color:#0066cc;text-decoration:none;">' + escapeHtml(part) + '</a>';
                }
            });
            bc.innerHTML = html;
        }

        // --- Search ---
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'f') { e.preventDefault(); showSearch(); }
            if (e.key === 'Escape') document.getElementById('searchOverlay').style.display = 'none';
            if (e.ctrlKey && e.key === 'a') { e.preventDefault(); selectAllFiles(); }
        });
        function showSearch() {
            document.getElementById('searchOverlay').style.display = 'flex';
            document.getElementById('searchInput').focus();
        }
        document.getElementById('searchInput').addEventListener('input', function(e) {
            const q = e.target.value.toLowerCase().trim();
            const res = document.getElementById('searchResults');
            if (!q) { res.innerHTML = ''; return; }
            const matchFiles   = allFiles.filter(f => f.name.toLowerCase().includes(q));
            const matchFolders = allFolders.filter(n => n.toLowerCase().includes(q));
            const all = [
                ...matchFolders.map(n => ({ name: n, isFolder: true })),
                ...matchFiles.map(f => ({ name: f.name, isFolder: false, type: f.type, size: f.size }))
            ];
            if (!all.length) { res.innerHTML = '<div class="search-item" style="color:#999;">No results</div>'; return; }
            res.innerHTML = all.map(item => {
                const label = item.isFolder ? '&#128193; ' + escapeHtml(item.name) : escapeHtml(item.name);
                const meta  = item.isFolder ? 'Folder' : (item.type + ' - ' + formatFileSize(item.size));
                return '<div class="search-item" onclick="jumpToItem(\'' + item.name.replace(/'/g,"\\'") + '\',' + item.isFolder + ')">' +
                    '<div><div style="font-size:14px;">' + label + '</div><div style="font-size:11px;color:#999;">' + meta + '</div></div>' +
                    '<span style="font-size:11px;color:#0066cc;white-space:nowrap;">Jump &#8594;</span>' +
                    '</div>';
            }).join('');
        });
        function jumpToItem(name, isFolder) {
            document.getElementById('searchOverlay').style.display = 'none';
            document.getElementById('searchInput').value = '';
            document.getElementById('searchResults').innerHTML = '';
            const id = 'snd-item-' + name.replace(/[^a-zA-Z0-9]/g, '_');
            const el = document.getElementById(id);
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                el.classList.add('search-highlight');
                setTimeout(() => el.classList.remove('search-highlight'), 2800);
            }
        }

        // --- Bulk select ---
        function selectAllFiles() {
            if (!bulkMode) { bulkMode = true; document.getElementById('bulkActions').classList.add('active'); }
            selectedFiles.clear();
            allFiles.forEach(f => selectedFiles.add(f.name));
            document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = true);
            updateBulkCount();
        }
        function deselectAll() {
            selectedFiles.clear();
            document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = false);
            bulkMode = false;
            document.getElementById('bulkActions').classList.remove('active');
        }
        function toggleFileSelect(filename, checkbox) {
            if (checkbox.checked) {
                selectedFiles.add(filename);
                if (!bulkMode) { bulkMode = true; document.getElementById('bulkActions').classList.add('active'); }
            } else {
                selectedFiles.delete(filename);
                if (!selectedFiles.size) { bulkMode = false; document.getElementById('bulkActions').classList.remove('active'); }
            }
            updateBulkCount();
        }
        function updateBulkCount() {
            document.getElementById('selectedCount').textContent = selectedFiles.size + ' selected';
        }
        function bulkSetPublic(isPublic) {
            if (!selectedFiles.size) return;
            var files = Array.from(selectedFiles);
            Promise.all(files.map(function(f) {
                return fetch('/set-permission', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:f,is_public:isPublic})});
            })).then(function() {
                showToast(files.length + ' files ' + (isPublic ? 'made public' : 'made private'), 'success');
                deselectAll(); loadFiles();
            }).catch(function() { showToast('Some permissions failed','error'); });
        }

        function bulkDelete() {
            if (!selectedFiles.size) return;
            var files = Array.from(selectedFiles);
            showConfirm('Delete ' + files.length + ' file(s)? Cannot be undone.', function() {
                Promise.all(files.map(function(f) { return fetch('/delete/' + encodeURIComponent(f), {method:'DELETE'}); }))
                    .then(function() { showToast(files.length + ' files deleted', 'success'); deselectAll(); loadFiles(); })
                    .catch(function() { showToast('Some deletes failed','error'); });
            });
        }

        function showConfirm(message, onYes) {
            var modal = document.getElementById('_confirmModal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = '_confirmModal';
                modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:9999;align-items:center;justify-content:center;';
                var box = document.createElement('div');
                box.style.cssText = 'background:#fff;border-radius:8px;padding:28px;min-width:300px;max-width:400px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);';
                var msgEl = document.createElement('div');
                msgEl.id = '_confirmMsg';
                msgEl.style.cssText = 'font-size:15px;margin-bottom:20px;line-height:1.5;color:#1a1a1a;';
                var row = document.createElement('div');
                row.style.cssText = 'display:flex;gap:10px;justify-content:center;';
                var cancelBtn = document.createElement('button');
                cancelBtn.textContent = 'Cancel';
                cancelBtn.style.cssText = 'padding:8px 20px;background:#f5f5f5;border:1px solid #ddd;border-radius:4px;cursor:pointer;font-size:14px;';
                cancelBtn.onclick = function() { modal.style.display = 'none'; };
                var yesBtn = document.createElement('button');
                yesBtn.id = '_cBtnYes';
                yesBtn.textContent = 'Confirm';
                yesBtn.style.cssText = 'padding:8px 20px;background:#d32f2f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px;';
                row.appendChild(cancelBtn);
                row.appendChild(yesBtn);
                box.appendChild(msgEl);
                box.appendChild(row);
                modal.appendChild(box);
                document.body.appendChild(modal);
                modal.addEventListener('click', function(e) { if (e.target === modal) modal.style.display = 'none'; });
            }
            document.getElementById('_confirmMsg').textContent = message;
            document.getElementById('_cBtnYes').onclick = function() { modal.style.display = 'none'; if (onYes) onYes(); };
            modal.style.display = 'flex';
        }

        function downloadSelectedAsZip() {
            if (!selectedFiles.size) return;
            const files = Array.from(selectedFiles);
            fetch('/zip-multiple', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({files})
            }).then(r => r.blob()).then(blob => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'files_' + Date.now() + '.zip';
                a.click();
                showToast('Downloaded ' + files.length + ' files as ZIP', 'success');
            }).catch(() => showToast('Failed to create ZIP','error'));
        }

        // --- Context menu ---
        function toggleContextMenu(e, id) {
            e.stopPropagation();
            document.querySelectorAll('.context-menu').forEach(m => { if (m.id !== 'menu-' + id) m.classList.remove('show'); });
            const menu = document.getElementById('menu-' + id);
            // FIX: When liquid glass is active, context-menu uses position:fixed (to escape the
            // backdrop-filter stacking context on .file-item). Compute viewport coords from the button.
            if (document.body.classList.contains('th-liquid')) {
                const btn = e.currentTarget || e.target;
                const rect = btn.getBoundingClientRect();
                const menuW = 200; // min-width of menu
                // Position below button, align right edge with button right
                let top = rect.bottom + 4;
                let right = window.innerWidth - rect.right;
                // Clamp: if menu would overflow bottom of viewport, flip above
                if (top + 200 > window.innerHeight) {
                    top = Math.max(4, rect.top - 4 - 200);
                }
                // Clamp: if right side would push off left edge, pin to left side
                if (rect.right - menuW < 0) {
                    right = window.innerWidth - Math.min(rect.right + menuW, window.innerWidth - 4);
                }
                menu.style.top = top + 'px';
                menu.style.right = right + 'px';
                menu.style.left = 'auto';
            }
            menu.classList.toggle('show');
        }
        document.addEventListener('click', () => document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show')));

        // --- Upload ---
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const selectedFilesDiv = document.getElementById('selectedFiles');

        if (isAuthenticated) {
            fileInput.addEventListener('change', updateSelectedFiles);
            uploadArea.addEventListener('dragover', e => { e.preventDefault(); uploadArea.classList.add('dragover'); });
            uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('dragover'));
            uploadArea.addEventListener('drop', e => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                fileInput.files = e.dataTransfer.files;
                updateSelectedFiles();
            });
        }

        function updateSelectedFiles() {
            const files = fileInput.files;
            if (!files.length) { selectedFilesDiv.style.display = 'none'; return; }
            let html = '<strong>Selected (' + files.length + '):</strong><br>';
            for (let i = 0; i < files.length; i++) {
                html += '<div>' + escapeHtml(files[i].name) + ' (' + (files[i].size/1024).toFixed(1) + ' KB)</div>';
            }
            selectedFilesDiv.innerHTML = html;
            selectedFilesDiv.style.display = 'block';
        }

        const CHUNK_SIZE = 4 * 1024 * 1024;

        function uploadFiles() {
            if (!isAuthenticated) { showToast('Please login to upload files', 'error'); return; }
            const files = fileInput.files;
            if (!files.length) { showToast('Please select files', 'error'); return; }

            const progressSection = document.getElementById('progressSection');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            const speedText = document.getElementById('speedText');
            const uploadBtn = document.querySelector('.upload-btn');

            progressSection.style.display = 'block';
            uploadBtn.disabled = true;
            uploadBtn.textContent = 'Uploading...';

            const startTime = Date.now();
            let totalBytes = 0;
            let uploadedBytes = 0;
            for (let f of files) totalBytes += f.size;

            const uploadQueue = Array.from(files);
            let fileIdx = 0;

            function uploadNextFile() {
                if (fileIdx >= uploadQueue.length) {
                    finishUpload(uploadQueue.length);
                    return;
                }
                const file = uploadQueue[fileIdx++];
                uploadFileChunked(file, function(sent) {
                    uploadedBytes += sent;
                    const pct = totalBytes > 0 ? (uploadedBytes / totalBytes * 100).toFixed(1) : 100;
                    progressFill.style.width = pct + '%';
                    const elapsed = (Date.now() - startTime) / 1000;
                    const speed = elapsed > 0 ? (uploadedBytes / elapsed / 1024 / 1024).toFixed(2) : '0.00';
                    const remaining = totalBytes - uploadedBytes;
                    const eta = uploadedBytes > 0 ? (remaining / (uploadedBytes / elapsed)) : 0;
                    const etaText = eta < 60 ? ' ETA: ' + Math.floor(eta) + 's' : ' ETA: ' + Math.floor(eta/60) + 'm ' + Math.floor(eta%60) + 's';
                    progressText.textContent = pct + '% — ' + file.name;
                    speedText.textContent = speed + ' MB/s' + etaText;
                }, function() {
                    uploadNextFile();
                }, function(err) {
                    showToast('Upload failed: ' + err + ' — ' + file.name, 'error');
                    uploadNextFile();
                });
            }

            uploadNextFile();

            function finishUpload(count) {
                showToast('Upload complete — ' + count + ' file(s)', 'success');
                fileInput.value = '';
                selectedFilesDiv.style.display = 'none';
                progressSection.style.display = 'none';
                progressFill.style.width = '0%';
                uploadBtn.disabled = false;
                uploadBtn.textContent = 'Upload';
                setTimeout(() => loadFiles(), 500);
            }
        }

        function uploadFileChunked(file, onProgress, onDone, onError) {
            const path = currentPath;
            const totalSize = file.size;
            let offset = 0;
            let bytesSentForProgress = 0;

            function sendChunk(retries) {
                if (retries === undefined) retries = 3;
                const isFinal = (offset + CHUNK_SIZE) >= totalSize;
                const chunk = file.slice(offset, offset + CHUNK_SIZE);
                const chunkSize = chunk.size;

                const params = new URLSearchParams({
                    filename: file.name,
                    offset: offset,
                    total: totalSize,
                    final: isFinal ? '1' : '0'
                });
                if (path) params.set('path', path);

                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/upload-chunk?' + params.toString());

                xhr.upload.addEventListener('progress', function(e) {
                    if (e.lengthComputable) {
                        const delta = e.loaded - bytesSentForProgress;
                        if (delta > 0) { bytesSentForProgress = e.loaded; onProgress(delta); }
                    }
                });

                xhr.addEventListener('load', function() {
                    if (xhr.status === 200) {
                        const delta = chunkSize - bytesSentForProgress;
                        if (delta > 0) { onProgress(delta); }
                        bytesSentForProgress = 0;
                        offset += chunkSize;
                        if (isFinal) {
                            onDone();
                        } else {
                            setTimeout(sendChunk, 0);
                        }
                    } else {
                        if (retries > 0) {
                            setTimeout(() => sendChunk(retries - 1), 2000);
                        } else {
                            onError('Server error ' + xhr.status);
                        }
                    }
                });

                xhr.addEventListener('error', function() {
                    if (retries > 0) {
                        setTimeout(() => sendChunk(retries - 1), 3000);
                    } else {
                        onError('Network error');
                    }
                });

                xhr.addEventListener('abort', function() {
                    onError('Upload aborted');
                });

                xhr.send(chunk);
            }

            sendChunk();
        }

        // --- Load files ---
        function loadFiles() {
            const url = currentPath ? '/files?path=' + encodeURIComponent(currentPath) : '/files';
            fetch(url)
                .then(r => { if (!r.ok) throw new Error(); return r.json(); })
                .then(data => {
                    const files = data.files || [];
                    const folders = data.folders || [];
                    allFiles = files;
                    allFolders = folders;
                    const section = document.getElementById('filesSection');

                    if (!folders.length && !files.length) {
                        section.innerHTML = '<div class="empty-state">No files or folders here</div>';
                        return;
                    }

                    let html = '';

                    folders.forEach(folder => {
                        const fullPath = currentPath ? currentPath + '/' + folder : folder;
                        const escapedFP = fullPath.replace(/'/g, "\\'");
                        const escapedF  = folder.replace(/'/g, "\\'");
                        const safeId    = 'snd-item-' + folder.replace(/[^a-zA-Z0-9]/g, '_');
                        html += '<div class="file-item" id="' + safeId + '" style="background:#f9f9f9;">';
                        html += '<input type="checkbox" class="checkbox file-checkbox" style="visibility:hidden;" disabled>';
                        html += '<div style="font-size:28px;line-height:1;width:72px;display:flex;align-items:center;justify-content:center;">&#128193;</div>';
                        html += '<div class="file-info" onclick="navigateToFolder(\'' + escapedFP + '\')" style="cursor:pointer;">';
                        html += '<div class="file-name" style="font-weight:600;">' + escapeHtml(folder);
                        html += '<span class="file-type-badge" style="background:#e3f2fd;color:#1976d2">FOLDER</span>';
                        if (isAuthenticated) {
                            html += '<label class="toggle-switch" style="margin-left:8px;vertical-align:middle;" onclick="event.stopPropagation();" title="Public / Private">';
                            html += '<input type="checkbox" id="ftoggle-' + safeId + '" onchange="toggleFolderPublic(\'' + escapedFP + '\',this.checked)">';
                            html += '<span class="toggle-slider"></span></label>';
                        }
                        html += '</div><div class="file-meta" style="color:#999;">Click to open</div></div>';
                        if (isAuthenticated) {
                            html += '<div class="file-actions">';
                            html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'folder-' + safeId + '\');return false;">&#8942;</button>';
                            html += '<div class="context-menu" id="menu-folder-' + safeId + '">';
                            html += '<div class="context-menu-item" onclick="renameFolderDialog(\'' + escapedFP + '\',\'' + escapedF + '\')">Rename Folder</div>';
                            html += '<div class="context-menu-item" onclick="showFolderProperties(\'' + escapedFP + '\')">Properties</div>';
                            html += '<div class="context-menu-sep"></div>';
                            html += '<div class="context-menu-item danger" onclick="deleteFolder(\'' + escapedFP + '\')">Delete Folder</div>';
                            html += '</div></div>';
                        }
                        html += '</div>';
                    });

                    if (isAuthenticated) {
                        folders.forEach(folder => {
                            const fullPath = currentPath ? currentPath + '/' + folder : folder;
                            const safeId = 'snd-item-' + folder.replace(/[^a-zA-Z0-9]/g, '_');
                            fetch('/folder-info/' + encodeURIComponent(fullPath))
                                .then(r => r.json())
                                .then(d => { const cb = document.getElementById('ftoggle-' + safeId); if (cb) cb.checked = d.is_public; })
                                .catch(() => {});
                        });
                    }

                    setPreviewFiles(files);
                    files.forEach(f => {
                        const fullFileName = currentPath ? currentPath + '/' + f.name : f.name;
                        const rawUrl = window.location.origin + '/raw/' + encodeURIComponent(fullFileName);
                        const esc = fullFileName.replace(/'/g,"\\'").replace(/"/g,'&quot;');
                        const isPublic = f.is_public || false;
                        const modDate = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';

                        const badgeStyles = {
                            text:    'background:#e8f5e9;color:#2e7d32',
                            image:   'background:#e3f2fd;color:#1976d2',
                            video:   'background:#fce4ec;color:#c2185b',
                            audio:   'background:#f3e5f5;color:#7b1fa2',
                            archive: 'background:#fff3e0;color:#f57c00',
                            document:'background:#ffebee;color:#d32f2f',
                            font:    'background:#e0f2f1;color:#00695c',
                            database:'background:#e1f5fe;color:#0277bd',
                        };
                        const badgeStyle = badgeStyles[f.type] || 'background:#f5f5f5;color:#616161';

                        const safeFileId = 'snd-item-' + f.name.replace(/[^a-zA-Z0-9]/g, '_');
                        html += '<div class="file-item" id="' + safeFileId + '">';
                        html += '<input type="checkbox" class="checkbox file-checkbox" onchange="toggleFileSelect(\'' + esc + '\',this)">';

                        // ── Thumbnail / Icon (shown first) ──────────────────
                        if (f.type === 'image' || f.type === 'video') {
                            const thumbSrc = '/thumbnail/' + encodeURIComponent(fullFileName);
                            html += '<div class="file-thumb" onclick="openPreviewModal(\'' + esc + '\',\'' + f.type + '\')" style="cursor:pointer;width:72px;height:72px;border-radius:8px;overflow:hidden;flex-shrink:0;background:#f0f0f0;">' +
                                '<img src="' + thumbSrc + '" loading="lazy" alt="" style="width:100%;height:100%;object-fit:cover;" onerror="this.style.display=\'none\';this.parentNode.style.cssText+=\'background:#f5f5f5;background-image:url(/icons/' + f.type + '.svg);background-repeat:no-repeat;background-position:center;background-size:36px\'">' +
                                '</div>';
                        } else {
                            html += '<div class="file-thumb" onclick="openPreviewModal(\'' + esc + '\',\'' + f.type + '\')" style="cursor:pointer;width:72px;height:72px;border-radius:8px;overflow:hidden;flex-shrink:0;background:#f5f5f5;display:flex;align-items:center;justify-content:center;">' +
                                '<img src="/icons/' + f.type + '.svg" style="width:36px;height:36px;opacity:0.55;" onerror="this.src=\'/icons/file.svg\'">' +
                                '</div>';
                        }

                        html += '<div class="file-info">';
                        html += '<div class="file-name">' + escapeHtml(f.name);
                        html += '<span class="file-type-badge" style="' + badgeStyle + '">' + f.type + '</span>';

                        if (isAuthenticated) {
                            html += '<label class="toggle-switch" style="margin-left:8px;vertical-align:middle;" onclick="event.stopPropagation();">';
                            html += '<input type="checkbox" ' + (isPublic ? 'checked' : '') + ' onchange="togglePublicSwitch(\'' + esc + '\',this.checked)">';
                            html += '<span class="toggle-slider"></span></label>';
                        } else {
                            html += '<span class="file-type-badge" style="' + (isPublic ? 'background:#4caf50;color:white' : 'background:#f44336;color:white') + ';margin-left:4px">' + (isPublic ? 'PUBLIC' : 'PRIVATE') + '</span>';
                        }


                        html += '</div>';
                        html += '<div class="file-meta">' + formatFileSize(f.size) + ' - ' + modDate;
                        if (f.download_count > 0) html += ' - ' + f.download_count + ' downloads';
                        html += '</div>';
                        html += '<div class="file-link" onclick="copyLink(\'' + esc + '\',' + isPublic + ')" title="Click to copy">' + escapeHtml(rawUrl) + '</div>';
                        html += '</div>';
                        // file-actions stays INSIDE .file-item grid
                        html += '<div class="file-actions">';
                        html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'' + safeFileId + '\');return false;">&#8942;</button>';
                        html += '<div class="context-menu" id="menu-' + safeFileId + '">';

                        const viewLabel = (f.type === 'video' || f.type === 'audio') ? 'Play' : 'View';
                        html += '<div class="context-menu-item" onclick="viewFile(\''+esc+'\',\''+f.type+'\')">'+viewLabel+'</div>';
                        if (isAuthenticated) {
                            html += '<div class="context-menu-item" onclick="editFile(\''+esc+'\')">Edit</div>';
                        }
                        html += '<div class="context-menu-item" onclick="copyLink(\''+esc+'\',' + isPublic + ')">Copy link</div>';
                        html += '<div class="context-menu-item" onclick="downloadAsZip(\''+esc+'\')">Download as ZIP</div>';
                        if (isAuthenticated) {
                            html += '<div class="context-menu-item" onclick="renameFile(\''+esc+'\')">Rename</div>';
                            html += '<div class="context-menu-item" onclick="duplicateFile(\''+esc+'\')">Duplicate</div>';
                            html += '<div class="context-menu-item danger" onclick="deleteFile(\''+esc+'\')">Delete</div>';
                        }
                        html += '</div></div></div>'; // close context-menu, file-actions, file-item
                    });

                    section.innerHTML = html;
                })
                .catch(() => {
                    document.getElementById('filesSection').innerHTML =
                        '<div class="empty-state">Error loading files. Please refresh.</div>';
                });
        }

        // --- File actions ---
        function togglePublicSwitch(filename, isPublic) {
            fetch('/set-permission', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({filename, is_public: isPublic})
            }).then(r => r.json()).then(() => {
                showToast(filename + ' is now ' + (isPublic ? 'PUBLIC' : 'PRIVATE'),'success');
                loadFiles();
            }).catch(() => { showToast('Failed to update permission','error'); loadFiles(); });
        }

        function copyLink(filename, isPublic) {
            // Security fix: public files don't need token in URL
            const base = window.location.origin + '/raw/' + encodeURIComponent(filename);
            const url = isPublic ? base : addTokenToURL(base);
            navigator.clipboard.writeText(url)
                .then(() => showToast('Link copied!','success'))
                .catch(() => showToast('Failed to copy link','error'));
        }

        function viewFile(filename, type) {
            const rawUrl = addTokenToURL('/raw/' + encodeURIComponent(filename));
            const streamUrl = addTokenToURL('/stream/' + encodeURIComponent(filename));
            const baseName = filename.split('/').pop();

            if (type === 'video') {
                csa.player({
                    src: streamUrl,
                    title: baseName,
                    mode: 'modal',
                    autoplay: true,
                    loader: 'ring',
                    theme: { accent: '#e07820', accent2: '#ffaa55' }
                });
                return;
            }

            if (type === 'audio') {
                csa.player({
                    src: streamUrl,
                    title: baseName,
                    mode: 'modal',
                    autoplay: true,
                    loader: 'ring',
                    theme: { accent: '#e07820', accent2: '#ffaa55' }
                });
                return;
            }

            const viewBody = document.getElementById('viewBody');
            document.getElementById('viewTitle').textContent = baseName;
            document.getElementById('viewModal').style.display = 'block';

            if (type === 'image') {
                viewBody.innerHTML = '<div class="media-viewer" id="imageViewer"><div class="media-viewer-inner" id="imageInner"><img src="' + rawUrl + '" id="zoomableImage"></div><div class="zoom-hint" id="zoomHint">Click to zoom in</div></div>';
                setupImageZoom();
                return;
            }

            if (type === 'archive') {
                viewZipContents(filename);
                return;
            }

            // text / document / binary / etc.
            viewBody.innerHTML = '<div style="color:#999;padding:24px;text-align:center;">Loading...</div>';
            fetch(rawUrl)
                .then(r => r.text())
                .then(c => {
                    viewBody.innerHTML = '<pre id="viewContent" style="white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:12px;line-height:1.6;background:#f5f5f5;padding:16px;border-radius:4px;overflow:auto;max-height:62vh;"></pre>';
                    document.getElementById('viewContent').textContent = c;
                })
                .catch(() => { viewBody.innerHTML = '<div style="padding:24px;color:#d32f2f;">Failed to load file.</div>'; });
        }

        function setupImageZoom() {
            const viewer = document.getElementById('imageViewer');
            const inner = document.getElementById('imageInner');
            const img = document.getElementById('zoomableImage');
            const hint = document.getElementById('zoomHint');
            if (!viewer || !img) return;
            let scale = 1, panning = false, pointX = 0, pointY = 0, startX = 0, startY = 0;
            function setTransform() { inner.style.transform = 'translate(' + pointX + 'px,' + pointY + 'px) scale(' + scale + ')'; }
            img.addEventListener('click', e => {
                e.stopPropagation();
                if (scale === 1) { scale = 2; viewer.classList.add('zoomed'); hint.textContent = 'Drag to pan - Click to zoom out'; }
                else { scale = 1; pointX = 0; pointY = 0; viewer.classList.remove('zoomed'); hint.textContent = 'Click to zoom in'; }
                setTransform();
            });
            viewer.addEventListener('wheel', e => {
                e.preventDefault();
                const xs = (e.clientX - pointX) / scale, ys = (e.clientY - pointY) / scale;
                scale = Math.min(Math.max(0.5, scale + (e.deltaY > 0 ? -0.2 : 0.2)), 5);
                if (scale > 1) { pointX = e.clientX - xs * scale; pointY = e.clientY - ys * scale; viewer.classList.add('zoomed'); }
                else { scale = 1; pointX = 0; pointY = 0; viewer.classList.remove('zoomed'); }
                setTransform();
            }, { passive: false });
            viewer.addEventListener('mousedown', e => { if (scale <= 1) return; e.preventDefault(); startX = e.clientX - pointX; startY = e.clientY - pointY; panning = true; });
            viewer.addEventListener('mousemove', e => { if (!panning) return; e.preventDefault(); pointX = e.clientX - startX; pointY = e.clientY - startY; setTransform(); });
            viewer.addEventListener('mouseup', () => panning = false);
            viewer.addEventListener('mouseleave', () => panning = false);
        }

        function viewZipContents(filename) {
            fetch('/zip-view/' + encodeURIComponent(filename)).then(r => r.json()).then(data => {
                document.getElementById('viewTitle').textContent = filename + ' (ZIP Contents)';
                let html = '<div style="font-family:monospace;font-size:12px;">';
                html += '<div style="margin-bottom:12px;padding:10px;background:#f5f5f5;border:1px solid #e0e0e0;border-radius:4px;">';
                html += '<strong>' + data.files.length + ' files</strong> - Total: ' + formatFileSize(data.total_size) + '</div>';
                data.files.forEach(f => {
                    html += '<div class="zip-entry"><strong>' + escapeHtml(f.name) + '</strong><span style="color:#999;margin-left:16px;">' + formatFileSize(f.size) + '</span></div>';
                });
                html += '</div>';
                document.getElementById('viewBody').innerHTML = html;
            }).catch(() => showToast('Failed to read ZIP','error'));
        }

        function editFile(filename) {
            if (!isAuthenticated) { showToast('Login required','error'); return; }
            currentEditFile = filename;
            document.getElementById('editTitle').textContent = 'Edit: ' + filename.split('/').pop();
            document.getElementById('editContent').value = 'Loading...';
            document.getElementById('editModal').style.display = 'block';
            fetch(addTokenToURL('/raw/' + encodeURIComponent(filename)))
                .then(r => r.text())
                .then(c => { document.getElementById('editContent').value = c; })
                .catch(() => { document.getElementById('editContent').value = '// Failed to load file'; });
        }

        function saveFile() {
            fetch('/save/' + encodeURIComponent(currentEditFile), {
                method: 'POST',
                headers: {'Content-Type': 'text/plain'},
                body: document.getElementById('editContent').value
            }).then(r => r.json()).then(d => {
                showToast(d.message,'success');
                closeModal('editModal');
                loadFiles();
            }).catch(() => showToast('Failed to save','error'));
        }

        function downloadFile(filename) {
            window.location.href = addTokenToURL('/download/' + encodeURIComponent(filename));
        }

        function downloadAsZip(filename) {
            fetch('/zip-multiple', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({files: [filename]})
            }).then(r => r.blob()).then(blob => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = filename + '.zip';
                a.click();
            });
        }

        function deleteFile(filename) {
            if (!isAuthenticated) { showToast('Login required','error'); return; }
            if (!confirm('Delete ' + filename + '?')) return;
            fetch('/delete/' + encodeURIComponent(filename), {method: 'DELETE'})
                .then(r => r.json()).then(d => { showToast(d.message,'success'); loadFiles(); })
                .catch(() => showToast('Failed to delete','error'));
        }

        function renameFile(filename) {
            currentRenameFile = filename;
            document.getElementById('renameInput').value = filename;
            document.getElementById('renameModal').style.display = 'block';
            document.getElementById('renameInput').select();
        }

        function confirmRename() {
            const newName = document.getElementById('renameInput').value.trim();
            if (!newName) { showToast('Please enter a name','error'); return; }
            const mode = document.getElementById('renameModal').dataset.mode;
            if (mode === 'folder') {
                fetch('/rename-folder/' + encodeURIComponent(currentRenameFolderPath), {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({old_path: currentRenameFolderPath, new_name: newName})
                }).then(r => r.json()).then(d => {
                    if (d.success === false) { showToast(d.error || 'Failed to rename', 'error'); return; }
                    showToast('Folder renamed to ' + newName, 'success');
                    closeModal('renameModal');
                    document.getElementById('renameModal').dataset.mode = '';
                    loadFiles();
                }).catch(() => showToast('Failed to rename folder','error'));
            } else {
                fetch('/rename/' + encodeURIComponent(currentRenameFile), {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({new_name: newName})
                }).then(r => r.json()).then(d => {
                    showToast(d.message,'success'); closeModal('renameModal'); loadFiles();
                }).catch(() => showToast('Failed to rename','error'));
            }
        }

        function duplicateFile(filename) {
            fetch('/duplicate/' + encodeURIComponent(filename), {method: 'POST'})
                .then(r => r.json()).then(d => { showToast(d.message,'success'); loadFiles(); })
                .catch(() => showToast('Failed to duplicate','error'));
        }

        function toggleFolderPublic(folderPath, isPublic) {
            fetch('/set-folder-permission', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({path: folderPath, is_public: isPublic})
            }).then(r => r.json())
              .then(() => showToast(folderPath.split('/').pop() + ' is now ' + (isPublic ? 'PUBLIC' : 'PRIVATE'), 'success'))
              .catch(() => showToast('Failed to update folder permission','error'));
        }

        let currentRenameFolderPath = '';
        function renameFolderDialog(fullPath, name) {
            currentRenameFolderPath = fullPath;
            document.getElementById('renameInput').value = name;
            document.getElementById('renameModal').style.display = 'block';
            document.getElementById('renameInput').select();
            document.getElementById('renameModal').dataset.mode = 'folder';
        }

        function showFolderProperties(folderPath) {
            document.getElementById('propsTitle').textContent = folderPath.split('/').pop() + '/';
            document.getElementById('propsBody').innerHTML = '<div style="color:#999;padding:24px;text-align:center;">Loading...</div>';
            document.getElementById('propsModal').style.display = 'block';
            fetch('/folder-info/' + encodeURIComponent(folderPath))
                .then(r => r.json())
                .then(d => {
                    document.getElementById('propsBody').innerHTML =
                        '<table class="props-table">' +
                        '<tr><td>Name</td><td><strong>' + escapeHtml(d.name) + '/</strong></td></tr>' +
                        '<tr><td>Path</td><td style="font-family:monospace;font-size:12px;">' + escapeHtml(d.path) + '</td></tr>' +
                        '<tr><td>Files</td><td>' + d.file_count + '</td></tr>' +
                        '<tr><td>Subfolders</td><td>' + d.folder_count + '</td></tr>' +
                        '<tr><td>Total size</td><td>' + formatFileSize(d.total_size) + '</td></tr>' +
                        '<tr><td>Visibility</td><td>' + (d.is_public ? '<span style="color:#2e7d32;font-weight:600;">Public</span>' : '<span style="color:#d32f2f;font-weight:600;">Private</span>') + '</td></tr>' +
                        '</table>';
                })
                .catch(() => { document.getElementById('propsBody').innerHTML = '<div style="color:#d32f2f;padding:12px;">Failed to load info.</div>'; });
        }

        function deleteFolder(folderName) {
            if (!confirm('Type OK to confirm deletion of folder: ' + folderName)) return;
            fetch('/delete-folder/' + encodeURIComponent(folderName), {method: 'DELETE'})
                .then(r => r.json()).then(d => { showToast(d.message,'success'); loadFiles(); })
                .catch(() => showToast('Failed to delete folder','error'));
        }

        function openCreateFolderModal() {
            document.getElementById('folderNameInput').value = '';
            document.getElementById('createFolderModal').style.display = 'block';
            document.getElementById('folderNameInput').focus();
        }

        function confirmCreateFolder() {
            const folderName = document.getElementById('folderNameInput').value.trim();
            if (!folderName) { showToast('Please enter a folder name','error'); return; }
            if (folderName.includes('..') || folderName.includes('/') || folderName.includes('\\')) {
                showToast('Invalid folder name','error'); return;
            }
            fetch('/create-folder', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({path: folderName, current_path: currentPath})
            }).then(r => r.json()).then(d => {
                showToast(d.message,'success'); closeModal('createFolderModal'); loadFiles();
            }).catch(() => showToast('Failed to create folder','error'));
        }

        function logout() {
            fetch('/logout').then(() => { showToast('Logged out','success'); setTimeout(() => location.reload(), 1000); });
        }

        // --- Modal & utilities ---
        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
        }
        window.onclick = function(e) {
            if (e.target.classList.contains('modal')) closeModal(e.target.id);
        };

        function showToast(msg, type = 'success') {
            const t = document.createElement('div');
            t.className = 'toast ' + type;
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
            if (bytes === 0) return '0 B';
            if (bytes < 1024) return bytes + ' B';
            const units = ['KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
            let i = 0;
            let size = bytes / 1024;
            while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
            return size.toFixed(2) + ' ' + units[i];
        }

        loadFiles();
    </script>
` + snd.ThemeSnippet("dashboard") + `
<script>
// FIX: Language system — fetch translations from /api/lang and apply data-i18n attributes
(function() {
    fetch('/api/lang').then(r => r.json()).then(function(t) {
        if (!t || typeof t !== 'object') return;
        document.querySelectorAll('[data-i18n]').forEach(function(el) {
            var key = el.getAttribute('data-i18n');
            if (t[key]) el.textContent = t[key];
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(function(el) {
            var key = el.getAttribute('data-i18n-placeholder');
            if (t[key]) el.placeholder = t[key];
        });
        // Expose globally so dynamic content can use it
        window._lang = t;
    }).catch(function(){});
})();
</script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}