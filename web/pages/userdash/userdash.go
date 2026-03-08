package userdash

import (
	"fmt"
	"net/http"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	user := snd.GetSessionUser(r)
	if user == nil {
		http.Redirect(w, r, "/ac", http.StatusSeeOther)
		return
	}

	apiTokenSection := fmt.Sprintf(`
        <div class="upload-section" id="apiTokenSection" style="background:#fff3e0;border:2px solid #f57c00;position:relative;">
            <button onclick="closeApiTokenSection()" style="position:absolute;top:8px;right:8px;background:none;border:none;font-size:20px;color:#e65100;cursor:pointer;width:28px;height:28px;display:flex;align-items:center;justify-content:center;" title="Hide">&times;</button>
            <div style="padding:12px;">
                <div style="font-size:13px;font-weight:500;color:#e65100;margin-bottom:8px;">My API Token</div>
                <div style="display:flex;gap:8px;align-items:center;">
                    <input type="password" id="apiTokenDisplay" value="%s" readonly
                           style="flex:1;padding:8px;border:1px solid #f57c00;font-family:monospace;font-size:12px;">
                    <button class="btn" onclick="toggleTokenVisibility()">Show</button>
                    <button class="btn" onclick="copyToken()">Copy</button>
                </div>
                <div style="font-size:11px;color:#e65100;margin-top:8px;">
                    Use with: <code style="background:#fff0e0;padding:1px 4px">?u=%s&amp;token=TOKEN</code>
                </div>
            </div>
        </div>`, user.APIToken, user.UUID)

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <title>` + snd.Cfg.SiteName + ` — ` + user.Username + `</title>
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
            display: block;
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
        .props-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .props-table td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
        .props-table td:first-child { color: #666; width: 38%; white-space: nowrap; }
        .props-table tr:last-child td { border-bottom: none; }
        /* csa overrides */
        .csa-bar { display: none !important; }
        .csa-progress-fill { background: #e07820 !important; }
        .csa-progress-thumb { background: #e07820 !important; box-shadow: 0 0 10px rgba(224,120,32,.5) !important; }
        @media (max-width: 768px) {
            .keyboard-hint { display: none; }
            .upload-section, .files-section, .bulk-actions, .progress-section { padding: 16px; }
            .file-item { grid-template-columns: auto auto 1fr; }
            .file-actions { grid-column: 3; width: 100%; justify-content: flex-end; }
            .modal-content { width: 95%; margin: 20px auto; max-height: calc(100vh - 40px); }
        }

        /* Liquid Glass */
        body.th-liquid .header, body.th-liquid .upload-section, body.th-liquid .files-section,
        body.th-liquid .file-item, body.th-liquid .bulk-actions, body.th-liquid .progress-section,
        body.th-liquid #breadcrumb, body.th-liquid .container, body.th-liquid .card, body.th-liquid .modal-content {
            background: rgba(255,255,255,0.08) !important;
            backdrop-filter: blur(24px) saturate(180%) !important;
            -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
            border-color: rgba(255,255,255,0.18) !important;
            box-shadow: 0 8px 32px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.3) !important;
        }
        body.th-liquid .file-item { border-radius: 12px !important; margin-bottom: 4px !important; }
        body.th-liquid .file-name { color: rgba(255,255,255,0.88) !important; }
        body.th-liquid .file-meta { color: rgba(255,255,255,0.5) !important; }
        body.th-liquid .file-link { color: rgba(150,200,255,0.8) !important; }
        body.th-liquid h1, body.th-liquid h2, body.th-liquid h3 { color: rgba(255,255,255,0.92) !important; }
        body.th-liquid input, body.th-liquid select { background: rgba(255,255,255,0.10) !important; border-color: rgba(255,255,255,0.2) !important; color: #fff !important; }
        body.th-liquid .upload-area { background: rgba(255,255,255,0.05) !important; border-color: rgba(255,255,255,0.2) !important; }
        body.th-liquid .upload-text { color: rgba(255,255,255,0.6) !important; }
        body.th-liquid .menu-btn { background: rgba(255,255,255,0.12) !important; border-color: rgba(255,255,255,0.2) !important; color: rgba(255,255,255,0.85) !important; }
        body.th-liquid .context-menu { background: rgba(20,20,30,0.92) !important; backdrop-filter: blur(20px) !important; border-color: rgba(255,255,255,0.15) !important; position: fixed !important; z-index: 99999 !important; top: auto !important; right: auto !important; left: auto !important; }
        body.th-liquid .context-menu-item { color: rgba(255,255,255,0.8) !important; }
        body.th-liquid .context-menu-item:hover { background: rgba(255,255,255,0.12) !important; }
        body.th-liquid:not(.th-rainbow):not(.th-dark) { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%) !important; }
        body.th-dark .file-item { background: #181818 !important; border-color: #2a2a2a !important; }
        body.th-dark .header { background: #111 !important; border-color: #2a2a2a !important; }
        body.th-dark input, body.th-dark select { background: #111 !important; border-color: #333 !important; color: #ddd !important; }
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
            <h1>` + snd.Cfg.SiteName + ` <span style="font-size:14px;font-weight:400;color:#888">/ ` + user.Username + `</span></h1>
            <div class="header-actions">
                <span class="keyboard-hint">Ctrl+F: Search | Ctrl+A: Select All</span>
                <button class="btn" onclick="openCreateFolderModal()" data-i18n="nav_new_folder">New Folder</button>
                <a href="/ad" class="btn" data-i18n="nav_my_account">My Account</a>
                <a href="/logout" class="btn" style="background:#c62828;" data-i18n="nav_logout">Logout</a>
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
            <span id="selectedCount" style="font-size:14px;color:#666;">0 selected</span>
            <button class="btn-small" onclick="downloadSelectedAsZip()">Download as ZIP</button>
            <button class="btn-small" onclick="deselectAll()">Deselect All</button>
        </div>

        <div class="files-section" id="filesSection">
            <div class="empty-state">Loading...</div>
        </div>
    </div>

    <!-- View Modal -->
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
        <strong>` + snd.Cfg.SiteName + `</strong> — ` + user.Username + ` — v` + snd.VERSION + `
    </div>

    <script>
        let currentPath = '';
        const USER_UUID = '` + user.UUID + `';
        const USER_TOKEN = '` + user.APIToken + `';
        let startTime, currentEditFile, currentRenameFile;
        let allFiles = [];
        let allFolders = [];
        let selectedFiles = new Set();
        let bulkMode = false;

        function closeApiTokenSection() {
            const s = document.getElementById('apiTokenSection');
            if (s) { s.style.display = 'none'; localStorage.setItem('hideApiToken_user','true'); }
        }
        document.addEventListener('DOMContentLoaded', function() {
            if (localStorage.getItem('hideApiToken_user') === 'true') {
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
            navigator.clipboard.writeText(USER_TOKEN)
                .then(() => showToast('Token copied!','success'))
                .catch(() => showToast('Failed to copy','error'));
        }
        function addTokenToURL(url) {
            return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(USER_TOKEN);
        }
        function makePublicURL(filename) {
            return window.location.origin + '/raw/' + encodeURIComponent(filename) + '?u=' + USER_UUID;
        }
        function makePrivateURL(filename) {
            return window.location.origin + '/raw/' + encodeURIComponent(filename) + '?u=' + USER_UUID + '&token=' + USER_TOKEN;
        }

        // Navigation
        function navigateToFolder(folderName) { currentPath = folderName; loadFiles(); updateBreadcrumb(); }
        function navigateToRoot() { currentPath = ''; loadFiles(); updateBreadcrumb(); }

        function updateBreadcrumb() {
            const bc = document.getElementById('breadcrumb');
            if (!bc) return;
            if (currentPath === '') { bc.innerHTML = '<span style="color:#666;">Root</span>'; return; }
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

        // Search
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
            const matchFiles = allFiles.filter(f => f.name.toLowerCase().includes(q));
            const matchFolders = allFolders.filter(n => n.toLowerCase().includes(q));
            const all = [...matchFolders.map(n => ({name:n,isFolder:true})),...matchFiles.map(f=>({name:f.name,isFolder:false,type:f.type,size:f.size}))];
            if (!all.length) { res.innerHTML = '<div class="search-item" style="color:#999;">No results</div>'; return; }
            res.innerHTML = all.map(item => {
                const label = item.isFolder ? '&#128193; ' + escapeHtml(item.name) : escapeHtml(item.name);
                const meta = item.isFolder ? 'Folder' : (item.type + ' - ' + formatFileSize(item.size));
                return '<div class="search-item" onclick="jumpToItem(\'' + item.name.replace(/'/g,"\\'") + '\',' + item.isFolder + ')"><div><div style="font-size:14px;">' + label + '</div><div style="font-size:11px;color:#999;">' + meta + '</div></div><span style="font-size:11px;color:#0066cc;white-space:nowrap;">Jump &#8594;</span></div>';
            }).join('');
        });
        function jumpToItem(name, isFolder) {
            document.getElementById('searchOverlay').style.display = 'none';
            document.getElementById('searchInput').value = '';
            document.getElementById('searchResults').innerHTML = '';
            const id = 'snd-item-' + name.replace(/[^a-zA-Z0-9]/g, '_');
            const el = document.getElementById(id);
            if (el) { el.scrollIntoView({behavior:'smooth',block:'center'}); el.classList.add('search-highlight'); setTimeout(() => el.classList.remove('search-highlight'), 2800); }
        }

        // Bulk select
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
            if (checkbox.checked) { selectedFiles.add(filename); if (!bulkMode) { bulkMode = true; document.getElementById('bulkActions').classList.add('active'); } }
            else { selectedFiles.delete(filename); if (!selectedFiles.size) { bulkMode = false; document.getElementById('bulkActions').classList.remove('active'); } }
            updateBulkCount();
        }
        function updateBulkCount() { document.getElementById('selectedCount').textContent = selectedFiles.size + ' selected'; }
        function downloadSelectedAsZip() {
            if (!selectedFiles.size) return;
            fetch('/zip-multiple', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({files:Array.from(selectedFiles)})})
                .then(r => r.blob()).then(blob => { const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='files_'+Date.now()+'.zip'; a.click(); showToast('Downloaded as ZIP','success'); })
                .catch(() => showToast('Failed to create ZIP','error'));
        }

        // Context menu
        function toggleContextMenu(e, id) {
            e.stopPropagation();
            document.querySelectorAll('.context-menu').forEach(m => { if (m.id !== 'menu-' + id) m.classList.remove('show'); });
            const menu = document.getElementById('menu-' + id);
            // FIX: liquid glass uses position:fixed on context-menu to escape backdrop-filter stacking context
            if (document.body.classList.contains('th-liquid')) {
                const btn = e.currentTarget || e.target;
                const rect = btn.getBoundingClientRect();
                const menuW = 200;
                let top = rect.bottom + 4;
                let right = window.innerWidth - rect.right;
                if (top + 200 > window.innerHeight) {
                    top = Math.max(4, rect.top - 4 - 200);
                }
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

        // Upload
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const selectedFilesDiv = document.getElementById('selectedFiles');
        fileInput.addEventListener('change', updateSelectedFiles);
        uploadArea.addEventListener('dragover', e => { e.preventDefault(); uploadArea.classList.add('dragover'); });
        uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('dragover'));
        uploadArea.addEventListener('drop', e => { e.preventDefault(); uploadArea.classList.remove('dragover'); fileInput.files = e.dataTransfer.files; updateSelectedFiles(); });

        function updateSelectedFiles() {
            const files = fileInput.files;
            if (!files.length) { selectedFilesDiv.style.display = 'none'; return; }
            let html = '<strong>Selected (' + files.length + '):</strong><br>';
            for (let i = 0; i < files.length; i++) html += '<div>' + escapeHtml(files[i].name) + ' (' + (files[i].size/1024).toFixed(1) + ' KB)</div>';
            selectedFilesDiv.innerHTML = html;
            selectedFilesDiv.style.display = 'block';
        }

        const CHUNK_SIZE = 4 * 1024 * 1024;

        function uploadFiles() {
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
            let totalBytes = 0, uploadedBytes = 0;
            for (let f of files) totalBytes += f.size;
            const uploadQueue = Array.from(files);
            let fileIdx = 0;
            function uploadNextFile() {
                if (fileIdx >= uploadQueue.length) { finishUpload(uploadQueue.length); return; }
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
                }, uploadNextFile, function(err) { showToast('Upload failed: ' + err + ' — ' + file.name, 'error'); uploadNextFile(); });
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
            let offset = 0, bytesSentForProgress = 0;
            function sendChunk(retries) {
                if (retries === undefined) retries = 3;
                const isFinal = (offset + CHUNK_SIZE) >= totalSize;
                const chunk = file.slice(offset, offset + CHUNK_SIZE);
                const chunkSize = chunk.size;
                const params = new URLSearchParams({filename: file.name, offset: offset, total: totalSize, final: isFinal ? '1' : '0'});
                if (path) params.set('path', path);
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/upload-chunk?' + params.toString());
                xhr.upload.addEventListener('progress', function(e) {
                    if (e.lengthComputable) { const delta = e.loaded - bytesSentForProgress; if (delta > 0) { bytesSentForProgress = e.loaded; onProgress(delta); } }
                });
                xhr.addEventListener('load', function() {
                    if (xhr.status === 200) {
                        const delta = chunkSize - bytesSentForProgress; if (delta > 0) onProgress(delta);
                        bytesSentForProgress = 0; offset += chunkSize;
                        if (isFinal) onDone(); else setTimeout(sendChunk, 0);
                    } else { if (retries > 0) setTimeout(() => sendChunk(retries-1), 2000); else onError('Server error ' + xhr.status); }
                });
                xhr.addEventListener('error', function() { if (retries > 0) setTimeout(() => sendChunk(retries-1), 3000); else onError('Network error'); });
                xhr.addEventListener('abort', function() { onError('Upload aborted'); });
                xhr.send(chunk);
            }
            sendChunk();
        }

        // Load files
        function loadFiles() {
            const url = currentPath ? '/files?path=' + encodeURIComponent(currentPath) : '/files';
            fetch(url).then(r => { if (!r.ok) throw new Error(); return r.json(); }).then(data => {
                allFiles = data.files || [];
                allFolders = data.folders || [];
                const section = document.getElementById('filesSection');
                if (!allFolders.length && !allFiles.length) { section.innerHTML = '<div class="empty-state">No files or folders here</div>'; return; }
                let html = '';
                allFolders.forEach(folder => {
                    const fullPath = currentPath ? currentPath + '/' + folder : folder;
                    const escapedFP = fullPath.replace(/'/g, "\\'");
                    const escapedF = folder.replace(/'/g, "\\'");
                    const safeId = 'snd-item-' + folder.replace(/[^a-zA-Z0-9]/g, '_');
                    html += '<div class="file-item" id="' + safeId + '" style="background:#f9f9f9;">';
                    html += '<input type="checkbox" class="checkbox file-checkbox" style="visibility:hidden;" disabled>';
                    html += '<div style="font-size:28px;line-height:1;width:72px;display:flex;align-items:center;justify-content:center;">&#128193;</div>';
                    html += '<div class="file-info" onclick="navigateToFolder(\'' + escapedFP + '\')" style="cursor:pointer;">';
                    html += '<div class="file-name" style="font-weight:600;">' + escapeHtml(folder);
                    html += '<span class="file-type-badge" style="background:#e3f2fd;color:#1976d2">FOLDER</span>';
                    html += '<label class="toggle-switch" style="margin-left:8px;vertical-align:middle;" onclick="event.stopPropagation();" title="Public / Private">';
                    html += '<input type="checkbox" id="ftoggle-' + safeId + '" onchange="toggleFolderPublic(\'' + escapedFP + '\',this.checked)">';
                    html += '<span class="toggle-slider"></span></label>';
                    html += '</div><div class="file-meta" style="color:#999;">Click to open</div></div>';
                    html += '<div class="file-actions">';
                    html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'folder-' + safeId + '\');return false;">&#8942;</button>';
                    html += '<div class="context-menu" id="menu-folder-' + safeId + '">';
                    html += '<div class="context-menu-item" onclick="renameFolderDialog(\'' + escapedFP + '\',\'' + escapedF + '\')">Rename Folder</div>';
                    html += '<div class="context-menu-item" onclick="showFolderProperties(\'' + escapedFP + '\')">Properties</div>';
                    html += '<div class="context-menu-item danger" onclick="deleteFolder(\'' + escapedFP + '\')">Delete Folder</div>';
                    html += '</div></div></div>';
                });
                allFolders.forEach(folder => {
                    const fullPath = currentPath ? currentPath + '/' + folder : folder;
                    const safeId = 'snd-item-' + folder.replace(/[^a-zA-Z0-9]/g, '_');
                    fetch('/folder-info/' + encodeURIComponent(fullPath)).then(r => r.json()).then(d => { const cb = document.getElementById('ftoggle-' + safeId); if (cb) cb.checked = d.is_public; }).catch(() => {});
                });
                setPreviewFiles(allFiles);
                allFiles.forEach(f => {
                    const fullFileName = currentPath ? currentPath + '/' + f.name : f.name;
                    const pubURL = makePublicURL(fullFileName);
                    const privURL = makePrivateURL(fullFileName);
                    const displayURL = f.is_public ? pubURL : privURL;
                    const esc = fullFileName.replace(/'/g,"\\'").replace(/"/g,'&quot;');
                    const isPublic = f.is_public || false;
                    const modDate = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';
                    const badgeStyles = {text:'background:#e8f5e9;color:#2e7d32',image:'background:#e3f2fd;color:#1976d2',video:'background:#fce4ec;color:#c2185b',audio:'background:#f3e5f5;color:#7b1fa2',archive:'background:#fff3e0;color:#f57c00',document:'background:#ffebee;color:#d32f2f'};
                    const badgeStyle = badgeStyles[f.type] || 'background:#f5f5f5;color:#616161';
                    const safeFileId = 'snd-item-' + f.name.replace(/[^a-zA-Z0-9]/g, '_');
                     html += '<div class="file-item" id="' + safeFileId + '">';
                     html += '<input type="checkbox" class="checkbox file-checkbox" onchange="toggleFileSelect(\'' + esc + '\',this)">';
                     // Thumbnail / Icon shown first
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
                     html += '<div class="file-name">' + escapeHtml(f.name) + '<span class="file-type-badge" style="' + badgeStyle + '">' + f.type + '</span>';
                     html += '<label class="toggle-switch" style="margin-left:8px;vertical-align:middle;" onclick="event.stopPropagation();"><input type="checkbox" ' + (isPublic ? 'checked' : '') + ' onchange="togglePublicSwitch(\'' + esc + '\',this.checked)"><span class="toggle-slider"></span></label>';
                     html += '</div>';
                     html += '<div class="file-meta">' + formatFileSize(f.size) + ' - ' + modDate;
                     if (f.download_count > 0) html += ' - ' + f.download_count + ' downloads';
                     html += '</div>';
                     html += '<div class="file-link" onclick="copyLink(\'' + esc + '\')" title="Click to copy">' + escapeHtml(displayURL) + '</div>';
                     html += '</div>';
                    html += '<div class="file-actions">';
                    html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'' + safeFileId + '\');return false;">&#8942;</button>';
                    html += '<div class="context-menu" id="menu-' + safeFileId + '">';
                    const viewLabel = (f.type === 'video' || f.type === 'audio') ? 'Play' : 'View';
                    html += '<div class="context-menu-item" onclick="viewFile(\'' + esc + '\',\'' + f.type + '\')">' + viewLabel + '</div>';
                    html += '<div class="context-menu-item" onclick="editFile(\'' + esc + '\')">Edit</div>';
                    html += '<div class="context-menu-item" onclick="downloadFile(\'' + esc + '\')">Download</div>';
                    html += '<div class="context-menu-item" onclick="copyLink(\'' + esc + '\')">Copy link</div>';
                    html += '<div class="context-menu-item" onclick="downloadAsZip(\'' + esc + '\')">Download as ZIP</div>';
                    if (f.type === 'archive') {
                        html += '<div class="context-menu-item" onclick="extractArchive(\'' + esc + '\')">&#128194; Extract here</div>';
                    }
                    html += '<div class="context-menu-item" onclick="renameFile(\'' + esc + '\')">Rename</div>';
                    html += '<div class="context-menu-item" onclick="duplicateFile(\'' + esc + '\')">Duplicate</div>';
                    html += '<div class="context-menu-item danger" onclick="deleteFile(\'' + esc + '\')">Delete</div>';
                    html += '</div></div></div>';
                });
                section.innerHTML = html;
                applyDirectLinksVisibility(_showDirectLinks);
            }).catch(() => { document.getElementById('filesSection').innerHTML = '<div class="empty-state">Error loading files. Please refresh.</div>'; });
        }

        function togglePublicSwitch(filename, isPublic) {
            fetch('/set-permission', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename, is_public: isPublic})})
                .then(r => r.json()).then(() => { showToast(filename + ' is now ' + (isPublic ? 'PUBLIC' : 'PRIVATE'),'success'); loadFiles(); })
                .catch(() => { showToast('Failed to update permission','error'); loadFiles(); });
        }
        function copyLink(filename) {
            const f = allFiles.find(x => (currentPath ? currentPath+'/'+x.name : x.name) === filename || x.name === filename);
            // FIX: use full path (filename) not just basename so subfolder files work
            const url = (f && f.is_public) ? makePublicURL(filename) : makePrivateURL(filename);
            navigator.clipboard.writeText(url).then(() => showToast('Link copied!','success')).catch(() => showToast('Failed to copy','error'));
        }
        function getAuthToken() {
            const el = document.getElementById('apiTokenDisplay');
            return el ? el.value : '';
        }

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
            const streamUrl = '/stream/' + encodeURIComponent(filename);
            const authStreamUrl = addTokenToURL(streamUrl);
            const rawUrl = '/api/view/' + encodeURIComponent(filename);
            const baseName = filename.split('/').pop();

            if (type === 'image') {
                document.getElementById('viewTitle').textContent = baseName;
                document.getElementById('viewBody').innerHTML =
                    '<div style="text-align:center;padding:8px;"><img src="' + rawUrl + '" style="max-width:100%;max-height:70vh;object-fit:contain;border-radius:4px;" alt="'+escapeHtml(baseName)+'"></div>' +
                    '<div style="text-align:center;margin-top:12px;"><button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> <button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
                document.getElementById('viewModal').style.display = 'block';
                return;
            }

            if (type === 'video' || type === 'audio') {
                const ext = filename.split('.').pop().toLowerCase();
                if (ext === 'm3u8') {
                    document.getElementById('viewTitle').textContent = baseName;
                    document.getElementById('viewBody').innerHTML =
                        '<video id="hlsPlayer" controls autoplay playsinline style="width:100%;max-height:70vh;background:#000;border-radius:4px;"></video>' +
                        '<div style="text-align:center;margin-top:12px;"><button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> <button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
                    document.getElementById('viewModal').style.display = 'block';
                    const v = document.getElementById('hlsPlayer');
                    if (typeof Hls !== 'undefined' && Hls.isSupported()) {
                        const h = new Hls(); h.loadSource(streamUrl); h.attachMedia(v); v.play().catch(()=>{});
                    } else if (v.canPlayType('application/vnd.apple.mpegurl')) { v.src = streamUrl; v.play().catch(()=>{}); }
                    v.addEventListener('ended', () => advancePreview(1));
                } else if (typeof csa !== 'undefined' && csa.player) {
                    csa.player({
                        src: authStreamUrl, title: baseName, mode: 'modal', autoplay: true,
                        loader: 'ring', theme: { accent: '#e07820', accent2: '#ffaa55' },
                        onEnded: () => advancePreview(1)
                    });
                } else {
                    document.getElementById('viewTitle').textContent = baseName;
                    const tag = type === 'audio' ? 'audio' : 'video';
                    const style = type === 'audio' ? 'width:100%;margin:20px 0;' : 'width:100%;max-height:70vh;background:#000;border-radius:4px;';
                    document.getElementById('viewBody').innerHTML =
                        '<'+tag+' id="mediaPlayer" controls autoplay playsinline style="'+style+'" onended="advancePreview(1)"><source src="'+authStreamUrl+'"></'+tag+'>' +
                        '<div style="text-align:center;margin-top:12px;"><button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> <button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
                    document.getElementById('viewModal').style.display = 'block';
                }
                return;
            }
            viewFile(filename, type);
        }

        function advancePreview(dir) {
            if (!_previewFiles.length) return;
            const mediaTypes = ['image','video','audio'];
            let next = _previewIdx + dir;
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

        function viewFile(filename, type) {
            const rawUrl = addTokenToURL('/raw/' + encodeURIComponent(filename));
            const streamUrl = addTokenToURL('/stream/' + encodeURIComponent(filename));
            const baseName = filename.split('/').pop();
            if (type === 'video' || type === 'audio') { csa.player({src: streamUrl, title: baseName, mode: 'modal', autoplay: true, loader: 'ring', theme: {accent: '#e07820', accent2: '#ffaa55'}}); return; }
            const viewBody = document.getElementById('viewBody');
            document.getElementById('viewTitle').textContent = baseName;
            document.getElementById('viewModal').style.display = 'block';
            if (type === 'image') { viewBody.innerHTML = '<div class="media-viewer" id="imageViewer"><div class="media-viewer-inner" id="imageInner"><img src="' + rawUrl + '" id="zoomableImage"></div><div class="zoom-hint" id="zoomHint">Click to zoom in</div></div>'; setupImageZoom(); return; }
            if (type === 'archive') { viewZipContents(filename); return; }
            viewBody.innerHTML = '<div style="color:#999;padding:24px;text-align:center;">Loading...</div>';
            fetch(rawUrl).then(r => r.text()).then(c => { viewBody.innerHTML = '<pre style="white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:12px;line-height:1.6;background:#f5f5f5;padding:16px;border-radius:4px;overflow:auto;max-height:62vh;"></pre>'; viewBody.querySelector('pre').textContent = c; }).catch(() => { viewBody.innerHTML = '<div style="padding:24px;color:#d32f2f;">Failed to load file.</div>'; });
        }
        function setupImageZoom() {
            const viewer = document.getElementById('imageViewer'), inner = document.getElementById('imageInner'), img = document.getElementById('zoomableImage'), hint = document.getElementById('zoomHint');
            if (!viewer || !img) return;
            let scale = 1, panning = false, pointX = 0, pointY = 0, startX = 0, startY = 0;
            function setT() { inner.style.transform = 'translate(' + pointX + 'px,' + pointY + 'px) scale(' + scale + ')'; }
            img.addEventListener('click', e => { e.stopPropagation(); if (scale === 1) { scale = 2; viewer.classList.add('zoomed'); hint.textContent = 'Drag to pan - Click to zoom out'; } else { scale = 1; pointX = 0; pointY = 0; viewer.classList.remove('zoomed'); hint.textContent = 'Click to zoom in'; } setT(); });
            viewer.addEventListener('wheel', e => { e.preventDefault(); const xs = (e.clientX-pointX)/scale, ys=(e.clientY-pointY)/scale; scale=Math.min(Math.max(0.5,scale+(e.deltaY>0?-0.2:0.2)),5); if(scale>1){pointX=e.clientX-xs*scale;pointY=e.clientY-ys*scale;viewer.classList.add('zoomed');}else{scale=1;pointX=0;pointY=0;viewer.classList.remove('zoomed');}setT(); }, {passive:false});
            viewer.addEventListener('mousedown', e => { if(scale<=1)return; e.preventDefault(); startX=e.clientX-pointX; startY=e.clientY-pointY; panning=true; });
            viewer.addEventListener('mousemove', e => { if(!panning)return; e.preventDefault(); pointX=e.clientX-startX; pointY=e.clientY-startY; setT(); });
            viewer.addEventListener('mouseup', () => panning=false);
            viewer.addEventListener('mouseleave', () => panning=false);
        }
        function editFile(filename) {
            currentEditFile = filename;
            document.getElementById('editTitle').textContent = 'Edit: ' + filename.split('/').pop();
            document.getElementById('editContent').value = 'Loading...';
            document.getElementById('editModal').style.display = 'block';
            fetch(addTokenToURL('/raw/' + encodeURIComponent(filename))).then(r => r.text()).then(c => { document.getElementById('editContent').value = c; }).catch(() => { document.getElementById('editContent').value = '// Failed to load'; });
        }
        function saveFile() {
            fetch('/save/' + encodeURIComponent(currentEditFile), {method:'POST',headers:{'Content-Type':'text/plain'},body:document.getElementById('editContent').value})
                .then(r => r.json()).then(d => { showToast(d.message,'success'); closeModal('editModal'); loadFiles(); }).catch(() => showToast('Failed to save','error'));
        }
        function downloadFile(filename) { window.location.href = addTokenToURL('/download/' + encodeURIComponent(filename)); }
        function downloadAsZip(filename) {
            fetch('/zip-multiple',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({files:[filename]})}).then(r=>r.blob()).then(blob=>{const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=filename+'.zip';a.click();});
        }
        function deleteFile(filename) {
            if (!confirm('Delete ' + filename + '?')) return;
            fetch('/delete/' + encodeURIComponent(filename), {method:'DELETE'}).then(r => r.json()).then(d => { showToast(d.message,'success'); loadFiles(); }).catch(() => showToast('Failed to delete','error'));
        }
        function renameFile(filename) { currentRenameFile = filename; document.getElementById('renameInput').value = filename; document.getElementById('renameModal').style.display = 'block'; document.getElementById('renameInput').select(); }
        function confirmRename() {
            const newName = document.getElementById('renameInput').value.trim();
            if (!newName) { showToast('Please enter a name','error'); return; }
            const mode = document.getElementById('renameModal').dataset.mode;
            if (mode === 'folder') {
                fetch('/rename-folder/' + encodeURIComponent(currentRenameFolderPath), {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_path: currentRenameFolderPath, new_name: newName})})
                    .then(r => r.json()).then(d => { if(d.success===false){showToast(d.error||'Failed to rename','error');return;} showToast('Folder renamed','success'); closeModal('renameModal'); document.getElementById('renameModal').dataset.mode=''; loadFiles(); }).catch(() => showToast('Failed to rename folder','error'));
            } else {
                fetch('/rename/' + encodeURIComponent(currentRenameFile), {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_name: newName})})
                    .then(r => r.json()).then(d => { showToast(d.message,'success'); closeModal('renameModal'); loadFiles(); }).catch(() => showToast('Failed to rename','error'));
            }
        }
        function extractArchive(filename) {
            if (!confirm('Extract "' + filename.split('/').pop() + '" here?')) return;
            showToast('Extracting...', 'success');
            fetch('/extract-zip/' + encodeURIComponent(filename), {method: 'POST'})
                .then(r => r.json())
                .then(d => {
                    if (d.success) { showToast('Extracted successfully', 'success'); loadFiles(); }
                    else showToast('Extract failed: ' + (d.error || 'unknown error'), 'error');
                })
                .catch(() => showToast('Extract failed', 'error'));
        }
        function viewZipContents(filename) {
            fetch('/zip-view/' + encodeURIComponent(filename)).then(r => r.json()).then(data => {
                document.getElementById('viewTitle').textContent = filename.split('/').pop() + ' (contents)';
                let html = '<div style="font-family:monospace;font-size:12px;">';
                html += '<div style="margin-bottom:12px;padding:10px;background:#f5f5f5;border:1px solid #e0e0e0;border-radius:4px;"><strong>' + (data.files||[]).length + ' files</strong> — Total: ' + formatFileSize(data.total_size||0) + '</div>';
                (data.files||[]).forEach(f => { html += '<div style="padding:8px 12px;border-bottom:1px solid #f0f0f0;"><strong>' + escapeHtml(f.name) + '</strong><span style="color:#999;margin-left:16px;">' + formatFileSize(f.size) + '</span></div>'; });
                html += '</div>';
                document.getElementById('viewBody').innerHTML = html;
            }).catch(() => showToast('Failed to read archive', 'error'));
        }
        function duplicateFile(filename) {
            fetch('/duplicate/' + encodeURIComponent(filename),{method:'POST'}).then(r=>r.json()).then(d=>{showToast(d.message,'success');loadFiles();}).catch(()=>showToast('Failed to duplicate','error'));
        }
        function toggleFolderPublic(folderPath, isPublic) {
            fetch('/set-folder-permission',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:folderPath,is_public:isPublic})}).then(r=>r.json()).then(()=>showToast(folderPath.split('/').pop()+' is now '+(isPublic?'PUBLIC':'PRIVATE'),'success')).catch(()=>showToast('Failed','error'));
        }
        let currentRenameFolderPath = '';
        function renameFolderDialog(fullPath, name) { currentRenameFolderPath=fullPath; document.getElementById('renameInput').value=name; document.getElementById('renameModal').style.display='block'; document.getElementById('renameInput').select(); document.getElementById('renameModal').dataset.mode='folder'; }
        function showFolderProperties(folderPath) {
            document.getElementById('propsTitle').textContent = folderPath.split('/').pop() + '/';
            document.getElementById('propsBody').innerHTML = '<div style="color:#999;padding:24px;text-align:center;">Loading...</div>';
            document.getElementById('propsModal').style.display = 'block';
            fetch('/folder-info/' + encodeURIComponent(folderPath)).then(r=>r.json()).then(d=>{
                document.getElementById('propsBody').innerHTML = '<table class="props-table"><tr><td>Name</td><td><strong>'+escapeHtml(d.name)+'/</strong></td></tr><tr><td>Files</td><td>'+d.file_count+'</td></tr><tr><td>Subfolders</td><td>'+d.folder_count+'</td></tr><tr><td>Total size</td><td>'+formatFileSize(d.total_size)+'</td></tr><tr><td>Visibility</td><td>'+(d.is_public?'<span style="color:#2e7d32;font-weight:600;">Public</span>':'<span style="color:#d32f2f;font-weight:600;">Private</span>')+'</td></tr></table>';
            }).catch(()=>{document.getElementById('propsBody').innerHTML='<div style="color:#d32f2f;padding:12px;">Failed to load info.</div>';});
        }
        function deleteFolder(folderName) {
            if (!confirm('Delete folder "' + folderName + '" and all contents?')) return;
            fetch('/delete-folder/' + encodeURIComponent(folderName),{method:'DELETE'}).then(r=>r.json()).then(d=>{showToast(d.message,'success');loadFiles();}).catch(()=>showToast('Failed to delete folder','error'));
        }
        function openCreateFolderModal() { document.getElementById('folderNameInput').value=''; document.getElementById('createFolderModal').style.display='block'; document.getElementById('folderNameInput').focus(); }
        function confirmCreateFolder() {
            const folderName = document.getElementById('folderNameInput').value.trim();
            if (!folderName) { showToast('Please enter a folder name','error'); return; }
            fetch('/create-folder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:folderName,current_path:currentPath})}).then(r=>r.json()).then(d=>{showToast(d.message,'success');closeModal('createFolderModal');loadFiles();}).catch(()=>showToast('Failed to create folder','error'));
        }

        function closeModal(id) { document.getElementById(id).style.display = 'none'; }
        window.onclick = function(e) { if (e.target.classList.contains('modal')) closeModal(e.target.id); };

        function showToast(msg, type = 'success') {
            const t = document.createElement('div'); t.className = 'toast ' + type; t.textContent = msg; document.body.appendChild(t); setTimeout(() => t.remove(), 3000);
        }
        function escapeHtml(text) { const d = document.createElement('div'); d.textContent = text; return d.innerHTML; }
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B'; if (bytes < 1024) return bytes + ' B';
            const units = ['KB','MB','GB','TB']; let i=0, size=bytes/1024;
            while (size >= 1024 && i < units.length-1) { size/=1024; i++; }
            return size.toFixed(2) + ' ' + units[i];
        }


        // ─── User Settings ────────────────────────────────────────────────────
        function openSettingsPanel() {
            fetch('/user/settings').then(r=>r.json()).then(data => {
                const s = data.settings || {};
                const allowTheme = data.allow_theme;
                const modal = document.getElementById('settingsModal');
                document.getElementById('us-bg').value = s.background_url || '';
                document.getElementById('us-music').value = s.bg_music_url || '';
                document.getElementById('us-lang').value = s.language || 'en';
                document.getElementById('us-direct-links').checked = s.show_direct_links !== false;
                const themeRow = document.getElementById('us-theme-row');
                if (themeRow) themeRow.style.display = allowTheme ? '' : 'none';
                if (document.getElementById('us-theme')) document.getElementById('us-theme').value = s.theme || 'default';
                modal.style.display = 'flex';
                if (s.bg_music_url) applyUserBgMusic(s.bg_music_url);
            }).catch(() => showToast('Failed to load settings','error'));
        }

        function closeSettingsModal() { document.getElementById('settingsModal').style.display = 'none'; }

        async function saveUserSettings() {
            const s = {
                theme: document.getElementById('us-theme') ? document.getElementById('us-theme').value : 'default',
                background_url: document.getElementById('us-bg').value,
                bg_music_url: document.getElementById('us-music').value,
                language: document.getElementById('us-lang').value,
                show_direct_links: document.getElementById('us-direct-links').checked
            };
            const res = await fetch('/user/settings/save', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(s) });
            if (res.ok) {
                showToast('Settings saved','success');
                closeSettingsModal();
                applyUserBgMusic(s.bg_music_url);
                applyDirectLinksVisibility(s.show_direct_links);
            } else showToast('Failed to save settings','error');
        }

        // Track direct links preference
        let _showDirectLinks = true;
        function applyDirectLinksVisibility(show) {
            _showDirectLinks = show !== false;
            document.querySelectorAll('.file-link').forEach(el => el.style.display = _showDirectLinks ? '' : 'none');
        }

        function applyUserBgMusic(url) {
            let audio = document.getElementById('bgMusicPlayer');
            if (!url) { if (audio) { audio.pause(); audio.remove(); } return; }
            if (!audio) {
                audio = document.createElement('audio');
                audio.id = 'bgMusicPlayer'; audio.loop = true; audio.volume = 0.3;
                document.body.appendChild(audio);
            }
            if (audio.src !== url) { audio.src = url; audio.play().catch(()=>{}); }
        }

        // Load settings first to apply show_direct_links, then load files
        fetch('/user/settings').then(r=>r.json()).then(data => {
            const s = data.settings || data;
            _showDirectLinks = s.show_direct_links !== false;
            loadFiles();
            if (s.bg_music_url) applyUserBgMusic(s.bg_music_url);
        }).catch(() => { _showDirectLinks = true; loadFiles(); });
    </script>

` + snd.ThemeSnippet("dashboard") + `

    <!-- User Settings Modal -->
    <div id="settingsModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.45);z-index:300;align-items:center;justify-content:center;">
        <div style="background:#fff;border-radius:8px;padding:24px;width:440px;max-width:90vw;max-height:85vh;overflow-y:auto;">
            <h2 style="font-size:18px;font-weight:500;margin-bottom:20px;">&#9881; User Settings</h2>
            <div id="us-theme-row" style="margin-bottom:14px;">
                <label style="font-size:13px;color:#666;">Theme</label>
                <select id="us-theme" style="width:100%;padding:8px;border:1px solid #d0d0d0;margin-top:4px;">
                    <option value="default">Default</option>
                    <option value="dark">Dark</option>
                    <option value="rainbow">Rainbow</option>
                </select>
            </div>
            <div style="margin-bottom:14px;">
                <label style="font-size:13px;color:#666;">Background Image/GIF URL</label>
                <input type="text" id="us-bg" placeholder="https://..." style="width:100%;padding:8px;border:1px solid #d0d0d0;margin-top:4px;">
            </div>
            <div style="margin-bottom:14px;">
                <label style="font-size:13px;color:#666;">Background Music URL</label>
                <input type="text" id="us-music" placeholder="https://..." style="width:100%;padding:8px;border:1px solid #d0d0d0;margin-top:4px;">
            </div>
            <div style="margin-bottom:14px;">
                <label style="font-size:13px;color:#666;">Language</label>
                <select id="us-lang" style="width:100%;padding:8px;border:1px solid #d0d0d0;margin-top:4px;">
                    <option value="en">English</option>
                    <option value="vi">Ti&#7871;ng Vi&#7879;t</option>
                    <option value="zh">&#20013;&#25991;</option>
                    <option value="ja">&#26085;&#26412;&#35486;</option>
                </select>
            </div>
            <div style="margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;">
                <label style="font-size:13px;color:#666;">Show Direct File Link</label>
                <label class="toggle-switch"><input type="checkbox" id="us-direct-links"><span class="toggle-slider"></span></label>
            </div>
            <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:20px;">
                <button onclick="closeSettingsModal()" style="padding:9px 18px;background:none;border:1px solid #ddd;cursor:pointer;border-radius:4px;">Cancel</button>
                <button onclick="saveUserSettings()" style="padding:9px 18px;background:#1a1a1a;color:white;border:none;cursor:pointer;border-radius:4px;">Save</button>
            </div>
        </div>
    </div>
<script>
// FIX: Language system — fetch translations and apply data-i18n attributes
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
        window._lang = t;
    }).catch(function(){});
})();
</script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
