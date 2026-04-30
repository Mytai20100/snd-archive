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

	// Footer + custom CSS
	userFooterHTML := ""
	userCustomCSSTag := ""
	snd.SiteSettingsMu.RLock()
	hideFooter := snd.SiteSettingsData.HideFooter
	customCSS  := snd.SiteSettingsData.CustomCSS
	snd.SiteSettingsMu.RUnlock()
	if !hideFooter {
		userFooterHTML = `<div class="footer"><strong>` + snd.Cfg.SiteName + `</strong> — ` + user.Username + ` — v` + snd.VERSION + `</div>`
	}
	if customCSS != "" {
		userCustomCSSTag = `<style id="snd-custom-css">` + customCSS + `</style>`
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
    ` + snd.EmbedLoaderSnippet() + `
    <link rel="stylesheet" href="/css/main.css">
    <style>
        /* userdash extras: liquid glass with dark theme support */
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
    <script>
        /* Early shim so openDownloadURLModal() is safe before userdash.js loads */
        window._dlUrlPending = false;
        window.openDownloadURLModal = function() { window._dlUrlPending = true; };
    </script>
</head>
<body>
    <div class="search-overlay" id="searchOverlay">
        <div class="search-box">
            <input type="text" class="search-input" id="searchInput" placeholder="Search files..." data-i18n-placeholder="search_placeholder" autocomplete="off">
            <div class="search-results" id="searchResults"></div>
            <div class="search-hint" data-i18n="search_esc_hint">Press ESC to close</div>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1>` + snd.Cfg.SiteName + ` <span style="font-size:14px;font-weight:400;color:#888">/ ` + user.Username + `</span></h1>
            <div class="header-actions">
                <span class="keyboard-hint">Ctrl+F: Search | Ctrl+A: Select All</span>
                <button class="btn" onclick="openCreateFolderModal()" data-i18n="nav_new_folder">New Folder</button>
                <button class="btn" onclick="openDownloadURLModal()" title="Download file from URL" data-i18n="nav_download_url">Download URL</button>
                <a href="/ad" class="btn" data-i18n="nav_my_account">My Account</a>
                <a href="/logout" class="btn" style="background:#c62828;" data-i18n="nav_logout">Logout</a>
            </div>
        </div>
        <div style="padding:12px 20px;background:#f5f5f5;border-bottom:1px solid #e0e0e0;font-size:13px;" id="breadcrumb">
            <span style="color:#666;" data-i18n="ui_root">Root</span>
        </div>

        <div class="upload-section">
            <div class="upload-area" id="uploadArea">
                <input type="file" id="fileInput" multiple>
                <div class="upload-text" data-i18n="upload_drop_text">Drop files or click to upload</div>
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
                <h3 id="viewTitle" data-i18n="modal_view_file">View File</h3>
                <button class="close-btn" onclick="closeModal('viewModal')">&times;</button>
            </div>
            <div class="modal-body" id="viewBody"><pre id="viewContent"></pre></div>
        </div>
    </div>

    <!-- Edit Modal -->
    <div class="modal" id="editModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="editTitle" data-i18n="modal_edit_file">Edit File</h3>
                <button class="close-btn" onclick="closeModal('editModal')">&times;</button>
            </div>
            <div class="modal-body"><textarea id="editContent"></textarea></div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('editModal')" data-i18n="modal_cancel">Cancel</button>
                <button class="btn-small" onclick="saveFile()" data-i18n="modal_save">Save</button>
            </div>
        </div>
    </div>

    <!-- Rename Modal -->
    <div class="modal" id="renameModal">
        <div class="modal-content" style="max-width:500px;">
            <div class="modal-header">
                <h3>Rename</h3>
                <button class="close-btn" onclick="closeModal('renameModal')">&times;</button>
            </div>
            <div class="modal-body">
                <input type="text" id="renameInput" style="width:100%;padding:12px;border:1px solid #e0e0e0;font-size:14px;border-radius:4px;">
            </div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('renameModal')" data-i18n="modal_cancel">Cancel</button>
                <button class="btn-small" onclick="confirmRename()" data-i18n="modal_rename_btn">Rename</button>
            </div>
        </div>
    </div>

    <!-- Properties Modal -->
    <div class="modal" id="propsModal">
        <div class="modal-content" style="max-width:480px;">
            <div class="modal-header">
                <h3 id="propsTitle" data-i18n="modal_properties">Properties</h3>
                <button class="close-btn" onclick="closeModal('propsModal')">&times;</button>
            </div>
            <div class="modal-body" id="propsBody"></div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('propsModal')" data-i18n="modal_close">Close</button>
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
                <button class="btn-small" onclick="closeModal('createFolderModal')" data-i18n="modal_cancel">Cancel</button>
                <button class="btn-small" onclick="confirmCreateFolder()" data-i18n="modal_create">Create</button>
            </div>
        </div>
    </div>

    <!-- Download URL Modal -->
 <div class="modal" id="downloadURLModal">
        <div class="modal-content" style="max-width:520px;">
            <div class="modal-header">
                <h3>Download from URL</h3>
                <button class="close-btn" onclick="closeModal('downloadURLModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div style="font-size:13px;color:#666;margin-bottom:12px;" data-i18n="download_url_desc">Server will fetch the file from this URL and save it to the current folder.</div>
                <label style="display:block;font-size:13px;color:#555;margin-bottom:4px;">URL</label>
                <div style="display:flex;gap:8px;">
                    <input type="url" id="dlUrlInput" placeholder="https://example.com/file.zip"
                           style="flex:1;padding:10px;border:1px solid #e0e0e0;font-size:13px;border-radius:4px;box-sizing:border-box;"
                           onkeydown="if(event.key==='Enter')confirmDownloadURL()">
                    <button class="btn-small" id="dlUrlBtn" onclick="confirmDownloadURL()" data-i18n="modal_download" style="white-space:nowrap;">Download</button>
                </div>
                <div id="dlUrlQueue" style="display:none;margin-top:14px;border-top:1px solid #f0f0f0;padding-top:4px;max-height:240px;overflow-y:auto;"></div>
                <style>@keyframes _dlPulse{0%,100%{opacity:1;width:30%}50%{opacity:.6;width:60%}}</style>
            </div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('downloadURLModal')" data-i18n="modal_close">Close</button>
            </div>
        </div>
    </div>

    ` + userFooterHTML + `

    <script src="/lib/utils.js" defer></script>
    <script src="/lib/context-menu.js" defer></script>
    <script src="/lib/upload.js" defer></script>
    <script src="/lib/userdash.js" defer></script>
    <script>
        const USER_UUID  = '` + user.UUID + `';
        const USER_TOKEN = '` + user.APIToken + `';

        function addTokenToURL(url) {
            return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(USER_TOKEN);
        }
        function makePublicURL(filename, publicToken) {
            const base = window.location.origin + '/raw/' + encodeURIComponent(filename) + '?u=' + USER_UUID;
            return publicToken ? base + '&pt=' + encodeURIComponent(publicToken) : base;
        }
        function makePrivateURL(filename) {
            return window.location.origin + '/raw/' + encodeURIComponent(filename) + '?u=' + USER_UUID + '&token=' + USER_TOKEN;
        }

        document.addEventListener('DOMContentLoaded', function() {
            initUpload();
            // Flush any early click on Download URL button
            if (window._dlUrlPending) { window._dlUrlPending = false; openDownloadURLModal(); }
            // Load settings first then files
            fetch('/user/settings').then(r => r.json()).then(data => {
                const s = data.settings || data;
                _showDirectLinks = s.show_direct_links !== false;
                loadFiles();
                if (s.bg_music_url) applyUserBgMusic(s.bg_music_url);
            }).catch(() => { _showDirectLinks = true; loadFiles(); });
        });
    </script>
` + snd.ThemeSnippet("dashboard") + `
` + userCustomCSSTag + `
<script>
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
