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

	// Footer + custom CSS
	footerHTML := ""
	customCSSTag := ""
	snd.SiteSettingsMu.RLock()
	hideFooter := snd.SiteSettingsData.HideFooter
	customCSS  := snd.SiteSettingsData.CustomCSS
	snd.SiteSettingsMu.RUnlock()
	if !hideFooter {
		footerHTML = `<div class="footer">` + snd.Cfg.SiteName + ` v` + snd.VERSION + `</div>`
	}
	if customCSS != "" {
		customCSSTag = `<style id="snd-custom-css">` + customCSS + `</style>`
	}

	if isAuth {
		authStatus = "true"
		_ = isAdminUser
		authButtons = `<button class="btn" onclick="openCreateFolderModal()" data-i18n="nav_new_folder">New Folder</button>
                       <button class="btn" onclick="openDownloadURLModal()" title="Download file from URL" data-i18n="nav_download_url">Download URL</button>
                       <a href="/ad" class="btn" data-i18n="nav_admin">Admin</a>
                       <a href="#" onclick="logout(); return false;" class="btn" data-i18n="nav_logout">Logout</a>`
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
    ` + snd.EmbedLoaderSnippet() + `
    <link rel="stylesheet" href="/css/main.css">
    <style>
        /* dashboard-specific overrides */
        .upload-section { display: ` + uploadSectionDisplay + `; }
    </style>
    <script>
        /* Early shim so openDownloadURLModal() is safe to call before dashboard.js loads */
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
            <h1>` + snd.Cfg.SiteName + `</h1>
            <div class="header-actions">
                <span class="keyboard-hint">Ctrl+F: Search | Ctrl+A: Select All</span>
                ` + authButtons + `
            </div>
        </div>
        <div style="padding:12px 20px;background:#f5f5f5;border-bottom:1px solid #e0e0e0;font-size:13px;" id="breadcrumb">
            <span style="color:#666;" data-i18n="ui_root">Root</span>
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
            <button class="btn-small" onclick="downloadSelectedAsZip()" data-i18n="bulk_zip_download">ZIP Download</button>
            <button class="btn-small" onclick="bulkSetPublic(true)" style="background:#2e7d32;" data-i18n="bulk_make_public">Make Public</button>
            <button class="btn-small" onclick="bulkSetPublic(false)" style="background:#c62828;" data-i18n="bulk_make_private">Make Private</button>
            <button class="btn-small" onclick="bulkDelete()" style="background:#d32f2f;" data-i18n="bulk_delete">Delete</button>
            <button class="btn-small" onclick="deselectAll()" style="background:#555;" data-i18n="bulk_deselect">Deselect All</button>
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
                <h3>Rename File</h3>
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
                <div style="font-size:13px;color:#666;margin-bottom:12px;" data-i18n="download_url_desc">Server will fetch the file from this URL and save it to the current folder. For YouTube/Vimeo/etc. you'll get a format picker.</div>
                <label style="display:block;font-size:13px;color:#555;margin-bottom:4px;">URL</label>
                <div style="display:flex;gap:8px;">
                    <input type="url" id="dlUrlInput" placeholder="https://example.com/file.zip or youtube.com/watch?v=..."
                           style="flex:1;padding:10px;border:1px solid #e0e0e0;font-size:13px;border-radius:4px;box-sizing:border-box;"
                           oninput="_dlAdminUrlHint(this.value)"
                           onkeydown="if(event.key==='Enter')confirmDownloadURL()">
                    <button class="btn-small" id="dlUrlBtn" onclick="confirmDownloadURL()" data-i18n="modal_download" style="white-space:nowrap;">Download</button>
                </div>
                <div id="dlAdminStreamHint" style="display:none;margin-top:8px;font-size:12px;color:#1976d2;background:#e3f2fd;border-radius:4px;padding:6px 10px;">
                    Streaming platform detected — clicking Download will open the format picker.
                </div>
                <div id="dlUrlQueue" style="display:none;margin-top:14px;border-top:1px solid #f0f0f0;padding-top:4px;max-height:240px;overflow-y:auto;"></div>
                <style>@keyframes _dlPulse{0%,100%{opacity:1;width:30%}50%{opacity:.6;width:60%}}</style>
            </div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('downloadURLModal')" data-i18n="modal_close">Close</button>
            </div>
        </div>
    </div>

    <!-- Stream Format Picker Modal -->
    <div class="modal" id="streamFormatModal">
        <div class="modal-content" style="max-width:560px;">
            <div class="modal-header">
                <h3 id="streamFormatTitle">Select Format</h3>
                <button class="close-btn" onclick="closeModal('streamFormatModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div id="streamFormatInfo" style="display:flex;gap:12px;align-items:center;margin-bottom:14px;"></div>
                <div id="streamFormatLoading" style="text-align:center;padding:20px;color:#888;font-size:13px;">Fetching formats...</div>
                <div id="streamFormatList" style="display:none;max-height:320px;overflow-y:auto;"></div>
            </div>
            <div class="modal-footer">
                <button class="btn-small" onclick="closeModal('streamFormatModal')">Cancel</button>
            </div>
        </div>
    </div>

    ` + footerHTML + `

    <script src="/lib/utils.js" defer></script>
    <script src="/lib/context-menu.js" defer></script>
    <script src="/lib/upload.js" defer></script>
    <script src="/lib/dashboard.js" defer></script>
    <script src="/lib/qr.js" defer></script>
    <script>
        const isAuthenticated = ` + authStatus + `;
        // SECURITY FIX: _apiToken is only embedded for authenticated sessions.
        // Unauthenticated visitors must never see the admin API token, because
        // it could be used to bypass file-permission checks on private files.
        const _apiToken = ` + func() string {
	if isAuth {
		return "'" + snd.Cfg.APIToken + "'"
	}
	return "''"
}() + `;

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
                          document.getElementById('apiTokenDisplay').value : _apiToken;
            return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
        }
        function getAuthToken() {
            const el = document.getElementById('apiTokenDisplay');
            return el ? el.value : _apiToken;
        }

        // Init
        document.addEventListener('DOMContentLoaded', function() {
            initUpload();
            loadFiles();
            // Flush any early click on Download URL button before scripts loaded
            if (window._dlUrlPending) { window._dlUrlPending = false; openDownloadURLModal(); }
            // Load QR settings for admin
            fetch('/admin/settings').then(function(r){return r.json();}).then(function(s){
                window._qrEnabled = !!s.allow_qr;
                window._qrLogoURL = s.qr_logo_url || '';
            }).catch(function(){});
        });
    </script>
` + snd.ThemeSnippet("dashboard") + `
` + customCSSTag + `
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
