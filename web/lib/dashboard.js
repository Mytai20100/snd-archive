// dashboard.js
// Globals expected from inline script: isAuthenticated, _apiToken, addTokenToURL, getAuthToken

'use strict';

// Language helper — returns translated string or fallback
function _t(key, fallback) { return (window._lang && window._lang[key]) || fallback || key; }

let currentPath = '';
let startTime, currentEditFile, currentRenameFile;
let allFiles   = [];
let allFolders = [];
let selectedFiles = new Set();
let bulkMode = false;

let _previewFiles = [];
let _previewIdx   = -1;
function setPreviewFiles(files) { _previewFiles = files; }

function openPreviewModal(filename, type) {
    _previewIdx = _previewFiles.findIndex(f => {
        const fn = currentPath ? currentPath + '/' + f.name : f.name;
        return fn === filename;
    });
    showPreview(filename, type);
}

function showPreview(filename, type) {
    const rawUrl    = '/api/view/' + encodeURIComponent(filename);
    const streamUrl = '/stream/'   + encodeURIComponent(filename);
    const baseName  = filename.split('/').pop();

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
        openModal('viewModal');
        return;
    }

    if (type === 'video' || type === 'audio') {
        const ext = filename.split('.').pop().toLowerCase();
        if (ext === 'm3u8') {
            document.getElementById('viewTitle').textContent = baseName;
            document.getElementById('viewBody').innerHTML =
                '<video id="hlsPlayer" controls autoplay playsinline style="width:100%;max-height:70vh;background:#000;border-radius:4px;"></video>' +
                '<div style="text-align:center;margin-top:12px;">' +
                '<button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> ' +
                '<button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
            openModal('viewModal');
            const v = document.getElementById('hlsPlayer');
            if (typeof Hls !== 'undefined' && Hls.isSupported()) {
                const h = new Hls(); h.loadSource(streamUrl); h.attachMedia(v); v.play().catch(() => {});
            } else if (v.canPlayType('application/vnd.apple.mpegurl')) {
                v.src = streamUrl; v.play().catch(() => {});
            }
            v.addEventListener('ended', () => advancePreview(1));
        } else {
            if (typeof csa !== 'undefined' && csa.player) {
                csa.player({
                    src: addTokenToURL(streamUrl), title: baseName, mode: 'modal', autoplay: true,
                    loader: 'ring', theme: { accent: '#e07820', accent2: '#ffaa55' },
                    onEnded: () => advancePreview(1)
                });
            } else {
                document.getElementById('viewTitle').textContent = baseName;
                const tag   = type === 'audio' ? 'audio' : 'video';
                const style = type === 'audio' ? 'width:100%;margin:20px 0;' : 'width:100%;max-height:70vh;background:#000;border-radius:4px;';
                document.getElementById('viewBody').innerHTML =
                    '<' + tag + ' id="mediaPlayer" controls autoplay playsinline style="' + style + '" onended="advancePreview(1)">' +
                    '<source src="' + addTokenToURL(streamUrl) + '">' +
                    '</' + tag + '>' +
                    '<div style="text-align:center;margin-top:12px;">' +
                    '<button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> ' +
                    '<button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
                openModal('viewModal');
            }
        }
        return;
    }
    viewFile(filename, type);
}

function advancePreview(dir) {
    if (!_previewFiles.length) return;
    const mediaTypes = ['image', 'video', 'audio'];
    let next = _previewIdx + dir;
    while (next >= 0 && next < _previewFiles.length) {
        if (mediaTypes.includes(_previewFiles[next].type)) break;
        next += dir;
    }
    if (next < 0 || next >= _previewFiles.length) return;
    _previewIdx = next;
    const f  = _previewFiles[next];
    const fn = currentPath ? currentPath + '/' + f.name : f.name;
    showPreview(fn, f.type);
}

function navigateToFolder(folderName) { currentPath = folderName; loadFiles(); updateBreadcrumb(); }
function navigateToRoot()             { currentPath = ''; loadFiles(); updateBreadcrumb(); }

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
            html += ' / <a href="#" onclick="currentPath=\'' + np.replace(/'/g, "\\'") + '\';loadFiles();updateBreadcrumb();return false;" style="color:#0066cc;text-decoration:none;">' + escapeHtml(part) + '</a>';
        }
    });
    bc.innerHTML = html;
}

document.addEventListener('keydown', function (e) {
    if (e.ctrlKey && e.key === 'f') { e.preventDefault(); showSearch(); }
    if (e.key === 'Escape') document.getElementById('searchOverlay').style.display = 'none';
    if (e.ctrlKey && e.key === 'a') { e.preventDefault(); selectAllFiles(); }
});
function showSearch() {
    document.getElementById('searchOverlay').style.display = 'flex';
    document.getElementById('searchInput').focus();
}
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('searchInput').addEventListener('input', function (e) {
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
            return '<div class="search-item" onclick="jumpToItem(\'' + item.name.replace(/'/g, "\\'") + '\',' + item.isFolder + ')">' +
                '<div><div style="font-size:14px;">' + label + '</div><div style="font-size:11px;color:#999;">' + meta + '</div></div>' +
                '<span style="font-size:11px;color:#0066cc;white-space:nowrap;">Jump &#8594;</span>' +
                '</div>';
        }).join('');
    });
});
function jumpToItem(name) {
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

function selectAllFiles() {
    if (!bulkMode) { bulkMode = true; document.getElementById('bulkActions').classList.add('active'); }
    selectedFiles.clear();
    allFiles.forEach(f => {
        const fullFileName = currentPath ? currentPath + '/' + f.name : f.name;
        selectedFiles.add(fullFileName);
    });
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
    const files = Array.from(selectedFiles);
    Promise.all(files.map(f =>
        fetch('/set-permission', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ filename: f, is_public: isPublic }) })
    )).then(() => {
        showToast(files.length + ' ' + (isPublic ? _t('msg_files_made_public','files made public') : _t('msg_files_made_private','files made private')), 'success');
        deselectAll(); loadFiles();
    }).catch(() => showToast(_t('toast_error_permission','Some permissions failed'), 'error'));
}
function bulkDelete() {
    if (!selectedFiles.size) return;
    const files = Array.from(selectedFiles);
    showConfirm(
        _t('confirm_bulk_delete','Delete {n} file(s)? This cannot be undone.').replace('{n}', files.length),
        function () {
            Promise.all(files.map(f => fetch('/delete/' + encodeURIComponent(f), { method: 'DELETE' })))
                .then(() => { showToast(files.length + ' ' + _t('msg_files_deleted','files deleted'), 'success'); deselectAll(); loadFiles(); })
                .catch(() => showToast(_t('toast_error_delete','Some deletes failed'), 'error'));
        },
        { yesLabel: _t('btn_delete','Delete'), yesColor: '#d32f2f' }
    );
}
function downloadSelectedAsZip() {
    if (!selectedFiles.size) return;
    const files = Array.from(selectedFiles);
    showToast(_t('msg_preparing_zip', 'Preparing ZIP\u2026'), 'success');
    fetch('/zip-multiple', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files }) })
        .then(r => { if (!r.ok) throw new Error('Server error ' + r.status); return r.blob(); })
        .then(blob => {
            if (blob.size === 0) throw new Error('ZIP is empty');
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'files_' + Date.now() + '.zip';
            a.click();
            showToast(_t('toast_downloaded_zip','Downloaded as ZIP'), 'success');
        }).catch(e => showToast(_t('toast_error_zip','Failed to create ZIP') + ': ' + e.message, 'error'));
}

function loadFiles() {
    const url = currentPath ? '/files?path=' + encodeURIComponent(currentPath) : '/files';
    // Show skeleton while loading
    const section = document.getElementById('filesSection');
    if (section) section.innerHTML = _skeletonHTML();
    fetch(url)
        .then(r => { if (!r.ok) throw new Error(); return r.json(); })
        .then(data => {
            const files   = data.files   || [];
            const folders = data.folders || [];
            allFiles   = files;
            allFolders = folders;

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
                    html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'folder-' + safeId + '\');return false;">⋮</button>';
                    html += '<div class="context-menu" id="menu-folder-' + safeId + '">';
                    html += '<div class="context-menu-item" onclick="renameFolderDialog(\'' + escapedFP + '\',\'' + escapedF + '\')">'+_t('ctx_rename_folder','Rename Folder')+'</div>';
                    html += '<div class="context-menu-item" onclick="showFolderProperties(\'' + escapedFP + '\')">'+_t('ctx_properties','Properties')+'</div>';
                    html += '<div class="context-menu-item danger" onclick="deleteFolder(\'' + escapedFP + '\')">'+_t('ctx_delete_folder','Delete Folder')+'</div>';
                    html += '</div></div>';
                }
                html += '</div>';
            });

            // Load folder visibility state
            if (isAuthenticated) {
                folders.forEach(folder => {
                    const fullPath = currentPath ? currentPath + '/' + folder : folder;
                    const safeId   = 'snd-item-' + folder.replace(/[^a-zA-Z0-9]/g, '_');
                    fetch('/folder-info/' + encodeURIComponent(fullPath))
                        .then(r => r.json())
                        .then(d => { const cb = document.getElementById('ftoggle-' + safeId); if (cb) cb.checked = d.is_public; })
                        .catch(() => {});
                });
            }

                        setPreviewFiles(files);
            files.forEach(f => {
                const fullFileName = currentPath ? currentPath + '/' + f.name : f.name;
                const rawUrl    = window.location.origin + '/raw/' + encodeURIComponent(fullFileName);
                const esc       = fullFileName.replace(/'/g, "\\'").replace(/"/g, '&quot;');
                const isPublic  = f.is_public || false;
                const modDate   = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';

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
                const badgeStyle  = badgeStyles[f.type] || 'background:#f5f5f5;color:#616161';
                const safeFileId  = 'snd-item-' + f.name.replace(/[^a-zA-Z0-9]/g, '_');

                html += '<div class="file-item" id="' + safeFileId + '">';
                html += '<input type="checkbox" class="checkbox file-checkbox" onchange="toggleFileSelect(\'' + esc + '\',this)">';

                // Thumbnail / Icon
                if (f.type === 'image' || f.type === 'video') {
                    const thumbSrc = '/thumbnail/' + encodeURIComponent(fullFileName);
                    html += '<div class="file-thumb" onclick="openPreviewModal(\'' + esc + '\',\'' + f.type + '\')" style="cursor:pointer;width:72px;height:72px;border-radius:8px;overflow:hidden;flex-shrink:0;background:#f0f0f0;">' +
                        '<img src="' + thumbSrc + '" loading="lazy" alt="" style="width:100%;height:100%;object-fit:cover;" onerror="this.style.display=\'none\';this.parentNode.style.cssText+=\'background:#f5f5f5;background-image:url(/icons/' + (f.icon || f.type) + '.svg);background-repeat:no-repeat;background-position:center;background-size:36px\'">' +
                        '</div>';
                } else {
                    html += '<div class="file-thumb" onclick="openPreviewModal(\'' + esc + '\',\'' + f.type + '\')" style="cursor:pointer;width:72px;height:72px;border-radius:8px;overflow:hidden;flex-shrink:0;background:#f5f5f5;display:flex;align-items:center;justify-content:center;">' +
                        '<img src="/icons/' + (f.icon || f.type) + '.svg" style="width:36px;height:36px;opacity:0.55;" onerror="this.src=\'/icons/file.svg\'">' +
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

                // Actions
                html += '<div class="file-actions">';
                html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'' + safeFileId + '\');return false;">⋮</button>';
                html += '<div class="context-menu" id="menu-' + safeFileId + '">';
                const viewLabel = (f.type === 'video' || f.type === 'audio') ? 'Play' : 'View';
                html += '<div class="context-menu-item" onclick="viewFile(\'' + esc + '\',\'' + f.type + '\')">' + viewLabel + '</div>';
                if (isAuthenticated) {
                    html += '<div class="context-menu-item" onclick="editFile(\'' + esc + '\')">'+_t('ctx_edit','Edit')+'</div>';
                }
                html += '<div class="context-menu-item" onclick="copyLink(\'' + esc + '\',' + isPublic + ')">'+_t('ctx_copy_link','Copy link')+'</div>';
                // Direct download via /download/ which sets Content-Disposition:attachment.
                // Public files use ?pt= token so guests can download without an API token.
                (function(){
                    var dlUrl;
                    if (isPublic && f.public_token) {
                        dlUrl = '/download/' + encodeURIComponent(fullFileName) + '?pt=' + encodeURIComponent(f.public_token);
                    } else if (isPublic) {
                        dlUrl = '/download/' + encodeURIComponent(fullFileName);
                    } else {
                        dlUrl = addTokenToURL('/download/' + encodeURIComponent(fullFileName));
                    }
                    html += '<div class="context-menu-item"><a href="' + dlUrl.replace(/"/g,'&quot;') + '" style="color:inherit;text-decoration:none;">'+_t('ctx_download','Download')+'</a></div>';
                })();
                html += '<div class="context-menu-item" onclick="downloadAsZip(\'' + esc + '\')">'+_t('ctx_download_zip','Download as ZIP')+'</div>';
                if (isAuthenticated) {
                    if (f.type === 'archive') html += '<div class="context-menu-item" onclick="extractArchive(\'' + esc + '\')">'+_t('ctx_extract','Extract here')+'</div>';
                    html += '<div class="context-menu-item" onclick="renameFile(\'' + esc + '\')">'+_t('ctx_rename','Rename')+'</div>';
                    html += '<div class="context-menu-item" onclick="duplicateFile(\'' + esc + '\')">'+_t('ctx_duplicate','Duplicate')+'</div>';
                    html += '<div class="context-menu-item danger" onclick="deleteFile(\'' + esc + '\')">'+_t('ctx_delete','Delete')+'</div>';
                }
                if (window._qrEnabled) html += '<div class="context-menu-item" onclick="generateQR(\'' + esc + '\')">Generate QR</div>';
                html += '</div></div></div>';
            });

            section.innerHTML = html;

            // When unauthenticated: also load user public files and append them
            if (!isAuthenticated && !currentPath) {
                _loadUserPublicSection(section);
            }
        })
        .catch(() => {
            document.getElementById('filesSection').innerHTML =
                '<div class="empty-state">Error loading files. Please refresh.</div>';
        });
}

// Fetch /public-files and append user-contributed public files below admin files
function _loadUserPublicSection(section) {
    fetch('/public-files')
        .then(r => r.json())
        .then(entries => {
            // Filter only user files (have user_uuid)
            const userFiles = (entries || []).filter(f => !!f.user_uuid);
            if (!userFiles.length) return;

            const badgeColors = {
                text:     'background:#e8f5e9;color:#2e7d32',
                image:    'background:#e3f2fd;color:#1976d2',
                video:    'background:#fce4ec;color:#c2185b',
                audio:    'background:#f3e5f5;color:#7b1fa2',
                archive:  'background:#fff3e0;color:#f57c00',
                document: 'background:#ffebee;color:#d32f2f',
            };

            let html = '<div style="margin-top:24px;padding-top:16px;border-top:2px solid #e0e0e0;">';
            html += '<div style="font-size:13px;font-weight:600;color:#888;padding:0 12px 10px;text-transform:uppercase;letter-spacing:.04em;">User Public Files</div>';

setPreviewFilesUserPub(userFiles);

            userFiles.forEach((f, idx) => {
                const rawUrl    = f.user_uuid && f.raw_path
                    ? window.location.origin + '/raw/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid) + (f.public_token ? '&pt=' + encodeURIComponent(f.public_token) : '')
                    : window.location.origin + '/raw/' + encodeURIComponent(f.name) + (f.public_token ? '?pt=' + encodeURIComponent(f.public_token) : '');
                const downloadUrl = f.user_uuid && f.raw_path
                    ? '/download/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid) + (f.public_token ? '&pt=' + encodeURIComponent(f.public_token) : '')
                    : '/download/' + encodeURIComponent(f.name) + (f.public_token ? '?pt=' + encodeURIComponent(f.public_token) : '');
                const thumbUrl  = f.user_uuid && f.raw_path
                    ? '/thumbnail/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid) + (f.public_token ? '&pt=' + encodeURIComponent(f.public_token) : '')
                    : '/thumbnail/' + encodeURIComponent(f.name) + (f.public_token ? '&pt=' + encodeURIComponent(f.public_token) : '');
                const modDate   = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';
                const typeBadge = badgeColors[f.type] || 'background:#f5f5f5;color:#616161';
                const ownerTag  = f.owner
                    ? '<span style="font-size:10px;font-weight:600;color:#2e7d32;background:#e8f5e9;border:1px solid #c8e6c9;padding:1px 6px;border-radius:999px;margin-left:6px;">' + escapeHtml(f.owner) + '</span>'
                    : '';
                const escIdx   = '' + idx;
                const safeUserFileId = 'snd-userpub-' + idx;

                let thumbHtml;
                if (f.type === 'image' || f.type === 'video') {
                    thumbHtml = '<div style="width:72px;height:72px;border-radius:8px;overflow:hidden;flex-shrink:0;background:#f0f0f0;">' +
                        '<img src="' + thumbUrl + '" loading="lazy" alt="" style="width:100%;height:100%;object-fit:cover;" onerror="this.style.display=\'none\'">' +
                        '</div>';
                } else {
                    thumbHtml = '<div style="width:72px;height:72px;border-radius:8px;background:#f5f5f5;display:flex;align-items:center;justify-content:center;flex-shrink:0;">' +
                        '<img src="/icons/' + (f.icon || f.type) + '.svg" style="width:36px;height:36px;opacity:0.55;" onerror="this.src=\'/icons/file.svg\'">' +
                        '</div>';
                }

                html += '<div class="file-item" id="' + safeUserFileId + '">';
                html += '<input type="checkbox" class="checkbox file-checkbox" style="visibility:hidden;" disabled>';
                html += thumbHtml;
                html += '<div class="file-info">';
                html += '<div class="file-name">' + escapeHtml(f.name) + '<span class="file-type-badge" style="' + typeBadge + '">' + f.type + '</span>' + ownerTag + '</div>';
                html += '<div class="file-meta">' + formatFileSize(f.size) + ' · ' + modDate;
                if (f.download_count > 0) html += ' · ' + f.download_count + ' downloads';
                html += '</div>';
                html += '<div class="file-link" onclick="navigator.clipboard.writeText(\'' + rawUrl.replace(/'/g, "\\'") + '\').then(()=>showToast(\'Link copied!\',\'success\'))" title="Click to copy">' + escapeHtml(rawUrl) + '</div>';
                html += '</div>';
                html += '<div class="file-actions">';
                html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'' + safeUserFileId + '\');return false;">⋮</button>';
                html += '<div class="context-menu" id="menu-' + safeUserFileId + '">';
                html += '<div class="context-menu-item" onclick="viewUserPublicFile(\'' + safeUserFileId + '\',' + escIdx + ')">View</div>';
                html += '<div class="context-menu-item" onclick="copyLinkUserPub(\'' + rawUrl.replace(/'/g, "\\'") + '\')">Copy Link</div>';
                html += '<div class="context-menu-item"><a href="' + downloadUrl.replace(/"/g, '&quot;') + '" download style="color:inherit;text-decoration:none;">Download</a></div>';
                html += '<div class="context-menu-item" onclick="_dlZipUserPub(' + idx + ')">Download as ZIP</div>';
                if (window._qrEnabled) html += '<div class="context-menu-item" onclick="_qrUserPub(' + idx + ')">Generate QR</div>';
                html += '</div></div>';
                html += '</div>';
            });

            html += '</div>';
            section.innerHTML += html;
        })
        .catch(() => {}); // silent fail — user files are optional
}

function togglePublicSwitch(filename, isPublic) {
    fetch('/set-permission', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ filename, is_public: isPublic }) })
        .then(r => r.json())
        .then(d => {
            // Update the cached allFiles entry with the new public_token so copyLink works immediately
            const f = allFiles.find(x => x.name === filename || x.name === filename.split('/').pop());
            if (f) { f.is_public = isPublic; f.public_token = isPublic ? (d.public_token || '') : ''; }
            showToast(filename + ' is now ' + (isPublic ? 'PUBLIC' : 'PRIVATE'), 'success');
            loadFiles();
        })
        .catch(() => { showToast(_t('toast_error_permission','Failed to update permission'), 'error'); loadFiles(); });
}
function copyLink(filename, isPublic) {
    const base = window.location.origin + '/raw/' + encodeURIComponent(filename);
    let url;
    if (isPublic) {
        // Look up public_token from allFiles cache
        const f = allFiles.find(x => x.name === filename || x.name === filename.split('/').pop());
        const pt = f && f.public_token ? f.public_token : '';
        url = pt ? base + '?pt=' + encodeURIComponent(pt) : base;
    } else {
        url = addTokenToURL(base);
    }
    navigator.clipboard.writeText(url)
        .then(() => showToast(_t('toast_copied','Link copied!'), 'success'))
        .catch(() => showToast(_t('toast_error_copy_link','Failed to copy link'), 'error'));
}
function viewFile(filename, type) {
    const rawUrl    = addTokenToURL('/raw/'    + encodeURIComponent(filename));
    const streamUrl = addTokenToURL('/stream/' + encodeURIComponent(filename));
    const baseName  = filename.split('/').pop();

    if (type === 'video' || type === 'audio') {
        csa.player({ src: streamUrl, title: baseName, mode: 'modal', autoplay: true, loader: 'ring', theme: { accent: '#e07820', accent2: '#ffaa55' } });
        return;
    }
    const viewBody = document.getElementById('viewBody');
    document.getElementById('viewTitle').textContent = baseName;
    openModal('viewModal');

    if (type === 'image') {
        viewBody.innerHTML = '<div class="media-viewer" id="imageViewer"><div class="media-viewer-inner" id="imageInner"><img src="' + rawUrl + '" id="zoomableImage"></div><div class="zoom-hint" id="zoomHint">Click to zoom in</div></div>';
        setupImageZoom();
        return;
    }
    if (type === 'archive') { viewZipContents(filename); return; }

    viewBody.innerHTML = '<div style="color:#999;padding:24px;text-align:center;">Loading...</div>';
    fetch(rawUrl).then(r => r.text()).then(c => {
        viewBody.innerHTML = '<pre id="viewContent" style="white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:12px;line-height:1.6;background:#f5f5f5;padding:16px;border-radius:4px;overflow:auto;max-height:62vh;"></pre>';
        document.getElementById('viewContent').textContent = c;
    }).catch(() => { viewBody.innerHTML = '<div style="padding:24px;color:#d32f2f;">Failed to load file.</div>'; });
}
function setupImageZoom() {
    const viewer = document.getElementById('imageViewer');
    const inner  = document.getElementById('imageInner');
    const img    = document.getElementById('zoomableImage');
    const hint   = document.getElementById('zoomHint');
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
    viewer.addEventListener('mouseup',   () => panning = false);
    viewer.addEventListener('mouseleave',() => panning = false);
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
    }).catch(() => showToast(_t('toast_error_read_zip','Failed to read ZIP'), 'error'));
}
function editFile(filename) {
    if (!isAuthenticated) { showToast(_t('toast_login_required','Login required'), 'error'); return; }
    currentEditFile = filename;
    document.getElementById('editTitle').textContent = 'Edit: ' + filename.split('/').pop();
    document.getElementById('editContent').value = 'Loading...';
    openModal('editModal');
    fetch(addTokenToURL('/raw/' + encodeURIComponent(filename)))
        .then(r => r.text()).then(c => { document.getElementById('editContent').value = c; })
        .catch(() => { document.getElementById('editContent').value = '// Failed to load file'; });
}
function saveFile() {
    fetch('/save/' + encodeURIComponent(currentEditFile), {
        method: 'POST', headers: { 'Content-Type': 'text/plain' },
        body: document.getElementById('editContent').value
    }).then(r => r.json()).then(d => { showToast(d.message, 'success'); closeModal('editModal'); loadFiles(); })
      .catch(() => showToast(_t('toast_error_save','Failed to save'), 'error'));
}
function downloadAsZip(filename) {
    const displayName = filename.split('/').pop() || 'file';
    showToast('Preparing ZIP\u2026', 'success');
    fetch('/zip-multiple', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files: [filename] }) })
        .then(r => {
            if (!r.ok) throw new Error('Server error ' + r.status);
            return r.blob();
        })
        .then(blob => {
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = displayName + '.zip'; a.click();
            showToast('Downloaded as ZIP', 'success');
        })
        .catch(() => showToast(_t ? _t('toast_error_zip','Failed to create ZIP') : 'Failed to create ZIP', 'error'));
}
function deleteFile(filename) {
    if (!isAuthenticated) { showToast(_t('toast_login_required','Login required'), 'error'); return; }
    const shortName = filename.split('/').pop();
    showConfirm(
        _t('confirm_delete_file','Delete "{filename}"?').replace('{filename}', shortName),
        function() {
            fetch('/delete/' + encodeURIComponent(filename), { method: 'DELETE' })
                .then(r => r.json()).then(d => { showToast(d.message, 'success'); loadFiles(); })
                .catch(() => showToast(_t('toast_error_delete','Failed to delete'), 'error'));
        },
        { yesLabel: _t('btn_delete','Delete'), yesColor: '#d32f2f' }
    );
}
function renameFile(filename) {
    currentRenameFile = filename;
    document.getElementById('renameInput').value = filename;
    openModal('renameModal');
    document.getElementById('renameInput').select();
}
let currentRenameFolderPath = '';
function renameFolderDialog(fullPath, name) {
    currentRenameFolderPath = fullPath;
    document.getElementById('renameInput').value = name;
    openModal('renameModal');
    document.getElementById('renameInput').select();
    document.getElementById('renameModal').dataset.mode = 'folder';
}
function confirmRename() {
    const newName = document.getElementById('renameInput').value.trim();
    if (!newName) { showToast(_t('validation_enter_name','Please enter a name'), 'error'); return; }
    const mode = document.getElementById('renameModal').dataset.mode;
    if (mode === 'folder') {
        fetch('/rename-folder/' + encodeURIComponent(currentRenameFolderPath), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_path: currentRenameFolderPath, new_name: newName })
        }).then(r => r.json()).then(d => {
            if (d.success === false) { showToast(d.error || _t('toast_error_rename','Failed to rename'), 'error'); return; }
            showToast(_t('toast_folder_renamed','Folder renamed'), 'success');
            closeModal('renameModal'); document.getElementById('renameModal').dataset.mode = ''; loadFiles();
        }).catch(() => showToast(_t('toast_error_rename_folder','Failed to rename folder'), 'error'));
    } else {
        fetch('/rename/' + encodeURIComponent(currentRenameFile), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_name: newName })
        }).then(r => r.json()).then(d => { showToast(d.message, 'success'); closeModal('renameModal'); loadFiles(); })
          .catch(() => showToast(_t('toast_error_rename','Failed to rename'), 'error'));
    }
}
function duplicateFile(filename) {
    fetch('/duplicate/' + encodeURIComponent(filename), { method: 'POST' })
        .then(r => r.json()).then(d => { showToast(d.message, 'success'); loadFiles(); })
        .catch(() => showToast(_t('toast_error_duplicate','Failed to duplicate'), 'error'));
}
function toggleFolderPublic(folderPath, isPublic) {
    fetch('/set-folder-permission', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: folderPath, is_public: isPublic }) })
        .then(r => r.json())
        .then(d => {
            showToast(folderPath.split('/').pop() + ' is now ' + (isPublic ? 'PUBLIC' : 'PRIVATE'), 'success');
            if (isPublic && d.public_token) {
                const base = window.location.origin + '/raw/' + encodeURIComponent(folderPath);
                const folderLink = base + '?pt=' + encodeURIComponent(d.public_token);
                navigator.clipboard.writeText(folderLink).catch(() => {});
            }
        })
        .catch(() => showToast(_t('toast_error_permission','Failed to update permission'), 'error'));
}
function showFolderProperties(folderPath) {
    document.getElementById('propsTitle').textContent = folderPath.split('/').pop() + '/';
    document.getElementById('propsBody').innerHTML = '<div style="color:#999;padding:24px;text-align:center;">Loading...</div>';
    openModal('propsModal');
    fetch('/folder-info/' + encodeURIComponent(folderPath)).then(r => r.json()).then(d => {
        document.getElementById('propsBody').innerHTML =
            '<table class="props-table">' +
            '<tr><td>Name</td><td><strong>' + escapeHtml(d.name) + '/</strong></td></tr>' +
            '<tr><td>Path</td><td style="font-family:monospace;font-size:12px;">' + escapeHtml(d.path) + '</td></tr>' +
            '<tr><td>Files</td><td>' + d.file_count + '</td></tr>' +
            '<tr><td>Subfolders</td><td>' + d.folder_count + '</td></tr>' +
            '<tr><td>Total size</td><td>' + formatFileSize(d.total_size) + '</td></tr>' +
            '<tr><td>Visibility</td><td>' + (d.is_public ? '<span style="color:#2e7d32;font-weight:600;">Public</span>' : '<span style="color:#d32f2f;font-weight:600;">Private</span>') + '</td></tr>' +
            '</table>';
    }).catch(() => { document.getElementById('propsBody').innerHTML = '<div style="color:#d32f2f;padding:12px;">Failed to load info.</div>'; });
}
function deleteFolder(folderName) {
    const shortName = folderName.split('/').pop();
    showConfirm(
        _t('confirm_delete_folder','Delete folder "{name}" and all contents?').replace('{name}', shortName),
        function() {
            fetch('/delete-folder/' + encodeURIComponent(folderName), { method: 'DELETE' })
                .then(r => r.json()).then(d => { showToast(d.message, 'success'); loadFiles(); })
                .catch(() => showToast(_t('toast_error_delete_folder','Failed to delete folder'), 'error'));
        },
        { yesLabel: _t('btn_delete','Delete'), yesColor: '#d32f2f' }
    );
}
function openCreateFolderModal() {
    document.getElementById('folderNameInput').value = '';
    openModal('createFolderModal');
    document.getElementById('folderNameInput').focus();
}
function confirmCreateFolder() {
    const folderName = document.getElementById('folderNameInput').value.trim();
    if (!folderName) { showToast(_t('validation_enter_folder_name','Please enter a folder name'), 'error'); return; }
    if (folderName.includes('..') || folderName.includes('/') || folderName.includes('\\')) {
        showToast(_t('toast_invalid_folder','Invalid folder name'), 'error'); return;
    }
    fetch('/create-folder', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: folderName, current_path: currentPath }) })
        .then(r => r.json()).then(d => { showToast(d.message, 'success'); closeModal('createFolderModal'); loadFiles(); })
        .catch(() => showToast(_t('toast_error_create_folder','Failed to create folder'), 'error'));
}
function _skeletonHTML(rows) {
    rows = rows || 6;
    var style = '<style>' +
        '@keyframes snd-shimmer{0%{background-position:-600px 0}100%{background-position:600px 0}}' +
        '.snd-skel{border-radius:4px;background:linear-gradient(90deg,#ececec 25%,#f5f5f5 50%,#ececec 75%);' +
        'background-size:600px 100%;animation:snd-shimmer 1.4s infinite linear;}' +
        '</style>';
    var html = style;
    for (var i = 0; i < rows; i++) {
        html += '<div style="display:flex;align-items:center;padding:10px 12px;border-bottom:1px solid #f0f0f0;gap:12px">' +
            '<div class="snd-skel" style="width:36px;height:36px;border-radius:6px;flex-shrink:0"></div>' +
            '<div style="flex:1;display:flex;flex-direction:column;gap:6px">' +
            '<div class="snd-skel" style="height:13px;width:' + (55 + (i * 17) % 35) + '%;border-radius:3px"></div>' +
            '<div class="snd-skel" style="height:10px;width:' + (25 + (i * 11) % 25) + '%;border-radius:3px"></div>' +
            '</div>' +
            '<div class="snd-skel" style="width:60px;height:13px;border-radius:3px;flex-shrink:0"></div>' +
            '</div>';
    }
    return html;
}

function logout() {
    fetch('/logout').then(() => { showToast(_t('toast_logged_out','Logged out'), 'success'); setTimeout(() => location.reload(), 1000); });
}

function extractArchive(filename, password, _confirmed) {
    if (!_confirmed && !password) { showConfirm('Extract "' + filename.split('/').pop() + '" here?', function() { extractArchive(filename, '', true); }); return; }
    showToast(_t('msg_extracting','Extracting…'), 'success');
    const body = new URLSearchParams();
    if (password) body.append('password', password);
    fetch('/extract-zip/' + encodeURIComponent(filename), { method: 'POST', body })
        .then(r => r.json())
        .then(d => {
            if (d.success) { showToast(_t('toast_extracted','Extracted successfully'), 'success'); loadFiles(); return; }
            if (d.needs_password) { showZipPasswordModal(filename, !!d.wrong_password); return; }
            showToast(_t('toast_error_extract','Extract failed') + ': ' + (d.error || 'unknown error'), 'error');
        })
        .catch(() => showToast(_t('toast_error_extract','Extract failed'), 'error'));
}

function showZipPasswordModal(filename, wrongPassword) {
    const existing = document.getElementById('zip-pw-modal');
    if (existing) existing.remove();
    const name = filename.split('/').pop();
    const modal = document.createElement('div');
    modal.id = 'zip-pw-modal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45)';
    const safeName = name.replace(/</g,'&lt;').replace(/>/g,'&gt;');
    modal.innerHTML = `
        <div style="background:#fff;border-radius:8px;padding:28px 24px;min-width:320px;max-width:90vw;box-shadow:0 8px 32px rgba(0,0,0,0.2)">
            <div style="font-size:16px;font-weight:600;margin-bottom:6px">Password Required</div>
            <div style="font-size:13px;color:#666;margin-bottom:14px">"${safeName}" is encrypted. Enter the archive password.</div>
            ${wrongPassword ? '<div style="font-size:12px;color:#c00;margin-bottom:10px">x Wrong password — try again.</div>' : ''}
            <input id="zip-pw-input" type="password" placeholder="Archive password"
                style="width:100%;padding:9px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;box-sizing:border-box;margin-bottom:14px"
                onkeydown="if(event.key==='Enter')document.getElementById('zip-pw-ok').click()">
            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button onclick="document.getElementById('zip-pw-modal').remove()"
                    style="padding:7px 16px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:13px">Cancel</button>
                <button id="zip-pw-ok"
                    style="padding:7px 16px;border:none;border-radius:4px;background:#1a1a1a;color:#fff;cursor:pointer;font-size:13px">Extract</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
    document.getElementById('zip-pw-ok').addEventListener('click', () => {
        const pw = document.getElementById('zip-pw-input').value;
        modal.remove();
        extractArchive(filename, pw);
    });
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    setTimeout(() => { const inp = document.getElementById('zip-pw-input'); if (inp) inp.focus(); }, 50);
}

// Queue tracks all in-progress and completed downloads so the modal stays open.
var _dlQueue = []; // [{id, url, filename, status, pct, error}]
var _dlQueueIdSeq = 0;

function openDownloadURLModal() {
    const inp = document.getElementById('dlUrlInput');
    if (inp) inp.value = '';
    var modal = document.getElementById('downloadURLModal');
    if (modal) { modal.style.display = 'flex'; }
    setTimeout(function() { if (inp) inp.focus(); }, 50);
    _renderDlQueue();
}
// Flush any click that happened before this script loaded
document.addEventListener('DOMContentLoaded', function() {
    if (window._dlUrlPending) { window._dlUrlPending = false; openDownloadURLModal(); }
});

function _renderDlQueue() {
    var list = document.getElementById('dlUrlQueue');
    if (!list) return;
    if (!_dlQueue.length) { list.style.display = 'none'; list.innerHTML = ''; return; }
    list.style.display = 'block';
    list.innerHTML = _dlQueue.map(function(job) {
        var statusColor = job.status === 'done' ? '#2e7d32' : job.status === 'error' ? '#c62828' : '#555';
        var barColor    = job.status === 'done' ? '#4caf50' : job.status === 'error' ? '#d32f2f' : '#1976d2';
        var label = job.status === 'done'  ? '✓ Done'
                  : job.status === 'error' ? '✗ ' + (job.error || 'Failed')
                  : (job.pct !== null ? job.pct + '%' : 'Fetching…');
        var bar = (job.status === 'pending' && job.pct !== null)
            ? '<div style="height:3px;background:#e0e0e0;border-radius:2px;margin-top:4px;">'
            + '<div style="height:3px;background:' + barColor + ';width:' + job.pct + '%;border-radius:2px;transition:width .3s;"></div></div>'
            : (job.status === 'pending'
                ? '<div style="height:3px;background:#e0e0e0;border-radius:2px;margin-top:4px;">'
                + '<div style="height:3px;background:' + barColor + ';width:40%;border-radius:2px;animation:_dlPulse 1.2s ease-in-out infinite;"></div></div>'
                : '');
        var nameDisplay = escapeHtml(job.filename || job.url.split('/').pop().split('?')[0] || job.url);
        return '<div style="padding:8px 0;border-bottom:1px solid #f0f0f0;">'
            + '<div style="display:flex;align-items:center;gap:8px;font-size:13px;">'
            + '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#1a1a1a;" title="' + escapeHtml(job.url) + '">' + nameDisplay + '</span>'
            + '<span style="color:' + statusColor + ';white-space:nowrap;font-size:12px;">' + label + '</span>'
            + '</div>' + bar + '</div>';
    }).join('');
}

function _dlAdminUrlHint(val) {
    var hint = document.getElementById('dlAdminStreamHint');
    if (!hint) return;
    hint.style.display = _isStreamingURL(val.trim()) ? '' : 'none';
}

// ── Streaming platform detection ─────────────────────────────────────────────
var _streamingHosts = [
    'youtube.com','youtu.be','vimeo.com','dailymotion.com','twitch.tv',
    'tiktok.com','instagram.com','facebook.com','fb.watch',
    'twitter.com','x.com','reddit.com','soundcloud.com',
    'bilibili.com','nicovideo.jp','rumble.com','odysee.com',
    'loom.com','streamable.com'
];
function _isStreamingURL(url) {
    try {
        var host = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
        return _streamingHosts.some(function(h) { return host === h || host.endsWith('.' + h); });
    } catch(e) { return false; }
}

// Pending stream download URL (used by format picker)
var _pendingStreamURL = '';

async function confirmDownloadURL() {
    const inp = document.getElementById('dlUrlInput');
    const url = inp ? inp.value.trim() : '';
    if (!url) {
        showToast(_t('toast_enter_url','Please enter a URL'), 'error');
        return;
    }

    // If it's a streaming platform URL, show the format picker instead
    if (_isStreamingURL(url)) {
        if (inp) inp.value = '';
        closeModal('downloadURLModal');
        _showStreamFormatPicker(url);
        return;
    }

    if (inp) inp.value = '';

    const id = ++_dlQueueIdSeq;
    const job = { id, url, filename: url.split('/').pop().split('?')[0] || 'file', status: 'pending', pct: null, error: null };
    _dlQueue.push(job);
    _renderDlQueue();

    // Indeterminate pulse while server fetches
    const pulseTimer = setInterval(function() {
        if (job.status === 'pending') _renderDlQueue();
    }, 800);

    try {
        const fetchOpts = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, path: currentPath || '' })
        };
        if (typeof USER_TOKEN !== 'undefined' && USER_TOKEN) {
            fetchOpts.headers['Authorization'] = 'Bearer ' + USER_TOKEN;
        }
        const res = await fetch('/download-url', fetchOpts);
        const d = await res.json();
        clearInterval(pulseTimer);
        if (d.success) {
            job.status = 'done';
            job.filename = d.filename || job.filename;
            job.pct = 100;
            showToast(_t('toast_downloaded_zip','Downloaded') + ': ' + job.filename, 'success');
            loadFiles();
        } else {
            job.status = 'error';
            job.error = d.error || 'Unknown error';
            showToast(_t('toast_error_download','Download failed') + ': ' + job.error, 'error');
        }
    } catch(e) {
        clearInterval(pulseTimer);
        job.status = 'error';
        job.error = 'Network error';
        showToast(_t('toast_error_network','Network error') + ': ' + e.message, 'error');
    }
    _renderDlQueue();
    // Auto-clean completed/failed entries after 8 s
    setTimeout(function() {
        _dlQueue = _dlQueue.filter(function(j) { return j.id !== id; });
        _renderDlQueue();
    }, 8000);
}

// ── Stream Format Picker ──────────────────────────────────────────────────────
async function _showStreamFormatPicker(url) {
    _pendingStreamURL = url;
    const modal = document.getElementById('streamFormatModal');
    const titleEl = document.getElementById('streamFormatTitle');
    const infoEl  = document.getElementById('streamFormatInfo');
    const loadEl  = document.getElementById('streamFormatLoading');
    const listEl  = document.getElementById('streamFormatList');

    titleEl.textContent = 'Select Format';
    infoEl.innerHTML = '';
    loadEl.style.display = '';
    loadEl.textContent = 'Fetching available formats…';
    listEl.style.display = 'none';
    listEl.innerHTML = '';
    if (modal) modal.style.display = 'flex';

    const headers = { 'Content-Type': 'application/json' };
    if (typeof USER_TOKEN !== 'undefined' && USER_TOKEN) headers['Authorization'] = 'Bearer ' + USER_TOKEN;

    try {
        const res = await fetch('/stream-info?url=' + encodeURIComponent(url), { headers });
        const info = await res.json();
        loadEl.style.display = 'none';

        if (info.error) {
            listEl.style.display = '';
            listEl.innerHTML = '<div style="color:#c62828;font-size:13px;padding:8px 0;">' + escapeHtml(info.error) + '</div>';
            return;
        }

        // Show thumbnail + title
        if (info.title) titleEl.textContent = info.title;
        infoEl.innerHTML =
            (info.thumbnail ? '<img src="' + escapeHtml(info.thumbnail) + '" style="width:80px;height:52px;object-fit:cover;border-radius:4px;flex-shrink:0;">' : '') +
            '<div><div style="font-size:13px;font-weight:600;color:#1a1a1a;">' + escapeHtml(info.title || url) + '</div>' +
            (info.uploader ? '<div style="font-size:12px;color:#888;margin-top:2px;">by ' + escapeHtml(info.uploader) + '</div>' : '') +
            (info.duration  ? '<div style="font-size:12px;color:#888;">' + _fmtDuration(info.duration) + '</div>' : '') + '</div>';

        // Build format list grouped: video+audio first, then audio-only, then other
        var fmts = (info.formats || []).filter(function(f) { return f.ext && f.ext !== 'none'; });

        // Deduplicate / pick best per resolution
        var seen = {}; var best = [];
        fmts.forEach(function(f) {
            var key = (f.height || 0) + '_' + f.ext + '_' + (f.vcodec && f.vcodec !== 'none' ? 'v' : 'a');
            if (!seen[key] || (f.filesize || 0) > (seen[key].filesize || 0)) { seen[key] = f; }
        });
        Object.values(seen).forEach(function(f) { best.push(f); });
        best.sort(function(a,b) { return (b.height||0) - (a.height||0) || (b.tbr||0) - (a.tbr||0); });

        // Add a "best quality" auto option at the top
        var rows = '<div style="padding:8px 0;border-bottom:1px solid #f0f0f0;">' +
            '<button onclick="_doStreamDownload(\'bestvideo+bestaudio/best\')" style="width:100%;text-align:left;background:none;border:1px solid #1a73e8;border-radius:4px;padding:10px 12px;cursor:pointer;font-size:13px;color:#1a73e8;font-weight:600;">' +
            'Best quality (auto-merge)</button></div>';

        best.forEach(function(f) {
            var hasVideo = f.vcodec && f.vcodec !== 'none';
            var hasAudio = f.acodec && f.acodec !== 'none';
            var label = hasVideo
                ? (f.height ? f.height + 'p' : '') + ' ' + f.ext.toUpperCase() + (f.format_note ? ' · ' + f.format_note : '') + (hasAudio ? '' : ' (video only)')
                : 'Audio · ' + f.ext.toUpperCase() + (f.format_note ? ' · ' + f.format_note : '');
            var size = f.filesize ? ' · ' + _fmtSize(f.filesize) : '';
            var tbr  = f.tbr ? ' · ~' + Math.round(f.tbr) + ' kbps' : '';
            rows += '<div style="padding:6px 0;border-bottom:1px solid #f5f5f5;">' +
                '<button onclick="_doStreamDownload(\'' + escapeHtml(f.format_id) + '\')" style="width:100%;text-align:left;background:none;border:1px solid #e0e0e0;border-radius:4px;padding:8px 12px;cursor:pointer;font-size:13px;color:#1a1a1a;">' +
                escapeHtml(label) + '<span style="color:#999;font-size:11px;">' + escapeHtml(size + tbr) + '</span></button></div>';
        });

        listEl.innerHTML = rows;
        listEl.style.display = '';
    } catch(e) {
        loadEl.style.display = '';
        loadEl.textContent = 'Error: ' + e.message;
    }
}

async function _doStreamDownload(formatId) {
    closeModal('streamFormatModal');
    const url = _pendingStreamURL;
    if (!url) return;

    const id = ++_dlQueueIdSeq;
    const job = { id, url, filename: 'Downloading…', status: 'pending', pct: null, error: null };
    _dlQueue.push(job);

    // Re-open download URL modal to show queue progress
    const dlModal = document.getElementById('downloadURLModal');
    if (dlModal) dlModal.style.display = 'flex';
    _renderDlQueue();

    const pulseTimer = setInterval(function() {
        if (job.status === 'pending') _renderDlQueue();
    }, 800);

    const headers = { 'Content-Type': 'application/json' };
    if (typeof USER_TOKEN !== 'undefined' && USER_TOKEN) headers['Authorization'] = 'Bearer ' + USER_TOKEN;

    try {
        const res = await fetch('/stream-download', {
            method: 'POST',
            headers,
            body: JSON.stringify({ url, format_id: formatId, path: currentPath || '' })
        });
        const d = await res.json();
        clearInterval(pulseTimer);
        if (d.success) {
            job.status = 'done'; job.pct = 100;
            showToast('Downloaded from stream ✓', 'success');
            loadFiles();
        } else {
            job.status = 'error'; job.error = d.error || 'Unknown error';
            showToast('Stream download failed: ' + job.error, 'error');
        }
    } catch(e) {
        clearInterval(pulseTimer);
        job.status = 'error'; job.error = 'Network error';
    }
    _renderDlQueue();
    setTimeout(function() { _dlQueue = _dlQueue.filter(function(j) { return j.id !== id; }); _renderDlQueue(); }, 8000);
}

function _fmtDuration(s) {
    var h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
    return h ? h+':'+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0') : m+':'+String(sec).padStart(2,'0');
}
function _fmtSize(b) {
    if (b >= 1073741824) return (b/1073741824).toFixed(1)+' GB';
    if (b >= 1048576) return (b/1048576).toFixed(1)+' MB';
    return (b/1024).toFixed(0)+' KB';
}

var _userPubFiles = [];
function setPreviewFilesUserPub(files) { _userPubFiles = files; }

function viewUserPublicFile(safeId, idx) {
    const f = _userPubFiles[idx];
    if (!f) return;
    const thumbUrl = f.user_uuid && f.raw_path
        ? '/thumbnail/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid) + (f.public_token ? '&pt=' + encodeURIComponent(f.public_token) : '')
        : '/thumbnail/' + encodeURIComponent(f.name) + (f.public_token ? '?pt=' + encodeURIComponent(f.public_token) : '');
    const streamUrl = f.user_uuid && f.raw_path
        ? '/stream/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid) + (f.public_token ? '&pt=' + encodeURIComponent(f.public_token) : '')
        : '/stream/' + encodeURIComponent(f.name) + (f.public_token ? '?pt=' + encodeURIComponent(f.public_token) : '');
    const baseName = f.name.split('/').pop();
    const navBtns = '<div style="text-align:center;margin-top:12px;">' +
        '<button class="btn" onclick="advanceUserPubPreview(-1,' + idx + ')">&#8592; Prev</button> ' +
        '<button class="btn" onclick="advanceUserPubPreview(1,' + idx + ')">Next &#8594;</button></div>';
    document.getElementById('viewTitle').textContent = baseName;
    if (f.type === 'image') {
        document.getElementById('viewBody').innerHTML =
            '<div style="text-align:center;padding:8px;">' +
            '<img src="' + thumbUrl + '" style="max-width:100%;max-height:70vh;object-fit:contain;border-radius:4px;" alt="' + escapeHtml(baseName) + '">' +
            '</div>' + navBtns;
        openModal('viewModal');
        return;
    }
    if (f.type === 'video' || f.type === 'audio') {
        const tag = f.type === 'audio' ? 'audio' : 'video';
        const style = f.type === 'audio' ? 'width:100%;margin:20px 0;' : 'width:100%;max-height:70vh;background:#000;border-radius:4px;';
        document.getElementById('viewBody').innerHTML =
            '<' + tag + ' controls autoplay playsinline style="' + style + '">' +
            '<source src="' + streamUrl + '">' +
            '</' + tag + '>' + navBtns;
        openModal('viewModal');
        return;
    }
    document.getElementById('viewBody').innerHTML = '<div style="color:#999;padding:24px;">Preview not available for this file type.</div>' + navBtns;
    openModal('viewModal');
}

function advanceUserPubPreview(dir, currentIdx) {
    const previewable = ['image', 'video', 'audio'];
    let next = currentIdx + dir;
    while (next >= 0 && next < _userPubFiles.length) {
        if (previewable.includes(_userPubFiles[next].type)) break;
        next += dir;
    }
    if (next < 0 || next >= _userPubFiles.length) return;
    const safeId = 'snd-userpub-' + next;
    viewUserPublicFile(safeId, next);
}

function copyLinkUserPub(url) {
    navigator.clipboard.writeText(url).then(() => showToast(_t('toast_copied','Link copied!'),'success')).catch(() => showToast(_t('toast_error_copy','Failed to copy'),'error'));
}

// Generate QR for a user-public file given its full public URL.
// No API token is embedded — the URL already contains pt= if needed.
function generateQRUserPub(publicUrl, encodedPT) {
    var url = publicUrl;
    if (encodedPT && publicUrl.indexOf('pt=') === -1) {
        url += (publicUrl.indexOf('?') === -1 ? '?' : '&') + 'pt=' + encodedPT;
    }
    var modal  = document.getElementById('snd-qr-modal');
    var title  = document.getElementById('snd-qr-title');
    var canvas = document.getElementById('snd-qr-canvas');
    if (!modal || !canvas) return;
    title.textContent = publicUrl.split('/').pop().split('?')[0] || 'file';
    modal.style.display = 'flex';
    if (typeof _renderQRServerSide === 'function') {
        _renderQRServerSide(canvas, url);
    }
}

// Index-based helpers — avoid quote escaping issues in html string building
function _dlZipUserPub(idx) {
    var f = _userPubFiles && _userPubFiles[idx];
    if (!f) return;
    var filename = f.raw_path || f.name || ('file' + idx);
    downloadAsZipUserPub(filename);
}

function _qrUserPub(idx) {
    var f = _userPubFiles && _userPubFiles[idx];
    if (!f) return;
    var rawUrl = f.user_uuid && f.raw_path
        ? window.location.origin + '/raw/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid) + (f.public_token ? '&pt=' + encodeURIComponent(f.public_token) : '')
        : window.location.origin + '/raw/' + encodeURIComponent(f.name) + (f.public_token ? '?pt=' + encodeURIComponent(f.public_token) : '');
    generateQRUserPub(rawUrl, '');
}

function downloadAsZipUserPub(relFilename) {
    // relFilename is now the relative filename (e.g. "photo.png"), not a full URL.
    // Passed from the updated context menu patch.
    const displayName = relFilename.split('/').pop() || 'file';
    showToast('Preparing ZIP\u2026','success');
    fetch('/zip-multiple', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ files: [relFilename] }) })
        .then(r => {
            if (!r.ok) throw new Error('Server error ' + r.status);
            return r.blob();
        }).then(blob => {
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = displayName + '.zip'; a.click();
            showToast('Downloaded as ZIP','success');
        }).catch(() => showToast('Failed to download ZIP','error'));
}
