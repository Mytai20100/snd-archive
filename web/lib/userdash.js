// userdash.js
// Globals expected: USER_UUID, USER_TOKEN, addTokenToURL, makePublicURL, makePrivateURL

'use strict';

// Language helper — returns translated string or fallback
function _t(key, fallback) { return (window._lang && window._lang[key]) || fallback || key; }

let currentPath   = '';
let currentEditFile, currentRenameFile, currentRenameFolderPath = '';
let allFiles      = [];
let allFolders    = [];
let selectedFiles = new Set();
let bulkMode      = false;
let _showDirectLinks = true;

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
    const streamUrl     = '/stream/'   + encodeURIComponent(filename);
    const authStreamUrl = addTokenToURL(streamUrl);
    const rawUrl        = '/api/view/' + encodeURIComponent(filename);
    const baseName      = filename.split('/').pop();

    if (type === 'image') {
        document.getElementById('viewTitle').textContent = baseName;
        document.getElementById('viewBody').innerHTML =
            '<div style="text-align:center;padding:8px;"><img src="' + rawUrl + '" style="max-width:100%;max-height:70vh;object-fit:contain;border-radius:4px;" alt="' + escapeHtml(baseName) + '"></div>' +
            '<div style="text-align:center;margin-top:12px;"><button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> <button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
        openModal('viewModal');
        return;
    }
    if (type === 'video' || type === 'audio') {
        const ext = filename.split('.').pop().toLowerCase();
        if (ext === 'm3u8') {
            document.getElementById('viewTitle').textContent = baseName;
            document.getElementById('viewBody').innerHTML =
                '<video id="hlsPlayer" controls autoplay playsinline style="width:100%;max-height:70vh;background:#000;border-radius:4px;"></video>' +
                '<div style="text-align:center;margin-top:12px;"><button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> <button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
            openModal('viewModal');
            const v = document.getElementById('hlsPlayer');
            if (typeof Hls !== 'undefined' && Hls.isSupported()) {
                const h = new Hls(); h.loadSource(streamUrl); h.attachMedia(v); v.play().catch(() => {});
            } else if (v.canPlayType('application/vnd.apple.mpegurl')) { v.src = streamUrl; v.play().catch(() => {}); }
            v.addEventListener('ended', () => advancePreview(1));
        } else if (typeof csa !== 'undefined' && csa.player) {
            csa.player({ src: authStreamUrl, title: baseName, mode: 'modal', autoplay: true, loader: 'ring', theme: { accent: '#e07820', accent2: '#ffaa55' }, onEnded: () => advancePreview(1) });
        } else {
            document.getElementById('viewTitle').textContent = baseName;
            const tag = type === 'audio' ? 'audio' : 'video';
            const style = type === 'audio' ? 'width:100%;margin:20px 0;' : 'width:100%;max-height:70vh;background:#000;border-radius:4px;';
            document.getElementById('viewBody').innerHTML =
                '<' + tag + ' id="mediaPlayer" controls autoplay playsinline style="' + style + '" onended="advancePreview(1)"><source src="' + authStreamUrl + '"></' + tag + '>' +
                '<div style="text-align:center;margin-top:12px;"><button class="btn" onclick="advancePreview(-1)">&#8592; Prev</button> <button class="btn" onclick="advancePreview(1)">Next &#8594;</button></div>';
            openModal('viewModal');
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
function showSearch() { document.getElementById('searchOverlay').style.display = 'flex'; document.getElementById('searchInput').focus(); }
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('searchInput').addEventListener('input', function (e) {
        const q = e.target.value.toLowerCase().trim();
        const res = document.getElementById('searchResults');
        if (!q) { res.innerHTML = ''; return; }
        const all = [
            ...allFolders.filter(n => n.toLowerCase().includes(q)).map(n => ({ name: n, isFolder: true })),
            ...allFiles.filter(f => f.name.toLowerCase().includes(q)).map(f => ({ name: f.name, isFolder: false, type: f.type, size: f.size }))
        ];
        if (!all.length) { res.innerHTML = '<div class="search-item" style="color:#999;">No results</div>'; return; }
        res.innerHTML = all.map(item => {
            const label = item.isFolder ? '&#128193; ' + escapeHtml(item.name) : escapeHtml(item.name);
            const meta  = item.isFolder ? 'Folder' : (item.type + ' - ' + formatFileSize(item.size));
            return '<div class="search-item" onclick="jumpToItem(\'' + item.name.replace(/'/g, "\\'") + '\')">' +
                '<div><div style="font-size:14px;">' + label + '</div><div style="font-size:11px;color:#999;">' + meta + '</div></div>' +
                '<span style="font-size:11px;color:#0066cc;white-space:nowrap;">Jump &#8594;</span></div>';
        }).join('');
    });
});
function jumpToItem(name) {
    document.getElementById('searchOverlay').style.display = 'none';
    document.getElementById('searchInput').value = '';
    document.getElementById('searchResults').innerHTML = '';
    const el = document.getElementById('snd-item-' + name.replace(/[^a-zA-Z0-9]/g, '_'));
    if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.classList.add('search-highlight'); setTimeout(() => el.classList.remove('search-highlight'), 2800); }
}

function selectAllFiles() {
    if (!bulkMode) { bulkMode = true; document.getElementById('bulkActions').classList.add('active'); }
    selectedFiles.clear();
    // Use fullFileName (with currentPath prefix) — same as what toggleFileSelect receives
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
    updateBulkCount();
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
    const el = document.getElementById('selectedCount');
    if (el) el.textContent = selectedFiles.size + ' ' + _t('ui_selected', 'selected');
}
function downloadSelectedAsZip() {
    if (!selectedFiles.size) { showToast(_t('toast_select_files', 'Select files first'), 'error'); return; }
    const token = typeof USER_TOKEN !== 'undefined' ? USER_TOKEN : '';
    const hdrs = { 'Content-Type': 'application/json' };
    if (token) hdrs['Authorization'] = 'Bearer ' + token;
    showToast(_t('msg_preparing_zip', 'Preparing ZIP…'), 'success');
    fetch('/zip-multiple', { method: 'POST', headers: hdrs, body: JSON.stringify({ files: Array.from(selectedFiles) }) })
        .then(r => { if (!r.ok) throw new Error('Server error ' + r.status); return r.blob(); })
        .then(blob => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'files_' + Date.now() + '.zip';
            a.click();
            showToast(_t('toast_downloaded_zip', 'Downloaded as ZIP'), 'success');
        })
        .catch(e => showToast(_t('toast_error_zip', 'Failed to create ZIP') + ': ' + e.message, 'error'));
}
function deleteSelectedFiles() {
    if (!selectedFiles.size) { showToast(_t('toast_select_files', 'Select files first'), 'error'); return; }
    const count = selectedFiles.size;
    showConfirm(
        _t('confirm_delete_selected', 'Delete {n} selected file(s)?').replace('{n}', count),
        async function() {
            const token = typeof USER_TOKEN !== 'undefined' ? USER_TOKEN : '';
            const hdrs = { 'Authorization': 'Bearer ' + token };
            let done = 0, failed = 0;
            const files = Array.from(selectedFiles);
            for (const filename of files) {
                try {
                    const res = await fetch('/delete/' + encodeURIComponent(filename), { method: 'DELETE', headers: hdrs });
                    if (res.ok) done++; else failed++;
                } catch(e) { failed++; }
            }
            deselectAll();
            loadFiles();
            if (failed === 0) showToast(_t('toast_deleted_n', 'Deleted {n} file(s)').replace('{n}', done), 'success');
            else showToast('Deleted ' + done + ', failed ' + failed, failed > 0 ? 'error' : 'success');
        }
    );
}

function loadFiles() {
    const url = currentPath ? '/files?path=' + encodeURIComponent(currentPath) : '/files';
    const section = document.getElementById('filesSection');
    if (section) section.innerHTML = _skeletonHTML();
    fetch(url).then(r => { if (!r.ok) throw new Error(); return r.json(); }).then(data => {
        allFiles   = data.files   || [];
        allFolders = data.folders || [];
        const section = document.getElementById('filesSection');
        if (!allFolders.length && !allFiles.length) { section.innerHTML = '<div class="empty-state">No files or folders here</div>'; return; }

        let html = '';
        allFolders.forEach(folder => {
            const fullPath  = currentPath ? currentPath + '/' + folder : folder;
            const escapedFP = fullPath.replace(/'/g, "\\'");
            const escapedF  = folder.replace(/'/g, "\\'");
            const safeId    = 'snd-item-' + folder.replace(/[^a-zA-Z0-9]/g, '_');
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
            html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'folder-' + safeId + '\');return false;">⋮</button>';
            html += '<div class="context-menu" id="menu-folder-' + safeId + '">';
            html += '<div class="context-menu-item" onclick="renameFolderDialog(\'' + escapedFP + '\',\'' + escapedF + '\')">'+_t('ctx_rename_folder','Rename Folder')+'</div>';
            html += '<div class="context-menu-item" onclick="showFolderProperties(\'' + escapedFP + '\')">'+_t('ctx_properties','Properties')+'</div>';
            html += '<div class="context-menu-item danger" onclick="deleteFolder(\'' + escapedFP + '\')">'+_t('ctx_delete_folder','Delete Folder')+'</div>';
            html += '</div></div></div>';
        });
        // Load folder toggle state
        allFolders.forEach(folder => {
            const fullPath = currentPath ? currentPath + '/' + folder : folder;
            const safeId   = 'snd-item-' + folder.replace(/[^a-zA-Z0-9]/g, '_');
            fetch('/folder-info/' + encodeURIComponent(fullPath)).then(r => r.json()).then(d => { const cb = document.getElementById('ftoggle-' + safeId); if (cb) cb.checked = d.is_public; }).catch(() => {});
        });

        setPreviewFiles(allFiles);
        allFiles.forEach(f => {
            const fullFileName = currentPath ? currentPath + '/' + f.name : f.name;
            const pubURL       = makePublicURL(fullFileName);
            const privURL      = makePrivateURL(fullFileName);
            const displayURL   = f.is_public ? pubURL : privURL;
            const esc          = fullFileName.replace(/'/g, "\\'").replace(/"/g, '&quot;');
            const isPublic     = f.is_public || false;
            const modDate      = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';
            const badgeStyles  = { text: 'background:#e8f5e9;color:#2e7d32', image: 'background:#e3f2fd;color:#1976d2', video: 'background:#fce4ec;color:#c2185b', audio: 'background:#f3e5f5;color:#7b1fa2', archive: 'background:#fff3e0;color:#f57c00', document: 'background:#ffebee;color:#d32f2f' };
            const badgeStyle   = badgeStyles[f.type] || 'background:#f5f5f5;color:#616161';
            const safeFileId   = 'snd-item-' + f.name.replace(/[^a-zA-Z0-9]/g, '_');

            html += '<div class="file-item" id="' + safeFileId + '">';
            html += '<input type="checkbox" class="checkbox file-checkbox" onchange="toggleFileSelect(\'' + esc + '\',this)">';
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
            html += '<div class="file-name">' + escapeHtml(f.name) + '<span class="file-type-badge" style="' + badgeStyle + '">' + f.type + '</span>';
            html += '<label class="toggle-switch" style="margin-left:8px;vertical-align:middle;" onclick="event.stopPropagation();"><input type="checkbox" ' + (isPublic ? 'checked' : '') + ' onchange="togglePublicSwitch(\'' + esc + '\',this.checked)"><span class="toggle-slider"></span></label>';
            html += '</div>';
            html += '<div class="file-meta">' + formatFileSize(f.size) + ' - ' + modDate;
            if (f.download_count > 0) html += ' - ' + f.download_count + ' downloads';
            html += '</div>';
            html += '<div class="file-link" onclick="copyLink(\'' + esc + '\')" title="Click to copy">' + escapeHtml(displayURL) + '</div>';
            html += '</div>';
            html += '<div class="file-actions">';
            html += '<button class="menu-btn" onclick="toggleContextMenu(event,\'' + safeFileId + '\');return false;">⋮</button>';
            html += '<div class="context-menu" id="menu-' + safeFileId + '">';
            const viewLabel = (f.type === 'video' || f.type === 'audio') ? 'Play' : 'View';
            html += '<div class="context-menu-item" onclick="viewFile(\'' + esc + '\',\'' + f.type + '\')">' + viewLabel + '</div>';
            html += '<div class="context-menu-item" onclick="editFile(\'' + esc + '\')">'+_t('ctx_edit','Edit')+'</div>';
            html += '<div class="context-menu-item" onclick="downloadFile(\'' + esc + '\')">Download</div>';
            html += '<div class="context-menu-item" onclick="copyLink(\'' + esc + '\')">'+_t('ctx_copy_link','Copy link')+'</div>';
            html += '<div class="context-menu-item" onclick="downloadAsZip(\'' + esc + '\')">'+_t('ctx_download_zip','Download as ZIP')+'</div>';
            if (f.type === 'archive') html += '<div class="context-menu-item" onclick="extractArchive(\'' + esc + '\')">'+_t('ctx_extract','Extract here')+'</div>';
            html += '<div class="context-menu-item" onclick="renameFile(\'' + esc + '\')">'+_t('ctx_rename','Rename')+'</div>';
            html += '<div class="context-menu-item" onclick="duplicateFile(\'' + esc + '\')">'+_t('ctx_duplicate','Duplicate')+'</div>';
            html += '<div class="context-menu-item danger" onclick="deleteFile(\'' + esc + '\')">'+_t('ctx_delete','Delete')+'</div>';
            if (window._qrEnabled) html += '<div class="context-menu-item" onclick="generateQR(\'' + esc + '\')">Generate QR</div>';
            html += '</div></div></div>';
        });
        section.innerHTML = html;
        applyDirectLinksVisibility(_showDirectLinks);
    }).catch(() => { document.getElementById('filesSection').innerHTML = '<div class="empty-state">Error loading files. Please refresh.</div>'; });
}

function togglePublicSwitch(filename, isPublic) {
    fetch('/set-permission', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ filename, is_public: isPublic }) })
        .then(r => r.json()).then(d => {
            // Update cached allFiles entry so copyLink can use the new token immediately
            const f = allFiles.find(x => (currentPath ? currentPath + '/' + x.name : x.name) === filename || x.name === filename);
            if (f) { f.is_public = isPublic; f.public_token = isPublic ? (d.public_token || '') : ''; }
            showToast(filename + ' is now ' + (isPublic ? 'PUBLIC' : 'PRIVATE'), 'success'); loadFiles();
        })
        .catch(() => { showToast(_t('toast_error_permission','Failed to update permission'), 'error'); loadFiles(); });
}
function copyLink(filename) {
    const f   = allFiles.find(x => (currentPath ? currentPath + '/' + x.name : x.name) === filename || x.name === filename);
    const url = (f && f.is_public) ? makePublicURL(filename, f.public_token) : makePrivateURL(filename);
    navigator.clipboard.writeText(url).then(() => showToast(_t('toast_copied','Link copied!'), 'success')).catch(() => showToast(_t('toast_error_copy','Failed to copy'), 'error'));
}
function viewFile(filename, type) {
    const rawUrl    = addTokenToURL('/raw/'    + encodeURIComponent(filename));
    const streamUrl = addTokenToURL('/stream/' + encodeURIComponent(filename));
    const baseName  = filename.split('/').pop();
    if (type === 'video' || type === 'audio') { csa.player({ src: streamUrl, title: baseName, mode: 'modal', autoplay: true, loader: 'ring', theme: { accent: '#e07820', accent2: '#ffaa55' } }); return; }
    const viewBody = document.getElementById('viewBody');
    document.getElementById('viewTitle').textContent = baseName;
    openModal('viewModal');
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
    openModal('editModal');
    fetch(addTokenToURL('/raw/' + encodeURIComponent(filename))).then(r => r.text()).then(c => { document.getElementById('editContent').value = c; }).catch(() => { document.getElementById('editContent').value = '// Failed to load'; });
}
function saveFile() {
    fetch('/save/' + encodeURIComponent(currentEditFile), { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: document.getElementById('editContent').value })
        .then(r => r.json()).then(d => { showToast(d.message, 'success'); closeModal('editModal'); loadFiles(); }).catch(() => showToast(_t('toast_error_save','Failed to save'), 'error'));
}
function downloadFile(filename) { window.location.href = addTokenToURL('/download/' + encodeURIComponent(filename)); }
function downloadAsZip(filename) {
    fetch('/zip-multiple', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ files: [filename] }) })
        .then(r => r.blob()).then(blob => { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename + '.zip'; a.click(); });
}
function deleteFile(filename) {
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
function renameFile(filename) { currentRenameFile = filename; document.getElementById('renameInput').value = filename; openModal('renameModal'); document.getElementById('renameInput').select(); }
function renameFolderDialog(fullPath, name) { currentRenameFolderPath = fullPath; document.getElementById('renameInput').value = name; openModal('renameModal'); document.getElementById('renameInput').select(); document.getElementById('renameModal').dataset.mode = 'folder'; }
function confirmRename() {
    const newName = document.getElementById('renameInput').value.trim();
    if (!newName) { showToast(_t('validation_enter_name','Please enter a name'), 'error'); return; }
    const mode = document.getElementById('renameModal').dataset.mode;
    if (mode === 'folder') {
        fetch('/rename-folder/' + encodeURIComponent(currentRenameFolderPath), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ old_path: currentRenameFolderPath, new_name: newName }) })
            .then(r => r.json()).then(d => { if (d.success === false) { showToast(d.error || _t('toast_error_rename','Failed to rename'), 'error'); return; } showToast(_t('toast_folder_renamed','Folder renamed'), 'success'); closeModal('renameModal'); document.getElementById('renameModal').dataset.mode = ''; loadFiles(); }).catch(() => showToast(_t('toast_error_rename_folder','Failed to rename folder'), 'error'));
    } else {
        fetch('/rename/' + encodeURIComponent(currentRenameFile), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ new_name: newName }) })
            .then(r => r.json()).then(d => { showToast(d.message, 'success'); closeModal('renameModal'); loadFiles(); }).catch(() => showToast(_t('toast_error_rename','Failed to rename'), 'error'));
    }
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
function viewZipContents(filename) {
    fetch('/zip-view/' + encodeURIComponent(filename)).then(r => r.json()).then(data => {
        document.getElementById('viewTitle').textContent = filename.split('/').pop() + ' (contents)';
        let html = '<div style="font-family:monospace;font-size:12px;">';
        html += '<div style="margin-bottom:12px;padding:10px;background:#f5f5f5;border:1px solid #e0e0e0;border-radius:4px;"><strong>' + (data.files || []).length + ' files</strong> — Total: ' + formatFileSize(data.total_size || 0) + '</div>';
        (data.files || []).forEach(f => { html += '<div style="padding:8px 12px;border-bottom:1px solid #f0f0f0;"><strong>' + escapeHtml(f.name) + '</strong><span style="color:#999;margin-left:16px;">' + formatFileSize(f.size) + '</span></div>'; });
        html += '</div>';
        document.getElementById('viewBody').innerHTML = html;
    }).catch(() => showToast(_t('toast_error_read_zip','Failed to read archive'), 'error'));
}
function duplicateFile(filename) {
    fetch('/duplicate/' + encodeURIComponent(filename), { method: 'POST' }).then(r => r.json()).then(d => { showToast(d.message, 'success'); loadFiles(); }).catch(() => showToast(_t('toast_error_duplicate','Failed to duplicate'), 'error'));
}
function toggleFolderPublic(folderPath, isPublic) {
    fetch('/set-folder-permission', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: folderPath, is_public: isPublic }) })
        .then(r => r.json()).then(d => {
            showToast(folderPath.split('/').pop() + ' is now ' + (isPublic ? 'PUBLIC' : 'PRIVATE'), 'success');
            if (isPublic && d.public_token) {
                // Build and copy the public folder link with pt= token
                const folderLink = makePublicURL(folderPath, d.public_token);
                navigator.clipboard.writeText(folderLink).catch(() => {});
            }
        }).catch(() => showToast(_t('toast_error','Failed'), 'error'));
}
function showFolderProperties(folderPath) {
    document.getElementById('propsTitle').textContent = folderPath.split('/').pop() + '/';
    document.getElementById('propsBody').innerHTML = '<div style="color:#999;padding:24px;text-align:center;">Loading...</div>';
    openModal('propsModal');
    fetch('/folder-info/' + encodeURIComponent(folderPath)).then(r => r.json()).then(d => {
        document.getElementById('propsBody').innerHTML = '<table class="props-table"><tr><td>Name</td><td><strong>' + escapeHtml(d.name) + '/</strong></td></tr><tr><td>Files</td><td>' + d.file_count + '</td></tr><tr><td>Subfolders</td><td>' + d.folder_count + '</td></tr><tr><td>Total size</td><td>' + formatFileSize(d.total_size) + '</td></tr><tr><td>Visibility</td><td>' + (d.is_public ? '<span style="color:#2e7d32;font-weight:600;">Public</span>' : '<span style="color:#d32f2f;font-weight:600;">Private</span>') + '</td></tr></table>';
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
function openCreateFolderModal() { document.getElementById('folderNameInput').value = ''; openModal('createFolderModal'); document.getElementById('folderNameInput').focus(); }
function confirmCreateFolder() {
    const folderName = document.getElementById('folderNameInput').value.trim();
    if (!folderName) { showToast(_t('validation_enter_folder_name','Please enter a folder name'), 'error'); return; }
    fetch('/create-folder', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: folderName, current_path: currentPath }) })
        .then(r => r.json()).then(d => { showToast(d.message, 'success'); closeModal('createFolderModal'); loadFiles(); }).catch(() => showToast(_t('toast_error_create_folder','Failed to create folder'), 'error'));
}

function closeApiTokenSection() {
    const s = document.getElementById('apiTokenSection');
    if (s) { s.style.display = 'none'; localStorage.setItem('hideApiToken_user', 'true'); }
}
document.addEventListener('DOMContentLoaded', function () {
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
    navigator.clipboard.writeText(USER_TOKEN).then(() => showToast(_t('toast_token_copied','Token copied!'), 'success')).catch(() => showToast(_t('toast_error_copy','Failed to copy'), 'error'));
}

function applyDirectLinksVisibility(show) {
    _showDirectLinks = show !== false;
    document.querySelectorAll('.file-link').forEach(el => el.style.display = _showDirectLinks ? '' : 'none');
}

function applyUserBgMusic(url) {
    let audio = document.getElementById('bgMusicPlayer');
    if (!url) { if (audio) { audio.pause(); audio.remove(); } return; }
    if (!audio) { audio = document.createElement('audio'); audio.id = 'bgMusicPlayer'; audio.loop = true; audio.volume = 0.3; document.body.appendChild(audio); }
    if (audio.src !== url) { audio.src = url; audio.play().catch(() => {}); }
}

function openSettingsPanel() {
    fetch('/user/settings').then(r => r.json()).then(data => {
        const s = data.settings || {};
        document.getElementById('us-bg').value    = s.background_url || '';
        document.getElementById('us-music').value = s.bg_music_url   || '';
        document.getElementById('us-lang').value  = s.language       || 'en';
        document.getElementById('us-direct-links').checked = s.show_direct_links !== false;
        const themeRow = document.getElementById('us-theme-row');
        if (themeRow) themeRow.style.display = data.allow_theme ? '' : 'none';
        if (document.getElementById('us-theme')) document.getElementById('us-theme').value = s.theme || 'default';

        // MCP section — only shown when admin allows user MCP
        const mcpSec = document.getElementById('us-mcp-section');
        if (mcpSec) {
            mcpSec.style.display = data.allow_mcp ? '' : 'none';
            if (data.allow_mcp) {
                const mcp = s.mcp || {};
                const mcpEnabled = document.getElementById('us-mcp-enabled');
                const mcpPerms   = document.getElementById('us-mcp-perms');
                if (mcpEnabled) {
                    mcpEnabled.checked = !!mcp.enabled;
                    if (mcpPerms) mcpPerms.style.display = mcp.enabled ? '' : 'none';
                    mcpEnabled.onchange = function() {
                        if (mcpPerms) mcpPerms.style.display = this.checked ? '' : 'none';
                    };
                }
                const mp   = mcp.permissions || {};
                const maxP = data.mcp_max_perms || {};
                _udLoadMcpPerm('us-mcp-perm-read',    mp.can_read,    maxP.can_read);
                _udLoadMcpPerm('us-mcp-perm-upload',  mp.can_upload,  maxP.can_upload);
                _udLoadMcpPerm('us-mcp-perm-create',  mp.can_create,  maxP.can_create);
                _udLoadMcpPerm('us-mcp-perm-rename',  mp.can_rename,  maxP.can_rename);
                _udLoadMcpPerm('us-mcp-perm-delete',  mp.can_delete,  maxP.can_delete);
                _udLoadMcpPerm('us-mcp-perm-storage', mp.can_storage, maxP.can_storage);
            }
        }

        openModal('settingsModal');
        if (s.bg_music_url) applyUserBgMusic(s.bg_music_url);
    }).catch(() => showToast(_t('toast_error_load_settings','Failed to load settings'), 'error'));
}

function _udLoadMcpPerm(id, val, adminMax) {
    const el = document.getElementById(id);
    if (!el) return;
    el.checked = !!val;
    el.disabled = !adminMax;
    el.parentElement.style.opacity = adminMax ? '' : '0.4';
    el.parentElement.title = adminMax ? '' : 'Not allowed by admin';
}

function closeSettingsModal() { document.getElementById('settingsModal').style.display = 'none'; }

async function saveUserSettings() {
    const _gc = id => { const el = document.getElementById(id); return el && !el.disabled ? el.checked : false; };
    const s = {
        theme:             document.getElementById('us-theme') ? document.getElementById('us-theme').value : 'default',
        background_url:    document.getElementById('us-bg').value,
        bg_music_url:      document.getElementById('us-music').value,
        language:          document.getElementById('us-lang').value,
        show_direct_links: document.getElementById('us-direct-links').checked,
        mcp: {
            enabled: _gc('us-mcp-enabled'),
            rate_limit: 30,
            permissions: {
                can_read:    _gc('us-mcp-perm-read'),
                can_upload:  _gc('us-mcp-perm-upload'),
                can_create:  _gc('us-mcp-perm-create'),
                can_rename:  _gc('us-mcp-perm-rename'),
                can_delete:  _gc('us-mcp-perm-delete'),
                can_storage: _gc('us-mcp-perm-storage'),
                can_users:   false
            }
        }
    };
    const res = await fetch('/user/settings/save', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(s) });
    if (res.ok) { showToast(_t('toast_settings_saved','Settings saved'), 'success'); closeSettingsModal(); applyUserBgMusic(s.bg_music_url); applyDirectLinksVisibility(s.show_direct_links); }
    else showToast(_t('toast_error_settings','Failed to save settings'), 'error');
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

// ─── Download URL Modal (streaming-aware) ──────────────────────────────────

var _dlQueue = [];
var _dlQueueIdSeq = 0;
var _dlStreamInfo = null;   // cached StreamInfo from /stream-info
var _dlCurrentTab = 'video';
var _dlDetectTimer = null;

// Known streaming platform host patterns
var _dlStreamingHosts = [
    'youtube.com','youtu.be','vimeo.com','dailymotion.com','twitch.tv',
    'tiktok.com','instagram.com','facebook.com','fb.watch','twitter.com',
    'x.com','reddit.com','soundcloud.com','bilibili.com','nicovideo.jp',
    'rumble.com','odysee.com','loom.com','streamable.com'
];

function _dlIsStreamingURL(rawUrl) {
    try {
        var u = new URL(rawUrl);
        var host = u.hostname.replace(/^www\./, '').toLowerCase();
        return _dlStreamingHosts.some(function(h) { return host === h || host.endsWith('.' + h); });
    } catch(e) { return false; }
}

function openDownloadURLModal() {
    var inp = document.getElementById('dlUrlInput');
    if (inp) inp.value = '';
    _dlStreamInfo = null;
    _dlResetStreamPanel();
    var modal = document.getElementById('downloadURLModal');
    if (modal) modal.style.display = 'flex';
    setTimeout(function() { if (inp) inp.focus(); }, 50);
    _renderDlQueue();
}

document.addEventListener('DOMContentLoaded', function() {
    if (window._dlUrlPending) { window._dlUrlPending = false; openDownloadURLModal(); }
});

// Called on every keystroke in the URL input
function _dlOnUrlChange(val) {
    clearTimeout(_dlDetectTimer);
    var url = val.trim();
    if (!url) { _dlResetStreamPanel(); return; }

    if (_dlIsStreamingURL(url)) {
        document.getElementById('dlUrlBtn').textContent = 'Fetch Info';
        document.getElementById('dlDirectDesc').style.display = 'none';
        // debounce: auto-fetch after 900ms of no typing
        _dlDetectTimer = setTimeout(function() { _dlFetchStreamInfo(url); }, 900);
    } else {
        _dlResetStreamPanel();
        document.getElementById('dlUrlBtn').textContent = 'Download';
        document.getElementById('dlDirectDesc').style.display = 'block';
    }
}

function _dlResetStreamPanel() {
    var panel = document.getElementById('dlStreamPanel');
    if (panel) panel.style.display = 'none';
    _dlStreamInfo = null;
    var btn = document.getElementById('dlUrlBtn');
    if (btn) { btn.textContent = 'Fetch Info'; btn.classList.remove('loading'); }
}

function _dlHandleEnter() {
    var url = (document.getElementById('dlUrlInput') || {}).value;
    if (!url) return;
    url = url.trim();
    if (_dlIsStreamingURL(url)) {
        _dlFetchStreamInfo(url);
    } else {
        confirmDownloadURL();
    }
}

async function _dlFetchStreamInfo(url) {
    var btn = document.getElementById('dlUrlBtn');
    if (btn) { btn.textContent = 'Loading…'; btn.classList.add('loading'); }

    try {
        var token = typeof USER_TOKEN !== 'undefined' ? USER_TOKEN : '';
        var hdrs = {};
        if (token) hdrs['Authorization'] = 'Bearer ' + token;
        var res = await fetch('/stream-info?url=' + encodeURIComponent(url), { headers: hdrs });
        var info = await res.json();

        if (btn) { btn.textContent = 'Fetch Info'; btn.classList.remove('loading'); }

        if (info.error || !info.available) {
            // Fall back to direct download
            showToast('yt-dlp unavailable, will use direct download', 'info');
            _dlResetStreamPanel();
            document.getElementById('dlDirectDesc').style.display = 'block';
            document.getElementById('dlUrlBtn').textContent = 'Download';
            return;
        }

        _dlStreamInfo = info;
        _dlRenderStreamPanel(info);
    } catch(e) {
        if (btn) { btn.textContent = 'Fetch Info'; btn.classList.remove('loading'); }
        showToast('Could not fetch stream info', 'error');
    }
}

function _dlRenderStreamPanel(info) {
    // Thumbnail + meta
    var thumb = document.getElementById('dlThumb');
    var title = document.getElementById('dlVideoTitle');
    var meta  = document.getElementById('dlVideoMeta');
    if (thumb) { thumb.src = info.thumbnail || ''; thumb.style.display = info.thumbnail ? '' : 'none'; }
    if (title) title.textContent = info.title || 'Unknown title';
    if (meta) {
        var parts = [];
        if (info.uploader) parts.push(info.uploader);
        if (info.duration) {
            var m = Math.floor(info.duration / 60), s = info.duration % 60;
            parts.push(m + ':' + (s < 10 ? '0' : '') + s);
        }
        meta.textContent = parts.join(' · ');
    }

    // Build video format options (has both video + audio)
    var videoFmts = (info.formats || []).filter(function(f) {
        return f.vcodec && f.vcodec !== 'none' && f.acodec && f.acodec !== 'none';
    }).sort(function(a, b) { return (b.height || 0) - (a.height || 0); });

    // Best combined formats + best+bestaudio merge options
    var videoSel = document.getElementById('dlVideoSelect');
    if (videoSel) {
        videoSel.innerHTML = '';
        // Add smart presets first
        ['bestvideo+bestaudio/best','best'].forEach(function(fid) {
            var label = fid === 'bestvideo+bestaudio/best' ? 'Best Quality (auto merge)' : 'Best Single File';
            var opt = document.createElement('option');
            opt.value = fid; opt.textContent = label;
            videoSel.appendChild(opt);
        });
        videoFmts.forEach(function(f) {
            var label = (f.height ? f.height + 'p' : '') + (f.format_note ? ' ' + f.format_note : '') + ' [' + f.ext + ']';
            if (f.filesize) label += ' (' + _dlFmtSize(f.filesize) + ')';
            var opt = document.createElement('option');
            opt.value = f.format_id; opt.textContent = label.trim();
            videoSel.appendChild(opt);
        });
        if (!videoFmts.length && videoSel.children.length === 2) {
            var opt = document.createElement('option');
            opt.value = 'best'; opt.textContent = 'Best available';
            videoSel.appendChild(opt);
        }
    }

    // Audio only
    var audioFmts = (info.formats || []).filter(function(f) {
        return (!f.vcodec || f.vcodec === 'none') && f.acodec && f.acodec !== 'none';
    }).sort(function(a, b) { return (b.tbr || 0) - (a.tbr || 0); });

    var audioSel = document.getElementById('dlAudioSelect');
    if (audioSel) {
        audioSel.innerHTML = '';
        var bestAudio = document.createElement('option');
        bestAudio.value = 'bestaudio'; bestAudio.textContent = 'Best Audio (auto)';
        audioSel.appendChild(bestAudio);
        audioFmts.forEach(function(f) {
            var label = f.ext.toUpperCase() + (f.tbr ? ' ~' + Math.round(f.tbr) + 'k' : '') + (f.format_note ? ' ' + f.format_note : '');
            if (f.filesize) label += ' (' + _dlFmtSize(f.filesize) + ')';
            var opt = document.createElement('option');
            opt.value = f.format_id; opt.textContent = label.trim();
            audioSel.appendChild(opt);
        });
    }

    _dlSwitchTab('video');
    document.getElementById('dlStreamPanel').style.display = 'block';
    document.getElementById('dlDirectDesc').style.display = 'none';
}

function _dlFmtSize(bytes) {
    if (!bytes) return '';
    if (bytes > 1073741824) return (bytes/1073741824).toFixed(1) + ' GB';
    if (bytes > 1048576) return (bytes/1048576).toFixed(1) + ' MB';
    return (bytes/1024).toFixed(0) + ' KB';
}

function _dlSwitchTab(tab) {
    _dlCurrentTab = tab;
    ['video','audio','direct'].forEach(function(t) {
        var btn = document.getElementById('dlTab' + t.charAt(0).toUpperCase() + t.slice(1));
        var panel = document.getElementById('dlPanel' + t.charAt(0).toUpperCase() + t.slice(1));
        if (btn) btn.className = 'dl-tab' + (t === tab ? ' dl-tab-active' : '');
        if (panel) panel.style.display = t === tab ? '' : 'none';
    });
}

async function _dlStreamDownload() {
    var url = (document.getElementById('dlUrlInput') || {}).value;
    if (!url) return;
    url = url.trim();

    if (_dlCurrentTab === 'direct') {
        // Use regular server-side HTTP fetch
        await _dlDirectFetch(url);
        return;
    }

    var selId = _dlCurrentTab === 'audio' ? 'dlAudioSelect' : 'dlVideoSelect';
    var sel = document.getElementById(selId);
    var formatId = sel ? sel.value : 'best';

    var id = ++_dlQueueIdSeq;
    var job = { id, url, filename: (_dlStreamInfo && _dlStreamInfo.title) || url.split('/').pop() || 'video', status: 'pending', error: null };
    _dlQueue.push(job);
    _renderDlQueue();

    var pulseTimer = setInterval(function() { if (job.status === 'pending') _renderDlQueue(); }, 800);
    var btn = document.getElementById('dlStreamBtn');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Downloading…'; }

    try {
        var token = typeof USER_TOKEN !== 'undefined' ? USER_TOKEN : '';
        var hdrs = { 'Content-Type': 'application/json' };
        if (token) hdrs['Authorization'] = 'Bearer ' + token;
        var res = await fetch('/stream-download', {
            method: 'POST', headers: hdrs,
            body: JSON.stringify({ url, format_id: formatId, path: currentPath || '' })
        });
        var d = await res.json();
        clearInterval(pulseTimer);
        if (d.success) {
            job.status = 'done';
            showToast('Downloaded: ' + job.filename, 'success');
            loadFiles();
        } else {
            job.status = 'error'; job.error = d.error || 'Unknown error';
            showToast('Download failed: ' + job.error, 'error');
        }
    } catch(e) {
        clearInterval(pulseTimer);
        job.status = 'error'; job.error = 'Network error';
        showToast('Network error: ' + e.message, 'error');
    }
    if (btn) { btn.disabled = false; btn.textContent = '⬇ Download'; }
    _renderDlQueue();
    setTimeout(function() { _dlQueue = _dlQueue.filter(function(j) { return j.id !== id; }); _renderDlQueue(); }, 8000);
}

async function _dlDirectFetch(url) {
    var id = ++_dlQueueIdSeq;
    var job = { id, url, filename: url.split('/').pop().split('?')[0] || 'file', status: 'pending', error: null };
    _dlQueue.push(job);
    _renderDlQueue();
    var pulseTimer = setInterval(function() { if (job.status === 'pending') _renderDlQueue(); }, 800);
    try {
        var token = typeof USER_TOKEN !== 'undefined' ? USER_TOKEN : '';
        var hdrs = { 'Content-Type': 'application/json' };
        if (token) hdrs['Authorization'] = 'Bearer ' + token;
        var res = await fetch('/download-url', { method: 'POST', headers: hdrs, body: JSON.stringify({ url, path: currentPath || '' }) });
        var d = await res.json();
        clearInterval(pulseTimer);
        if (d.success) {
            job.status = 'done'; job.filename = d.filename || job.filename;
            showToast('Downloaded: ' + job.filename, 'success');
            loadFiles();
        } else {
            job.status = 'error'; job.error = d.error || 'Unknown error';
            showToast('Download failed: ' + job.error, 'error');
        }
    } catch(e) {
        clearInterval(pulseTimer);
        job.status = 'error'; job.error = 'Network error';
        showToast('Network error: ' + e.message, 'error');
    }
    _renderDlQueue();
    setTimeout(function() { _dlQueue = _dlQueue.filter(function(j) { return j.id !== id; }); _renderDlQueue(); }, 8000);
}

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
                  : 'Fetching…';
        var bar = job.status === 'pending'
            ? '<div style="height:3px;background:#e0e0e0;border-radius:2px;margin-top:4px;">'
            + '<div style="height:3px;background:' + barColor + ';width:40%;border-radius:2px;animation:_dlPulse 1.2s ease-in-out infinite;"></div></div>'
            : '';
        var nameDisplay = escapeHtml(job.filename || job.url.split('/').pop().split('?')[0] || job.url);
        return '<div style="padding:8px 0;border-bottom:1px solid #f0f0f0;">'
            + '<div style="display:flex;align-items:center;gap:8px;font-size:13px;">'
            + '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#1a1a1a;" title="' + escapeHtml(job.url) + '">' + nameDisplay + '</span>'
            + '<span style="color:' + statusColor + ';white-space:nowrap;font-size:12px;">' + label + '</span>'
            + '</div>' + bar + '</div>';
    }).join('');
}

// Legacy function kept for any external calls
async function confirmDownloadURL() {
    var url = (document.getElementById('dlUrlInput') || {}).value;
    if (!url) { showToast(_t('toast_enter_url','Please enter a URL'), 'error'); return; }
    url = url.trim();
    await _dlDirectFetch(url);
}
