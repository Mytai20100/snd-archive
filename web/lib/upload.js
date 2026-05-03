// lib/upload.js — chunked file upload
// Requires: utils.js

'use strict';

// Language helper
function _t(key, fallback) { return (window._lang && window._lang[key]) || fallback || key; }

const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB

/**
 * Wire up drag-and-drop and file-input events for the upload area.
 * Call once on DOMContentLoaded.
 */
function initUpload() {
    const uploadArea       = document.getElementById('uploadArea');
    const fileInput        = document.getElementById('fileInput');
    if (!uploadArea || !fileInput) return;

    fileInput.addEventListener('change', updateSelectedFiles);

    uploadArea.addEventListener('dragover', e => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('dragover'));
    uploadArea.addEventListener('drop', e => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        const dropped = e.dataTransfer.files;
        if (!dropped || !dropped.length) return;
        fileInput.files = dropped;
        updateSelectedFiles();
        showToast(dropped.length + ' ' + _t('msg_files_ready', 'file(s) ready — click Upload to send'), 'success');
    });
}

function updateSelectedFiles() {
    const fileInput        = document.getElementById('fileInput');
    const selectedFilesDiv = document.getElementById('selectedFiles');
    if (!fileInput || !selectedFilesDiv) return;

    const files = fileInput.files;
    if (!files.length) { selectedFilesDiv.style.display = 'none'; return; }

    let html = '<strong>Selected (' + files.length + '):</strong><br>';
    for (let i = 0; i < files.length; i++) {
        html += '<div>' + escapeHtml(files[i].name) + ' (' + (files[i].size / 1024).toFixed(1) + ' KB)</div>';
    }
    selectedFilesDiv.innerHTML = html;
    selectedFilesDiv.style.display = 'block';
}

/**
 * Main upload entry point — called by the Upload button.
 * Reads currentPath from global scope (set by navigation).
 */
function uploadFiles() {
    if (typeof isAuthenticated !== 'undefined' && !isAuthenticated) {
        showToast(_t('toast_please_login', 'Please login to upload files'), 'error');
        return;
    }

    const fileInput = document.getElementById('fileInput');
    if (!fileInput || !fileInput.files.length) {
        showToast(_t('validation_select_files', 'Please select files'), 'error');
        return;
    }

    const files = Array.from(fileInput.files);
    const path  = (typeof currentPath !== 'undefined') ? currentPath : '';

    checkConflicts(files, path, resolvedFiles => {
        if (!resolvedFiles || !resolvedFiles.length) return;
        startUpload(resolvedFiles);
    });
}

// ── Conflict detection ────────────────────────────────────────────────────────

function checkConflicts(files, path, callback) {
    const conflicts = [];
    let checked = 0;

    files.forEach(file => {
        fetch('/check-exists', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path, filename: file.name })
        })
        .then(r => r.json())
        .then(d => {
            if (d.exists) conflicts.push(file.name);
            if (++checked === files.length) {
                if (!conflicts.length) {
                    callback(files.map(f => ({ file: f, action: 'overwrite' })));
                } else {
                    showConflictModal(files, conflicts, path, callback);
                }
            }
        })
        .catch(() => {
            if (++checked === files.length) {
                callback(files.map(f => ({ file: f, action: 'overwrite' })));
            }
        });
    });
}

function showConflictModal(files, conflicts, path, callback) {
    const existing = document.getElementById('upload-conflict-modal');
    if (existing) existing.remove();

    const listHtml = conflicts.map(n =>
        '<li style="margin:3px 0;font-family:monospace;font-size:12px;">' + escapeHtml(n) + '</li>'
    ).join('');

    const modal = document.createElement('div');
    modal.id = 'upload-conflict-modal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45)';
    modal.innerHTML = [
        '<div style="background:#fff;border-radius:8px;padding:28px 24px;min-width:340px;max-width:92vw;box-shadow:0 8px 32px rgba(0,0,0,0.22)">',
        '<div style="font-size:16px;font-weight:600;margin-bottom:8px">File conflict</div>',
        '<div style="font-size:13px;color:#555;margin-bottom:10px">The following file(s) already exist in this folder:</div>',
        '<ul style="margin:0 0 16px 18px;padding:0;color:#333;max-height:140px;overflow-y:auto">' + listHtml + '</ul>',
        '<div style="font-size:13px;color:#333;margin-bottom:16px">What would you like to do?</div>',
        '<div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">',
        '<button id="ucm-cancel"    style="padding:8px 16px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:13px">Cancel</button>',
        '<button id="ucm-skip"      style="padding:8px 16px;border:1px solid #ccc;border-radius:4px;background:#f5f5f5;cursor:pointer;font-size:13px">Skip existing</button>',
        '<button id="ucm-rename"    style="padding:8px 16px;border:none;border-radius:4px;background:#1565c0;color:#fff;cursor:pointer;font-size:13px">Keep both (rename)</button>',
        '<button id="ucm-overwrite" style="padding:8px 16px;border:none;border-radius:4px;background:#c62828;color:#fff;cursor:pointer;font-size:13px">Overwrite</button>',
        '</div></div>'
    ].join('');
    document.body.appendChild(modal);

    function close(action) {
        modal.remove();
        if (action === 'cancel') { callback([]); return; }
        const resolved = files.map(f => {
            const isConflict = conflicts.indexOf(f.name) !== -1;
            if (!isConflict) return { file: f, action: 'overwrite' };
            if (action === 'skip') return null;
            return { file: f, action };
        }).filter(Boolean);
        callback(resolved);
    }

    document.getElementById('ucm-cancel').onclick    = () => close('cancel');
    document.getElementById('ucm-skip').onclick      = () => close('skip');
    document.getElementById('ucm-rename').onclick    = () => close('rename');
    document.getElementById('ucm-overwrite').onclick = () => close('overwrite');
    modal.addEventListener('click', e => { if (e.target === modal) close('cancel'); });
}

// ── Upload after conflict resolution ─────────────────────────────────────────

function startUpload(resolvedFiles) {
    const progressSection = document.getElementById('progressSection');
    const progressFill    = document.getElementById('progressFill');
    const progressText    = document.getElementById('progressText');
    const speedText       = document.getElementById('speedText');
    const uploadBtn       = document.querySelector('.upload-btn');

    if (progressSection) progressSection.style.display = 'block';
    if (uploadBtn) { uploadBtn.disabled = true; uploadBtn.textContent = 'Uploading...'; }
    if (window.sndBar) {
        window.sndBar.startUpload('Preparing upload…');
        document.body.classList.add('snd-bar-active');
    }
    showToast(_t('msg_upload_started', 'Upload started —') + ' ' + resolvedFiles.length + ' file(s)', 'success');

    const startTime    = Date.now();
    const totalBytes   = resolvedFiles.reduce((s, r) => s + r.file.size, 0);
    let uploadedBytes  = 0;
    let fileIdx        = 0;

    function uploadNextFile() {
        if (fileIdx >= resolvedFiles.length) { finishUpload(resolvedFiles.length); return; }
        const resolved = resolvedFiles[fileIdx++];
        uploadFileChunked(
            resolved.file,
            resolved.action,
            sent => {
                uploadedBytes += sent;
                const pct       = totalBytes > 0 ? (uploadedBytes / totalBytes * 100).toFixed(1) : 100;
                const elapsed   = (Date.now() - startTime) / 1000;
                const speed     = elapsed > 0 ? (uploadedBytes / elapsed / 1024 / 1024).toFixed(2) : '0.00';
                const remaining = totalBytes - uploadedBytes;
                const eta       = uploadedBytes > 0 ? remaining / (uploadedBytes / elapsed) : 0;
                const etaText   = eta < 60
                    ? ' ETA: ' + Math.floor(eta) + 's'
                    : ' ETA: ' + Math.floor(eta / 60) + 'm ' + Math.floor(eta % 60) + 's';
                if (progressFill) progressFill.style.width = pct + '%';
                if (progressText) progressText.textContent = pct + '% — ' + resolved.file.name;
                if (speedText)    speedText.textContent    = speed + ' MB/s' + etaText;
                if (window.sndBar) {
                    window.sndBar.updateUpload(parseFloat(pct), pct + '% — ' + resolved.file.name + ' — ' + speed + ' MB/s');
                }
            },
            uploadNextFile,
            err => {
                showToast(_t('toast_error', 'Upload failed') + ': ' + err + ' — ' + resolved.file.name, 'error');
                uploadNextFile();
            }
        );
    }

    uploadNextFile();

    function finishUpload(count) {
        showToast(_t('msg_upload_complete', 'Upload complete —') + ' ' + count + ' file(s)', 'success');
        const fileInput        = document.getElementById('fileInput');
        const selectedFilesDiv = document.getElementById('selectedFiles');
        if (fileInput)        fileInput.value = '';
        if (selectedFilesDiv) selectedFilesDiv.style.display = 'none';
        if (progressSection)  progressSection.style.display = 'none';
        if (progressFill)     progressFill.style.width = '0%';
        if (uploadBtn) { uploadBtn.disabled = false; uploadBtn.textContent = 'Upload'; }
        if (window.sndBar) {
            window.sndBar.finishUpload();
            document.body.classList.remove('snd-bar-active');
        }
        setTimeout(() => { if (typeof loadFiles === 'function') loadFiles(); }, 500);
    }
}

/**
 * Upload a single file in CHUNK_SIZE chunks with automatic retry.
 * @param {File}     file
 * @param {'overwrite'|'rename'} action
 * @param {Function} onProgress  - called with bytes sent per tick
 * @param {Function} onDone
 * @param {Function} onError
 */
function uploadFileChunked(file, action, onProgress, onDone, onError) {
    const path      = (typeof currentPath !== 'undefined') ? currentPath : '';
    const totalSize = file.size;
    let offset      = 0;

    function sendChunk(retries = 3) {
        const isFinal   = (offset + CHUNK_SIZE) >= totalSize;
        const chunk     = file.slice(offset, offset + CHUNK_SIZE);
        const chunkSize = chunk.size;
        let bytesSent   = 0;

        const params = new URLSearchParams({
            filename: file.name,
            offset,
            total:  totalSize,
            final:  isFinal ? '1' : '0',
            action: action || 'overwrite'
        });
        if (path) params.set('path', path);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload-chunk?' + params.toString());

        xhr.upload.addEventListener('progress', e => {
            if (e.lengthComputable) {
                const delta = e.loaded - bytesSent;
                if (delta > 0) { bytesSent = e.loaded; onProgress(delta); }
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status === 200) {
                const delta = chunkSize - bytesSent;
                if (delta > 0) onProgress(delta);
                offset += chunkSize;
                if (isFinal) { onDone(); } else { setTimeout(sendChunk, 0); }
            } else {
                if (retries > 0) setTimeout(() => sendChunk(retries - 1), 2000);
                else onError('Server error ' + xhr.status);
            }
        });

        xhr.addEventListener('error', () => {
            if (retries > 0) setTimeout(() => sendChunk(retries - 1), 3000);
            else onError('Network error');
        });

        xhr.addEventListener('abort', () => onError('Upload aborted'));
        xhr.send(chunk);
    }

    sendChunk();
}

// ── Scroll-aware upload badge ─────────────────────────────────────────────────
// When the user scrolls past the upload section, a floating badge shows
// the current upload status and lets them scroll back up.
(function () {
    const SCROLL_THRESHOLD = 120;
    let _badge = null;

    function ensureBadge() {
        if (_badge) return _badge;
        _badge = document.createElement('div');
        _badge.id = '_sndUploadBadge';
        _badge.style.cssText = [
            'display:none;position:fixed;bottom:46px;right:16px;z-index:99998;',
            'background:rgba(20,20,20,0.9);color:#fff;border-radius:24px;',
            'padding:8px 16px;font-size:12px;backdrop-filter:blur(6px);',
            'box-shadow:0 4px 16px rgba(0,0,0,0.3);cursor:pointer;',
            'border:1px solid rgba(255,255,255,0.12);transition:opacity 0.2s;'
        ].join('');
        _badge.title = 'Click to scroll to upload area';
        _badge.addEventListener('click', () => {
            const sec = document.querySelector('.upload-section');
            if (sec) sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
        document.body.appendChild(_badge);
        return _badge;
    }

    function getBadgeLabel() {
        const progressFill  = document.getElementById('progressFill');
        const selectedFiles = document.getElementById('selectedFiles');
        const pct = progressFill ? progressFill.style.width : '';
        if (pct && pct !== '0%') return 'Uploading ' + pct;
        if (selectedFiles && selectedFiles.style.display !== 'none') {
            const count = selectedFiles.querySelectorAll('.selected-file-item').length || '';
            return count ? count + ' file(s) selected' : 'Files selected';
        }
        return 'Upload files';
    }

    function onScroll() {
        const uploadSec = document.querySelector('.upload-section:not(#apiTokenSection)');
        if (!uploadSec) return;
        const isHidden = uploadSec.getBoundingClientRect().bottom < SCROLL_THRESHOLD;
        const badge    = ensureBadge();
        if (isHidden) {
            badge.textContent = getBadgeLabel();
            badge.style.display = 'block';
        } else {
            badge.style.display = 'none';
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        if (!document.getElementById('uploadArea')) return;
        window.addEventListener('scroll', onScroll, { passive: true });

        const progFill = document.getElementById('progressFill');
        if (progFill) {
            new MutationObserver(() => {
                const b = document.getElementById('_sndUploadBadge');
                if (b && b.style.display !== 'none') b.textContent = getBadgeLabel();
            }).observe(progFill, { attributes: true, attributeFilter: ['style'] });
        }
    });
})();
