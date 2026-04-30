// Language helper
function _t(key, fallback) { return (window._lang && window._lang[key]) || fallback || key; }

// ===== lib/upload.js — chunked file upload =====

var CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB

/**
 * Wire up drag-and-drop and file-input events for the upload area.
 * Call once on DOMContentLoaded (or after the upload section is in the DOM).
 */
function initUpload() {
    var uploadArea     = document.getElementById('uploadArea');
    var fileInput      = document.getElementById('fileInput');
    var selectedFilesDiv = document.getElementById('selectedFiles');
    if (!uploadArea || !fileInput) return;

    fileInput.addEventListener('change', updateSelectedFiles);

    uploadArea.addEventListener('dragover', function (e) {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    uploadArea.addEventListener('dragleave', function () {
        uploadArea.classList.remove('dragover');
    });
    uploadArea.addEventListener('drop', function (e) {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        var dropped = e.dataTransfer.files;
        if (!dropped || !dropped.length) return;
        fileInput.files = dropped;
        updateSelectedFiles();
        showToast(dropped.length + ' ' + _t('msg_files_ready','file(s) ready — click Upload to send'), 'success');
    });
}
function updateSelectedFiles() {
    var fileInput        = document.getElementById('fileInput');
    var selectedFilesDiv = document.getElementById('selectedFiles');
    if (!fileInput || !selectedFilesDiv) return;
    var files = fileInput.files;
    if (!files.length) { selectedFilesDiv.style.display = 'none'; return; }
    var html = '<strong>Selected (' + files.length + '):</strong><br>';
    for (var i = 0; i < files.length; i++) {
        html += '<div>' + escapeHtml(files[i].name) + ' (' + (files[i].size / 1024).toFixed(1) + ' KB)</div>';
    }
    selectedFilesDiv.innerHTML = html;
    selectedFilesDiv.style.display = 'block';
}

/**
 * Main upload entry point — called by the Upload button.
 * Reads currentPath from global scope (set by navigation.js).
 */
function uploadFiles() {
    if (typeof isAuthenticated !== 'undefined' && !isAuthenticated) {
        showToast(_t('toast_please_login','Please login to upload files'), 'error'); return;
    }
    var fileInput = document.getElementById('fileInput');
    if (!fileInput || !fileInput.files.length) { showToast(_t('validation_select_files','Please select files'), 'error'); return; }

    var files = Array.from(fileInput.files);
    var path  = (typeof currentPath !== 'undefined') ? currentPath : '';

    // Check all files for conflicts first, then start upload
    checkConflicts(files, path, function(resolvedFiles) {
        if (!resolvedFiles || !resolvedFiles.length) return; // user cancelled all
        startUpload(resolvedFiles);
    });
}

// ─── Conflict detection ───────────────────────────────────────────────────────
function checkConflicts(files, path, callback) {
    var conflicts = [];
    var checked   = 0;
    files.forEach(function(file) {
        fetch('/check-exists', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path, filename: file.name })
        }).then(function(r) { return r.json(); }).then(function(d) {
            if (d.exists) conflicts.push(file.name);
            checked++;
            if (checked === files.length) {
                if (!conflicts.length) { callback(files.map(function(f){ return {file:f, action:'overwrite'}; })); return; }
                showConflictModal(files, conflicts, path, callback);
            }
        }).catch(function() {
            checked++;
            if (checked === files.length) callback(files.map(function(f){ return {file:f, action:'overwrite'}; }));
        });
    });
}

function showConflictModal(files, conflicts, path, callback) {
    var existing = document.getElementById('upload-conflict-modal');
    if (existing) existing.remove();

    var listHtml = conflicts.map(function(n) { return '<li style="margin:3px 0;font-family:monospace;font-size:12px;">' + escapeHtml(n) + '</li>'; }).join('');
    var modal = document.createElement('div');
    modal.id = 'upload-conflict-modal';
    modal.style.cssText = 'position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45)';
    modal.innerHTML = [
        '<div style="background:#fff;border-radius:8px;padding:28px 24px;min-width:340px;max-width:92vw;box-shadow:0 8px 32px rgba(0,0,0,0.22)">',
        '<div style="font-size:16px;font-weight:600;margin-bottom:8px">[!] File conflict</div>',
        '<div style="font-size:13px;color:#555;margin-bottom:10px">The following file(s) already exist in this folder:</div>',
        '<ul style="margin:0 0 16px 18px;padding:0;color:#333;max-height:140px;overflow-y:auto">' + listHtml + '</ul>',
        '<div style="font-size:13px;color:#333;margin-bottom:16px">What would you like to do?</div>',
        '<div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end">',
        '<button id="ucm-cancel"   style="padding:8px 16px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:13px">Cancel</button>',
        '<button id="ucm-skip"     style="padding:8px 16px;border:1px solid #ccc;border-radius:4px;background:#f5f5f5;cursor:pointer;font-size:13px">Skip existing</button>',
        '<button id="ucm-rename"   style="padding:8px 16px;border:none;border-radius:4px;background:#1565c0;color:#fff;cursor:pointer;font-size:13px">Keep both (rename)</button>',
        '<button id="ucm-overwrite"style="padding:8px 16px;border:none;border-radius:4px;background:#c62828;color:#fff;cursor:pointer;font-size:13px">Overwrite</button>',
        '</div></div>'
    ].join('');
    document.body.appendChild(modal);

    function close(action) {
        modal.remove();
        if (action === 'cancel') { callback([]); return; }
        var resolved = files.map(function(f) {
            var isConflict = conflicts.indexOf(f.name) !== -1;
            if (!isConflict) return { file: f, action: 'overwrite' };
            if (action === 'skip') return null;
            return { file: f, action: action }; // 'overwrite' | 'rename'
        }).filter(Boolean);
        callback(resolved);
    }

    document.getElementById('ucm-cancel').onclick    = function() { close('cancel'); };
    document.getElementById('ucm-skip').onclick      = function() { close('skip'); };
    document.getElementById('ucm-rename').onclick    = function() { close('rename'); };
    document.getElementById('ucm-overwrite').onclick = function() { close('overwrite'); };
    modal.addEventListener('click', function(e) { if (e.target === modal) close('cancel'); });
}

// ─── Actual upload after conflict resolution ──────────────────────────────────
function startUpload(resolvedFiles) {
    var progressSection = document.getElementById('progressSection');
    var progressFill    = document.getElementById('progressFill');
    var progressText    = document.getElementById('progressText');
    var speedText       = document.getElementById('speedText');
    var uploadBtn       = document.querySelector('.upload-btn');

    if (progressSection) progressSection.style.display = 'block';
    if (uploadBtn) { uploadBtn.disabled = true; uploadBtn.textContent = 'Uploading...'; }

    // Bottom bar
    if (window.sndBar) {
        window.sndBar.startUpload('Preparing upload…');
        document.body.classList.add('snd-bar-active');
    }
    showToast(_t('msg_upload_started','Upload started —') + ' ' + resolvedFiles.length + ' file(s)', 'success');

    var startTime     = Date.now();
    var totalBytes    = resolvedFiles.reduce(function(s, r) { return s + r.file.size; }, 0);
    var uploadedBytes = 0;
    var fileIdx       = 0;

    function uploadNextFile() {
        if (fileIdx >= resolvedFiles.length) { finishUpload(resolvedFiles.length); return; }
        var resolved = resolvedFiles[fileIdx++];
        uploadFileChunked(resolved.file, resolved.action,
            function onProgress(sent) {
                uploadedBytes += sent;
                var pct     = totalBytes > 0 ? (uploadedBytes / totalBytes * 100).toFixed(1) : 100;
                var elapsed = (Date.now() - startTime) / 1000;
                var speed   = elapsed > 0 ? (uploadedBytes / elapsed / 1024 / 1024).toFixed(2) : '0.00';
                var remaining = totalBytes - uploadedBytes;
                var eta     = uploadedBytes > 0 ? (remaining / (uploadedBytes / elapsed)) : 0;
                var etaText = eta < 60 ? ' ETA: ' + Math.floor(eta) + 's' : ' ETA: ' + Math.floor(eta / 60) + 'm ' + Math.floor(eta % 60) + 's';
                if (progressFill) progressFill.style.width = pct + '%';
                if (progressText) progressText.textContent = pct + '% — ' + resolved.file.name;
                if (speedText)    speedText.textContent    = speed + ' MB/s' + etaText;
                // Update bottom bar
                if (window.sndBar) {
                    window.sndBar.updateUpload(parseFloat(pct), pct + '% — ' + resolved.file.name + ' — ' + speed + ' MB/s');
                }
            },
            uploadNextFile,
            function onError(err) {
                showToast(_t('toast_error','Upload failed') + ': ' + err + ' — ' + resolved.file.name, 'error');
                uploadNextFile();
            }
        );
    }

    uploadNextFile();

    function finishUpload(count) {
        showToast(_t('msg_upload_complete','Upload complete —') + ' ' + count + ' file(s)', 'success');
        var fileInput = document.getElementById('fileInput');
        if (fileInput) fileInput.value = '';
        var selectedFilesDiv = document.getElementById('selectedFiles');
        if (selectedFilesDiv) selectedFilesDiv.style.display = 'none';
        if (progressSection) progressSection.style.display = 'none';
        if (progressFill) progressFill.style.width = '0%';
        if (uploadBtn) { uploadBtn.disabled = false; uploadBtn.textContent = 'Upload'; }
        if (window.sndBar) {
            window.sndBar.finishUpload();
            document.body.classList.remove('snd-bar-active');
        }
        setTimeout(function () { if (typeof loadFiles === 'function') loadFiles(); }, 500);
    }
}

/**
 * Upload a single file in 4 MB chunks with automatic retry.
 * action: 'overwrite' | 'rename'
 */
function uploadFileChunked(file, action, onProgress, onDone, onError) {
    var path      = (typeof currentPath !== 'undefined') ? currentPath : '';
    var totalSize = file.size;
    var offset    = 0;
    var bytesSentForProgress = 0;

    function sendChunk(retries) {
        if (retries === undefined) retries = 3;
        var isFinal   = (offset + CHUNK_SIZE) >= totalSize;
        var chunk     = file.slice(offset, offset + CHUNK_SIZE);
        var chunkSize = chunk.size;

        var params = new URLSearchParams({
            filename: file.name,
            offset:   offset,
            total:    totalSize,
            final:    isFinal ? '1' : '0',
            action:   action || 'overwrite'
        });
        if (path) params.set('path', path);

        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload-chunk?' + params.toString());

        xhr.upload.addEventListener('progress', function (e) {
            if (e.lengthComputable) {
                var delta = e.loaded - bytesSentForProgress;
                if (delta > 0) { bytesSentForProgress = e.loaded; onProgress(delta); }
            }
        });
        xhr.addEventListener('load', function () {
            if (xhr.status === 200) {
                var delta = chunkSize - bytesSentForProgress;
                if (delta > 0) onProgress(delta);
                bytesSentForProgress = 0;
                offset += chunkSize;
                if (isFinal) { onDone(); } else { setTimeout(sendChunk, 0); }
            } else {
                if (retries > 0) { setTimeout(function () { sendChunk(retries - 1); }, 2000); }
                else { onError('Server error ' + xhr.status); }
            }
        });
        xhr.addEventListener('error', function () {
            if (retries > 0) { setTimeout(function () { sendChunk(retries - 1); }, 3000); }
            else { onError('Network error'); }
        });
        xhr.addEventListener('abort', function () { onError('Upload aborted'); });
        xhr.send(chunk);
    }

    sendChunk();
}

// ─── Scroll-aware upload section ─────────────────────────────────────────────
// When the user scrolls down past the upload section, hide it and show a
// compact floating status badge instead (so upload status is always visible).
(function () {
    var SCROLL_THRESHOLD = 120; // px scrolled before hiding the upload section
    var _badge = null;

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
        _badge.addEventListener('click', function () {
            var sec = document.querySelector('.upload-section');
            if (sec) { sec.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
        });
        document.body.appendChild(_badge);
        return _badge;
    }

    function getBadgeLabel() {
        var progressText = document.getElementById('progressText');
        var progressFill = document.getElementById('progressFill');
        var selectedFiles = document.getElementById('selectedFiles');
        var pct = progressFill ? progressFill.style.width : '';
        if (pct && pct !== '0%') {
            return 'Uploading ' + pct;
        }
        if (selectedFiles && selectedFiles.style.display !== 'none') {
            var count = selectedFiles.querySelectorAll('.selected-file-item').length || '';
            return count ? count + ' file(s) selected' : 'Files selected';
        }
        return 'Upload files';
    }

    function onScroll() {
        var uploadSec = document.querySelector('.upload-section:not(#apiTokenSection)');
        if (!uploadSec) return;
        var rect      = uploadSec.getBoundingClientRect();
        var isHidden  = rect.bottom < SCROLL_THRESHOLD;
        var badge     = ensureBadge();

        if (isHidden) {
            badge.textContent = getBadgeLabel();
            badge.style.display = 'block';
        } else {
            badge.style.display = 'none';
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        // Only activate on pages that have an upload section
        if (!document.getElementById('uploadArea')) return;
        window.addEventListener('scroll', onScroll, { passive: true });
        // Update badge label when progress changes
        var progFill = document.getElementById('progressFill');
        if (progFill) {
            var mo = new MutationObserver(function () {
                if (document.getElementById('_sndUploadBadge') &&
                    document.getElementById('_sndUploadBadge').style.display !== 'none') {
                    document.getElementById('_sndUploadBadge').textContent = getBadgeLabel();
                }
            });
            mo.observe(progFill, { attributes: true, attributeFilter: ['style'] });
        }
    });
})();
