// ===== lib/utils.js — shared utility functions =====

/**
 * Escape HTML special characters to prevent XSS.
 */
function escapeHtml(text) {
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
}

/**
 * Format bytes into a human-readable string (KB, MB, GB...).
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    const units = ['KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
    let i = 0, size = bytes / 1024;
    while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
    return size.toFixed(2) + ' ' + units[i];
}

/**
 * Show a dismissible toast notification.
 * @param {string} msg
 * @param {'success'|'error'|string} type
 */
function showToast(msg, type) {
    type = type || 'success';
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { t.remove(); }, 3000);
}

/**
 * Show a confirm dialog with custom Yes/No buttons (non-blocking).
 * @param {string} message
 * @param {Function} onYes
 */
function showConfirm(message, onYes, opts) {
    // opts: { yesLabel, yesColor, icon } — all optional
    opts = opts || {};
    var modal = document.getElementById('_confirmModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = '_confirmModal';
        modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:100000;align-items:center;justify-content:center;';
        var box = document.createElement('div');
        box.style.cssText = 'background:#fff;border-radius:8px;padding:28px;min-width:300px;max-width:90vw;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);';
        // icon slot
        var iconEl = document.createElement('div');
        iconEl.id = '_confirmIcon';
        iconEl.style.cssText = 'font-size:36px;margin-bottom:12px;line-height:1;';
        var msgEl = document.createElement('div');
        msgEl.id = '_confirmMsg';
        msgEl.style.cssText = 'font-size:15px;margin-bottom:20px;line-height:1.5;color:#1a1a1a;';
        var row = document.createElement('div');
        row.style.cssText = 'display:flex;gap:10px;justify-content:center;';
        var cancelBtn = document.createElement('button');
        cancelBtn.id = '_cBtnCancel';
        cancelBtn.style.cssText = 'padding:8px 20px;background:#f5f5f5;border:1px solid #ddd;border-radius:4px;cursor:pointer;font-size:14px;';
        cancelBtn.onclick = function () { modal.style.display = 'none'; };
        var yesBtn = document.createElement('button');
        yesBtn.id = '_cBtnYes';
        yesBtn.style.cssText = 'padding:8px 20px;background:#d32f2f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px;';
        row.appendChild(cancelBtn);
        row.appendChild(yesBtn);
        box.appendChild(iconEl);
        box.appendChild(msgEl);
        box.appendChild(row);
        modal.appendChild(box);
        document.body.appendChild(modal);
        modal.addEventListener('click', function (e) { if (e.target === modal) modal.style.display = 'none'; });
    }
    var iconEl = document.getElementById('_confirmIcon');
    iconEl.textContent = opts.icon !== undefined ? opts.icon : '⚠️';
    iconEl.style.display = opts.icon === '' ? 'none' : 'block';
    document.getElementById('_confirmMsg').textContent = message;
    var cancelBtn = document.getElementById('_cBtnCancel');
    cancelBtn.textContent = (typeof _t === 'function') ? _t('modal_cancel','Cancel') : 'Cancel';
    var yesBtn = document.getElementById('_cBtnYes');
    yesBtn.textContent = opts.yesLabel || ((typeof _t === 'function') ? _t('confirm_yes','Confirm') : 'Confirm');
    yesBtn.style.background = opts.yesColor || '#d32f2f';
    yesBtn.onclick = function () {
        modal.style.display = 'none';
        if (onYes) onYes();
    };
    modal.style.display = 'flex';
}

/**
 * Close a modal by its element id.
 * @param {string} id
 */
function closeModal(id) {
    var el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

// Close modal on backdrop click
window.addEventListener('click', function (e) {
    if (e.target && e.target.classList.contains('modal')) {
        closeModal(e.target.id);
    }
});

// ─── NProgress-style bottom loading bar ──────────────────────────────────────
// Used for upload progress and persistent download-URL status.
// sessionStorage key 'snd_dlurl_pending' persists across page reloads.

(function () {
    var BAR_ID   = '_sndProgressBar';
    var LABEL_ID = '_sndProgressLabel';
    var DL_SS_KEY = 'snd_dlurl_pending'; // sessionStorage key

    // Timer state for download elapsed-time display
    var _dlTimer     = null;   // setInterval handle
    var _dlStartTime = 0;      // Date.now() when download began

    function ensureBar() {
        if (document.getElementById(BAR_ID)) return;
        var wrap = document.createElement('div');
        wrap.id = '_sndProgressWrap';
        wrap.style.cssText = [
            'position:fixed;bottom:0;left:0;right:0;z-index:99999;',
            'height:36px;background:rgba(20,20,20,0.93);',
            'display:none;align-items:center;gap:10px;padding:0 16px;',
            'backdrop-filter:blur(8px);',
            'border-top:1px solid rgba(255,255,255,0.10);'
        ].join('');

        var track = document.createElement('div');
        track.style.cssText = 'flex:1;height:4px;background:rgba(255,255,255,0.15);border-radius:2px;overflow:hidden;';
        var bar = document.createElement('div');
        bar.id = BAR_ID;
        bar.style.cssText = 'height:100%;width:0%;background:#4caf50;border-radius:2px;transition:width 0.25s ease;';
        track.appendChild(bar);

        var label = document.createElement('span');
        label.id = LABEL_ID;
        label.style.cssText = 'font-size:12px;color:rgba(255,255,255,0.8);white-space:nowrap;min-width:120px;';

        wrap.appendChild(track);
        wrap.appendChild(label);
        document.body.appendChild(wrap);
    }

    function getWrap() { return document.getElementById('_sndProgressWrap'); }

    // Format seconds to human-readable elapsed string
    function _fmtElapsed(ms) {
        var s = Math.floor(ms / 1000);
        if (s < 60) return s + 's';
        var m = Math.floor(s / 60);
        s = s % 60;
        return m + 'm ' + (s < 10 ? '0' : '') + s + 's';
    }

    // Format bytes/sec to human-readable speed
    function _fmtSpeed(bytes) {
        if (bytes < 1024) return bytes + ' B/s';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB/s';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB/s';
    }

    // Robustly hide and fully reset the bar
    function _hideBar(delay) {
        setTimeout(function () {
            var w   = getWrap();
            var bar = document.getElementById(BAR_ID);
            if (w)   w.style.display = 'none';
            if (bar) {
                // Reset ALL inline styles set during download/upload so next use starts clean
                bar.style.cssText = 'height:100%;width:0%;background:#4caf50;border-radius:2px;transition:width 0.25s ease;';
            }
        }, delay || 0);
    }

    // Stop the elapsed-time ticker
    function _stopTimer() {
        if (_dlTimer) { clearInterval(_dlTimer); _dlTimer = null; }
    }

    window.sndBar = {
        // Upload mode: deterministic progress 0-100
        startUpload: function (label) {
            ensureBar();
            var w = getWrap(); if (!w) return;
            var bar = document.getElementById(BAR_ID);
            var lbl = document.getElementById(LABEL_ID);
            if (bar) {
                bar.style.background   = '#4caf50';
                bar.style.width        = '0%';
                bar.style.transition   = 'width 0.25s ease';
                bar.style.animation    = '';
                bar.style.backgroundSize = '';
            }
            if (lbl) lbl.textContent = label || 'Uploading…';
            w.style.display = 'flex';
        },
        updateUpload: function (pct, label) {
            var bar = document.getElementById(BAR_ID);
            var lbl = document.getElementById(LABEL_ID);
            if (bar) bar.style.width = Math.min(pct, 100) + '%';
            if (lbl && label) lbl.textContent = label;
        },
        finishUpload: function () {
            var bar = document.getElementById(BAR_ID);
            var w   = getWrap();
            if (bar) bar.style.width = '100%';
            _hideBar(900);
        },

        // Download-URL mode: indeterminate shimmer + elapsed time ticker
        startDownload: function (urlHint) {
            ensureBar();
            _stopTimer();
            _dlStartTime = Date.now();
            var w = getWrap(); if (!w) return;
            var bar = document.getElementById(BAR_ID);
            var lbl = document.getElementById(LABEL_ID);
            if (bar) {
                bar.style.transition     = 'none';
                bar.style.width          = '100%';
                bar.style.background     = 'linear-gradient(90deg,#1565c0 0%,#42a5f5 50%,#1565c0 100%)';
                bar.style.backgroundSize = '200% 100%';
                bar.style.animation      = 'sndShimmer 1.5s linear infinite';
            }
            if (lbl) lbl.textContent = 'Downloading from URL… 0s';
            w.style.display = 'flex';
            try { sessionStorage.setItem(DL_SS_KEY, Date.now().toString()); } catch(e) {}

            // Tick elapsed time every second
            _dlTimer = setInterval(function () {
                var lbl2 = document.getElementById(LABEL_ID);
                if (lbl2) {
                    var elapsed = Date.now() - _dlStartTime;
                    lbl2.textContent = 'Downloading from URL… ' + _fmtElapsed(elapsed);
                }
            }, 1000);
        },

        // Call when download completes; pass optional size (bytes) for speed display
        finishDownload: function (sizeBytes) {
            _stopTimer();
            var elapsed = Date.now() - _dlStartTime;
            var bar = document.getElementById(BAR_ID);
            var lbl = document.getElementById(LABEL_ID);
            var w   = getWrap();
            if (bar) {
                bar.style.animation      = 'none';   // stop shimmer immediately
                bar.style.backgroundSize = '';
                bar.style.background     = '#4caf50';
                bar.style.width          = '100%';
                bar.style.transition     = '';
            }
            // Show final stats in label
            if (lbl) {
                var msg = 'Done! ' + _fmtElapsed(elapsed);
                if (sizeBytes && elapsed > 0) {
                    var speed = sizeBytes / (elapsed / 1000);
                    msg += ' — ' + _fmtSpeed(speed);
                }
                lbl.textContent = msg;
            }
            try { sessionStorage.removeItem(DL_SS_KEY); } catch(e) {}
            _hideBar(1800);  // leave success message visible briefly before hiding
        },

        failDownload: function (errMsg) {
            _stopTimer();
            var bar = document.getElementById(BAR_ID);
            var lbl = document.getElementById(LABEL_ID);
            var w   = getWrap();
            if (bar) {
                bar.style.animation      = 'none';
                bar.style.backgroundSize = '';
                bar.style.background     = '#c62828';
                bar.style.width          = '100%';
                bar.style.transition     = '';
            }
            if (lbl) lbl.textContent = errMsg || 'Download failed';
            try { sessionStorage.removeItem(DL_SS_KEY); } catch(e) {}
            _hideBar(3000);
        }
    };

    // On page load: restore pending download bar if sessionStorage flag is set
    document.addEventListener('DOMContentLoaded', function () {
        try {
            var startTs = sessionStorage.getItem(DL_SS_KEY);
            if (startTs) {
                _dlStartTime = parseInt(startTs, 10) || Date.now();
                ensureBar();
                var w   = getWrap();
                var bar = document.getElementById(BAR_ID);
                var lbl = document.getElementById(LABEL_ID);
                if (bar) {
                    bar.style.transition     = 'none';
                    bar.style.width          = '100%';
                    bar.style.background     = 'linear-gradient(90deg,#1565c0 0%,#42a5f5 50%,#1565c0 100%)';
                    bar.style.backgroundSize = '200% 100%';
                    bar.style.animation      = 'sndShimmer 1.5s linear infinite';
                }
                if (lbl) lbl.textContent = 'Downloading from URL… ' + _fmtElapsed(Date.now() - _dlStartTime);
                if (w) w.style.display = 'flex';

                // Resume elapsed-time ticker
                _stopTimer();
                _dlTimer = setInterval(function () {
                    var l = document.getElementById(LABEL_ID);
                    if (l) l.textContent = 'Downloading from URL… ' + _fmtElapsed(Date.now() - _dlStartTime);
                }, 1000);
            }
        } catch(e) {}
    });
})();
