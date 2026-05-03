// lib/utils.js — shared utility functions

'use strict';

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
}

/**
 * Format bytes into a human-readable string (KB, MB, GB...).
 * @param {number} bytes
 * @returns {string}
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
 * @param {'success'|'error'|string} [type]
 */
function showToast(msg, type) {
    type = type || 'success';
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3000);
}

/**
 * Show a confirm dialog with custom Yes/No buttons (non-blocking).
 * @param {string}   message
 * @param {Function} onYes
 * @param {Object}   [opts] - { yesLabel, yesColor, icon }
 */
function showConfirm(message, onYes, opts) {
    opts = opts || {};

    let modal = document.getElementById('_confirmModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = '_confirmModal';
        modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:100000;align-items:center;justify-content:center;';

        const box = document.createElement('div');
        box.style.cssText = 'background:#fff;border-radius:8px;padding:28px;min-width:300px;max-width:90vw;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);';

        const iconEl = document.createElement('div');
        iconEl.id = '_confirmIcon';
        iconEl.style.cssText = 'font-size:36px;margin-bottom:12px;line-height:1;';

        const msgEl = document.createElement('div');
        msgEl.id = '_confirmMsg';
        msgEl.style.cssText = 'font-size:15px;margin-bottom:20px;line-height:1.5;color:#1a1a1a;';

        const row = document.createElement('div');
        row.style.cssText = 'display:flex;gap:10px;justify-content:center;';

        const cancelBtn = document.createElement('button');
        cancelBtn.id = '_cBtnCancel';
        cancelBtn.style.cssText = 'padding:8px 20px;background:#f5f5f5;border:1px solid #ddd;border-radius:4px;cursor:pointer;font-size:14px;';
        cancelBtn.onclick = () => { modal.style.display = 'none'; };

        const yesBtn = document.createElement('button');
        yesBtn.id = '_cBtnYes';
        yesBtn.style.cssText = 'padding:8px 20px;background:#d32f2f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px;';

        row.appendChild(cancelBtn);
        row.appendChild(yesBtn);
        box.appendChild(iconEl);
        box.appendChild(msgEl);
        box.appendChild(row);
        modal.appendChild(box);
        document.body.appendChild(modal);
        modal.addEventListener('click', e => { if (e.target === modal) modal.style.display = 'none'; });
    }

    const iconEl    = document.getElementById('_confirmIcon');
    const cancelBtn = document.getElementById('_cBtnCancel');
    const yesBtn    = document.getElementById('_cBtnYes');

    iconEl.textContent   = opts.icon !== undefined ? opts.icon : '⚠️';
    iconEl.style.display = opts.icon === '' ? 'none' : 'block';
    document.getElementById('_confirmMsg').textContent = message;
    cancelBtn.textContent   = (typeof _t === 'function') ? _t('modal_cancel', 'Cancel') : 'Cancel';
    yesBtn.textContent      = opts.yesLabel || ((typeof _t === 'function') ? _t('confirm_yes', 'Confirm') : 'Confirm');
    yesBtn.style.background = opts.yesColor || '#d32f2f';
    yesBtn.onclick = () => { modal.style.display = 'none'; if (onYes) onYes(); };

    modal.style.display = 'flex';
}

/**
 * Close a modal by its element id.
 * @param {string} id
 */
function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

// Close modals when clicking on the backdrop
window.addEventListener('click', e => {
    if (e.target && e.target.classList.contains('modal')) {
        closeModal(e.target.id);
    }
});

// ── Bottom loading bar (upload progress / download-URL status) ────────────────
(function () {
    const BAR_ID    = '_sndProgressBar';
    const LABEL_ID  = '_sndProgressLabel';
    const DL_SS_KEY = 'snd_dlurl_pending';

    let _dlTimer     = null;
    let _dlStartTime = 0;

    function ensureBar() {
        if (document.getElementById(BAR_ID)) return;

        const wrap = document.createElement('div');
        wrap.id = '_sndProgressWrap';
        wrap.style.cssText = [
            'position:fixed;bottom:0;left:0;right:0;z-index:99999;',
            'height:36px;background:rgba(20,20,20,0.93);',
            'display:none;align-items:center;gap:10px;padding:0 16px;',
            'backdrop-filter:blur(8px);',
            'border-top:1px solid rgba(255,255,255,0.10);'
        ].join('');

        const track = document.createElement('div');
        track.style.cssText = 'flex:1;height:4px;background:rgba(255,255,255,0.15);border-radius:2px;overflow:hidden;';

        const bar = document.createElement('div');
        bar.id = BAR_ID;
        bar.style.cssText = 'height:100%;width:0%;background:#4caf50;border-radius:2px;transition:width 0.25s ease;';
        track.appendChild(bar);

        const label = document.createElement('span');
        label.id = LABEL_ID;
        label.style.cssText = 'font-size:12px;color:rgba(255,255,255,0.8);white-space:nowrap;min-width:120px;';

        wrap.appendChild(track);
        wrap.appendChild(label);
        document.body.appendChild(wrap);
    }

    function getWrap()  { return document.getElementById('_sndProgressWrap'); }
    function stopTimer(){ if (_dlTimer) { clearInterval(_dlTimer); _dlTimer = null; } }

    function fmtElapsed(ms) {
        const s = Math.floor(ms / 1000);
        if (s < 60) return s + 's';
        const m = Math.floor(s / 60);
        return m + 'm ' + String(s % 60).padStart(2, '0') + 's';
    }

    function fmtSpeed(bytes) {
        if (bytes < 1024)        return bytes + ' B/s';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB/s';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB/s';
    }

    function hideBar(delay) {
        setTimeout(() => {
            const w   = getWrap();
            const bar = document.getElementById(BAR_ID);
            if (w)   w.style.display = 'none';
            if (bar) bar.style.cssText = 'height:100%;width:0%;background:#4caf50;border-radius:2px;transition:width 0.25s ease;';
        }, delay || 0);
    }

    window.sndBar = {
        startUpload(label) {
            ensureBar();
            const w = getWrap(); if (!w) return;
            const bar = document.getElementById(BAR_ID);
            const lbl = document.getElementById(LABEL_ID);
            if (bar) {
                bar.style.background = '#4caf50';
                bar.style.width = '0%';
                bar.style.transition = 'width 0.25s ease';
                bar.style.animation = '';
                bar.style.backgroundSize = '';
            }
            if (lbl) lbl.textContent = label || 'Uploading…';
            w.style.display = 'flex';
        },

        updateUpload(pct, label) {
            const bar = document.getElementById(BAR_ID);
            const lbl = document.getElementById(LABEL_ID);
            if (bar) bar.style.width = Math.min(pct, 100) + '%';
            if (lbl && label) lbl.textContent = label;
        },

        finishUpload() {
            const bar = document.getElementById(BAR_ID);
            if (bar) bar.style.width = '100%';
            hideBar(900);
        },

        startDownload() {
            ensureBar();
            stopTimer();
            _dlStartTime = Date.now();
            const w   = getWrap(); if (!w) return;
            const bar = document.getElementById(BAR_ID);
            const lbl = document.getElementById(LABEL_ID);
            if (bar) {
                bar.style.transition     = 'none';
                bar.style.width          = '100%';
                bar.style.background     = 'linear-gradient(90deg,#1565c0 0%,#42a5f5 50%,#1565c0 100%)';
                bar.style.backgroundSize = '200% 100%';
                bar.style.animation      = 'sndShimmer 1.5s linear infinite';
            }
            if (lbl) lbl.textContent = 'Downloading from URL… 0s';
            w.style.display = 'flex';
            try { sessionStorage.setItem(DL_SS_KEY, Date.now().toString()); } catch (e) {}

            _dlTimer = setInterval(() => {
                const l = document.getElementById(LABEL_ID);
                if (l) l.textContent = 'Downloading from URL… ' + fmtElapsed(Date.now() - _dlStartTime);
            }, 1000);
        },

        finishDownload(sizeBytes) {
            stopTimer();
            const elapsed = Date.now() - _dlStartTime;
            const bar = document.getElementById(BAR_ID);
            const lbl = document.getElementById(LABEL_ID);
            if (bar) {
                bar.style.animation = 'none';
                bar.style.backgroundSize = '';
                bar.style.background = '#4caf50';
                bar.style.width = '100%';
                bar.style.transition = '';
            }
            if (lbl) {
                let msg = 'Done! ' + fmtElapsed(elapsed);
                if (sizeBytes && elapsed > 0) msg += ' — ' + fmtSpeed(sizeBytes / (elapsed / 1000));
                lbl.textContent = msg;
            }
            try { sessionStorage.removeItem(DL_SS_KEY); } catch (e) {}
            hideBar(1800);
        },

        failDownload(errMsg) {
            stopTimer();
            const bar = document.getElementById(BAR_ID);
            const lbl = document.getElementById(LABEL_ID);
            if (bar) {
                bar.style.animation = 'none';
                bar.style.backgroundSize = '';
                bar.style.background = '#c62828';
                bar.style.width = '100%';
                bar.style.transition = '';
            }
            if (lbl) lbl.textContent = errMsg || 'Download failed';
            try { sessionStorage.removeItem(DL_SS_KEY); } catch (e) {}
            hideBar(3000);
        }
    };

    // Restore in-progress download bar across page reloads
    document.addEventListener('DOMContentLoaded', () => {
        try {
            const startTs = sessionStorage.getItem(DL_SS_KEY);
            if (!startTs) return;
            _dlStartTime = parseInt(startTs, 10) || Date.now();
            ensureBar();
            const w   = getWrap();
            const bar = document.getElementById(BAR_ID);
            const lbl = document.getElementById(LABEL_ID);
            if (bar) {
                bar.style.transition     = 'none';
                bar.style.width          = '100%';
                bar.style.background     = 'linear-gradient(90deg,#1565c0 0%,#42a5f5 50%,#1565c0 100%)';
                bar.style.backgroundSize = '200% 100%';
                bar.style.animation      = 'sndShimmer 1.5s linear infinite';
            }
            if (lbl) lbl.textContent = 'Downloading from URL… ' + fmtElapsed(Date.now() - _dlStartTime);
            if (w)   w.style.display = 'flex';
            stopTimer();
            _dlTimer = setInterval(() => {
                const l = document.getElementById(LABEL_ID);
                if (l) l.textContent = 'Downloading from URL… ' + fmtElapsed(Date.now() - _dlStartTime);
            }, 1000);
        } catch (e) {}
    });
})();
