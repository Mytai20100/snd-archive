// qr.js — QR modal + server-side rendering via /api/qr (Go backend)
// Included on both admin dashboard and user dashboard when QR is enabled.

'use strict';

/* ── QR Modal ─────────────────────────────────────────────────────────────── */
(function() {
    // Inject modal HTML once DOM is ready
    function injectModal() {
        if (document.getElementById('snd-qr-modal')) return;
        var modal = document.createElement('div');
        modal.id = 'snd-qr-modal';
        modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:300;align-items:center;justify-content:center;';
        modal.innerHTML =
            '<div style="background:#fff;border-radius:10px;padding:32px 28px;min-width:300px;max-width:380px;width:100%;text-align:center;position:relative;">' +
            '<button id="snd-qr-close" style="position:absolute;top:12px;right:14px;background:none;border:none;font-size:22px;cursor:pointer;color:#888;line-height:1;">&times;</button>' +
            '<div id="snd-qr-title" style="font-size:15px;font-weight:600;margin-bottom:16px;color:#1a1a1a;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"></div>' +
            '<canvas id="snd-qr-canvas" style="border-radius:8px;max-width:100%;display:block;margin:0 auto;"></canvas>' +
            '<div style="margin-top:16px;display:flex;gap:10px;justify-content:center;">' +
            '<button id="snd-qr-download" style="padding:8px 20px;background:#1a1a1a;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:13px;">Download</button>' +
            '<button id="snd-qr-copy" style="padding:8px 20px;background:#f0f0f0;color:#1a1a1a;border:none;border-radius:5px;cursor:pointer;font-size:13px;">Copy Image</button>' +
            '</div></div>';
        document.body.appendChild(modal);

        document.getElementById('snd-qr-close').onclick = closeQRModal;
        modal.addEventListener('click', function(e) { if (e.target === modal) closeQRModal(); });

        document.getElementById('snd-qr-download').onclick = function() {
            var canvas = document.getElementById('snd-qr-canvas');
            var title  = (document.getElementById('snd-qr-title').textContent || 'qr')
                             .replace(/[^a-zA-Z0-9._-]/g, '_');
            var a = document.createElement('a');
            a.download = 'qr-' + title + '.png';
            a.href = canvas.toDataURL('image/png');
            a.click();
        };

        document.getElementById('snd-qr-copy').onclick = function() {
            var canvas = document.getElementById('snd-qr-canvas');
            canvas.toBlob(function(blob) {
                navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })])
                    .then(function() { if (typeof showToast === 'function') showToast('QR copied to clipboard', 'success'); })
                    .catch(function() { if (typeof showToast === 'function') showToast('Copy not supported in this browser', 'error'); });
            });
        };
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectModal);
    } else {
        injectModal();
    }
})();

function generateQR(filename) {
    // Resolve the direct file URL for this file (public token URL or authed URL).
    // SECURITY: never append ?token= (API token) to QR URLs for unauthenticated visitors.
    // The QR image may be shared publicly — leaking the admin API token would allow
    // anyone who scans it to bypass all file permission checks.
    var url;
    var guestMode = (typeof isAuthenticated !== 'undefined' && !isAuthenticated);

    if (typeof allFiles !== 'undefined') {
        var f = allFiles.find(function(x) {
            var fp = (typeof currentPath !== 'undefined' && currentPath)
                ? currentPath + '/' + x.name : x.name;
            return fp === filename || x.name === filename;
        });
        if (f && f.is_public) {
            // Public file: build a clean public URL.
            // Use pt= token if available; otherwise the bare /raw/ URL is enough
            // since public files are accessible without any token.
            var base = window.location.origin + '/raw/' + encodeURIComponent(filename);
            if (f.public_token) {
                url = base + '?pt=' + encodeURIComponent(f.public_token);
            } else {
                url = base; // public without pt= — still works
            }
        } else if (!guestMode) {
            // Authenticated user — safe to use authed URL
            if (typeof makePrivateURL === 'function') {
                url = makePrivateURL(filename);
            } else if (typeof addTokenToURL === 'function') {
                url = addTokenToURL(window.location.origin + '/raw/' + encodeURIComponent(filename));
            } else {
                url = window.location.origin + '/raw/' + encodeURIComponent(filename);
            }
        } else {
            // Guest + private file — should not happen since /files filters these out,
            // but guard anyway: show plain URL (server will block it).
            url = window.location.origin + '/raw/' + encodeURIComponent(filename);
        }
    } else if (!guestMode && typeof addTokenToURL === 'function') {
        // Fallback for user-dash where allFiles may be named differently
        url = addTokenToURL(window.location.origin + '/raw/' + encodeURIComponent(filename));
    } else {
        url = window.location.origin + '/raw/' + encodeURIComponent(filename);
    }

    var modal  = document.getElementById('snd-qr-modal');
    var title  = document.getElementById('snd-qr-title');
    var canvas = document.getElementById('snd-qr-canvas');
    if (!modal) return;

    title.textContent = filename.split('/').pop();
    modal.style.display = 'flex';
    _renderQRServerSide(canvas, url);
}

function closeQRModal() {
    var modal = document.getElementById('snd-qr-modal');
    if (modal) modal.style.display = 'none';
}

// Server-side QR: ask Go to generate the PNG, draw result onto canvas.
function _renderQRServerSide(canvas, text) {
    var size = 280;
    var apiURL = '/api/qr?url=' + encodeURIComponent(text) + '&size=' + size;

    // Show a loading spinner while the server generates the QR
    var ctx = canvas.getContext('2d');
    canvas.width  = size;
    canvas.height = size;
    ctx.fillStyle = '#f5f5f5';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#bbb';
    ctx.font = '14px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Generating…', size/2, size/2);

    var img = new Image();
    img.onload = function() {
        canvas.width  = img.naturalWidth  || size;
        canvas.height = img.naturalHeight || size;
        ctx.drawImage(img, 0, 0);
        // Overlay logo if set
        var logoURL = window._qrLogoURL || '';
        if (logoURL) {
            var logo = new Image();
            logo.crossOrigin = 'anonymous';
            logo.onload = function() {
                var dim = canvas.width;
                var lw = Math.round(dim * 0.22);
                var lh = Math.round(dim * 0.22);
                var lx = Math.round((dim - lw) / 2);
                var ly = Math.round((dim - lh) / 2);
                ctx.fillStyle = '#ffffff';
                ctx.fillRect(lx - 4, ly - 4, lw + 8, lh + 8);
                ctx.drawImage(logo, lx, ly, lw, lh);
            };
            logo.onerror = function() { /* logo failed — QR still visible */ };
            logo.src = logoURL;
        }
    };
    img.onerror = function() {
        // Server QR failed — show error message on canvas
        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, size, size);
        ctx.fillStyle = '#c62828';
        ctx.font = '13px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('QR generation failed', size/2, size/2 - 10);
        ctx.fillStyle = '#888';
        ctx.font = '11px sans-serif';
        ctx.fillText('Check server logs', size/2, size/2 + 10);
        console.error('[SND QR] Server-side QR failed for URL:', text);
    };
    img.src = apiURL;
}


