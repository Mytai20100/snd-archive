// lib/share.js — public share page
// Requires: utils.js

'use strict';

function _t(key, fallback) { return (window._lang && window._lang[key]) || fallback || key; }

let allFiles      = [];
let filteredFiles = [];

// Preview state
let _shareFiles = [];
let _shareIdx   = -1;
function setPreviewFiles(files) { _shareFiles = files; }

// ── URL builders ──────────────────────────────────────────────────────────────

function _appendPt(url, f) {
    if (f.public_token) return url + '&pt=' + encodeURIComponent(f.public_token);
    return url;
}

function buildRawUrl(f) {
    if (f.user_uuid && f.raw_path)
        return _appendPt(window.location.origin + '/raw/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid), f);
    const base = window.location.origin + '/raw/' + encodeURIComponent(f.name);
    return f.public_token ? base + '?pt=' + encodeURIComponent(f.public_token) : base;
}

function buildStreamUrl(f) {
    if (f.user_uuid && f.raw_path)
        return _appendPt('/stream/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid), f);
    const base = '/stream/' + encodeURIComponent(f.name);
    return f.public_token ? base + '?pt=' + encodeURIComponent(f.public_token) : base;
}

function buildApiViewUrl(f) {
    if (f.user_uuid && f.raw_path)
        return _appendPt('/api/view/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid), f);
    const base = '/api/view/' + encodeURIComponent(f.name);
    return f.public_token ? base + '?pt=' + encodeURIComponent(f.public_token) : base;
}

function buildThumbnailUrl(f) {
    if (f.user_uuid && f.raw_path)
        return _appendPt('/thumbnail/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid), f);
    const base = '/thumbnail/' + encodeURIComponent(f.name);
    return f.public_token ? base + '?pt=' + encodeURIComponent(f.public_token) : base;
}

function buildDownloadUrl(f) {
    if (f.user_uuid && f.raw_path)
        return _appendPt('/download/' + encodeURIComponent(f.raw_path) + '?u=' + encodeURIComponent(f.user_uuid), f);
    const base = '/download/' + encodeURIComponent(f.name);
    return f.public_token ? base + '?pt=' + encodeURIComponent(f.public_token) : base;
}

// ── Load & stats ──────────────────────────────────────────────────────────────

async function loadPublicFiles() {
    try {
        const res = await fetch('/public-files');
        if (!res.ok) throw new Error();
        allFiles      = (await res.json()) || [];
        filteredFiles = allFiles;
        renderFiles(allFiles);
        updateStats(allFiles);
    } catch {
        document.getElementById('filesSection').innerHTML =
            '<div class="empty-state"><div class="title">Unable to load files</div></div>';
    }
}

function updateStats(files) {
    const totalSize      = files.reduce((s, f) => s + (f.size || 0), 0);
    const totalDownloads = files.reduce((s, f) => s + (f.download_count || 0), 0);
    const admFiles       = files.filter(f => !f.user_uuid).length;
    const userFiles      = files.filter(f =>  f.user_uuid).length;

    document.getElementById('statsBar').innerHTML =
        '<span><strong>' + files.length + '</strong> public files</span>' +
        '<span>Total size: <strong>' + formatFileSize(totalSize) + '</strong></span>' +
        '<span>Downloads: <strong>' + totalDownloads + '</strong></span>' +
        (userFiles > 0
            ? '<span>Admin: <strong>' + admFiles + '</strong> &nbsp;|&nbsp; Users: <strong>' + userFiles + '</strong></span>'
            : '');
}

function filterFiles() {
    const q   = document.getElementById('searchInput').value.toLowerCase();
    filteredFiles = q
        ? allFiles.filter(f => (f.name + ' ' + (f.owner || '')).toLowerCase().includes(q))
        : allFiles;
    renderFiles(filteredFiles);
}

// ── Render ────────────────────────────────────────────────────────────────────

function renderFiles(files) {
    const section = document.getElementById('filesSection');
    if (!files.length) {
        section.innerHTML =
            '<div class="empty-state">' +
            '<div class="title">No public files available</div>' +
            '<div class="subtitle">Files marked as public will appear here.</div>' +
            '</div>';
        return;
    }

    const badgeColors = {
        text:     'background:#e8f5e9;color:#2e7d32',
        image:    'background:#e3f2fd;color:#1976d2',
        video:    'background:#fce4ec;color:#c2185b',
        audio:    'background:#f3e5f5;color:#7b1fa2',
        archive:  'background:#fff3e0;color:#f57c00',
        document: 'background:#ffebee;color:#d32f2f',
    };

    setPreviewFiles(files);

    section.innerHTML = files.map((f, idx) => {
        const rawUrl     = buildRawUrl(f);
        const modDate    = f.mod_time ? new Date(f.mod_time).toLocaleDateString() : 'N/A';
        const typeBadge  = badgeColors[f.type] || 'background:#f5f5f5;color:#616161';
        const isUser     = !!f.user_uuid;
        const ownerLabel = f.owner
            ? (isUser
                ? '<span style="font-size:10px;font-weight:600;color:#2e7d32;background:#e8f5e9;border:1px solid #c8e6c9;padding:1px 6px;border-radius:999px;margin-left:6px;">user:' + escapeHtml(f.owner) + '</span>'
                : '<span style="font-size:10px;font-weight:600;color:#3949ab;background:#e8eaf6;border:1px solid #c5cae9;padding:1px 6px;border-radius:999px;margin-left:6px;">admin</span>')
            : '';

        const canPreview = ['image', 'text', 'video', 'audio'].includes(f.type);
        const previewBtn = canPreview
            ? '<button class="action-btn" onclick="openPreviewByIdx(' + idx + ')">Preview</button>'
            : '';

        const thumbHtml = (f.type === 'image' || f.type === 'video')
            ? '<div onclick="openPreviewByIdx(' + idx + ')" style="cursor:pointer;width:72px;height:72px;border-radius:8px;overflow:hidden;flex-shrink:0;background:#f0f0f0;">' +
              '<img src="' + buildThumbnailUrl(f) + '" loading="lazy" alt="" style="width:100%;height:100%;object-fit:cover;"' +
              ' onerror="this.style.display=\'none\';this.parentNode.style.cssText+=\'background:#f5f5f5;background-image:url(/icons/' + (f.icon || f.type) + '.svg);background-repeat:no-repeat;background-position:center;background-size:36px\'">' +
              '</div>'
            : '<div onclick="openPreviewByIdx(' + idx + ')" style="cursor:pointer;width:72px;height:72px;border-radius:8px;background:#f5f5f5;display:flex;align-items:center;justify-content:center;flex-shrink:0;">' +
              '<img src="/icons/' + (f.icon || f.type) + '.svg" style="width:36px;height:36px;opacity:0.55;" onerror="this.src=\'/icons/file.svg\'">' +
              '</div>';

        return '<div class="file-item">' +
            thumbHtml +
            '<div class="file-info">' +
            '<div class="file-name">' + escapeHtml(f.name) +
            '<span class="file-type-badge" style="' + typeBadge + '">' + f.type + '</span>' +
            ownerLabel +
            '</div>' +
            '<div class="file-meta">' + formatFileSize(f.size) + ' &middot; ' + modDate +
            (f.download_count > 0 ? ' &middot; ' + f.download_count + ' downloads' : '') + '</div>' +
            '<div class="file-url" onclick="copyFileLink(' + idx + ')" title="Click to copy">' + escapeHtml(rawUrl) + '</div>' +
            '</div>' +
            '<div class="file-actions">' +
            previewBtn +
            '<a href="' + buildDownloadUrl(f) + '" class="action-btn">Download</a>' +
            '<button class="action-btn" onclick="copyFileLink(' + idx + ')">Copy link</button>' +
            '</div></div>';
    }).join('');
}

function copyFileLink(idx) {
    const f = filteredFiles[idx];
    if (!f) return;
    navigator.clipboard.writeText(buildRawUrl(f))
        .then(()  => showToast(_t('toast_copied', 'Link copied!'), 'success'))
        .catch(()  => showToast(_t('toast_error_copy', 'Failed to copy'), 'error'));
}

// ── Preview modal ─────────────────────────────────────────────────────────────

function openPreviewByIdx(idx) {
    _shareIdx = idx;
    const f = _shareFiles[idx];
    if (f) showPreview(f);
}

function showPreview(f) {
    const streamUrl  = buildStreamUrl(f);
    const apiViewUrl = buildApiViewUrl(f);
    const baseName   = f.name.split('/').pop();
    const navBtns    =
        '<div style="text-align:center;margin-top:12px;">' +
        '<button class="action-btn" onclick="advancePreview(-1)">&#8592; Prev</button> ' +
        '<button class="action-btn" onclick="advancePreview(1)">Next &#8594;</button></div>';

    document.getElementById('viewTitle').textContent = baseName;

    if (f.type === 'image') {
        document.getElementById('viewBody').innerHTML =
            '<div style="text-align:center;padding:8px;">' +
            '<img src="' + apiViewUrl + '" style="max-width:100%;max-height:70vh;object-fit:contain;" alt="' + escapeHtml(baseName) + '">' +
            '</div>' + navBtns;
        document.getElementById('viewModal').style.display = 'block';
        return;
    }

    if (f.type === 'video' || f.type === 'audio') {
        const ext = f.name.split('.').pop().toLowerCase();
        let playerHtml;
        if (ext === 'm3u8') {
            playerHtml =
                '<video id="hlsPlayer" controls autoplay playsinline style="width:100%;max-height:70vh;background:#000;border-radius:4px;"></video>' +
                '<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"><\/script>' +
                '<script>(function(){' +
                'var v=document.getElementById("hlsPlayer");' +
                'if(Hls.isSupported()){var h=new Hls();h.loadSource("' + streamUrl + '");h.attachMedia(v);v.play().catch(function(){});}' +
                'else if(v.canPlayType("application/vnd.apple.mpegurl")){v.src="' + streamUrl + '";v.play().catch(function(){});}' +
                'v.addEventListener("ended",function(){advancePreview(1);});' +
                '})();<\/script>';
        } else {
            const tag   = f.type === 'audio' ? 'audio' : 'video';
            const style = f.type === 'audio'
                ? 'width:100%;margin:20px 0;'
                : 'width:100%;max-height:70vh;background:#000;border-radius:4px;';
            playerHtml =
                '<' + tag + ' controls autoplay playsinline style="' + style + '" onended="advancePreview(1)">' +
                '<source src="' + streamUrl + '">' +
                '</' + tag + '>';
        }
        document.getElementById('viewBody').innerHTML = playerHtml + navBtns;
        document.getElementById('viewModal').style.display = 'block';
        return;
    }

    if (f.type === 'text') {
        fetch(buildRawUrl(f)).then(r => r.text()).then(c => {
            document.getElementById('viewBody').innerHTML =
                '<pre style="background:#fafafa;padding:16px;border-radius:4px;border:1px solid #e0e0e0;' +
                'font-family:monospace;font-size:13px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;">' +
                escapeHtml(c) + '</pre>';
            document.getElementById('viewModal').style.display = 'block';
        });
    }
}

function advancePreview(dir) {
    if (!_shareFiles.length) return;
    const previewable = ['image', 'video', 'audio', 'text'];
    let next = _shareIdx + dir;
    while (next >= 0 && next < _shareFiles.length) {
        if (previewable.includes(_shareFiles[next].type)) break;
        next += dir;
    }
    if (next < 0 || next >= _shareFiles.length) return;
    _shareIdx = next;
    showPreview(_shareFiles[next]);
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', loadPublicFiles);
