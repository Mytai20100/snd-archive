package snd

// ThemeSnippet returns the complete theme system HTML (styles + panel + script)
// to be embedded just before </body> in any page.
// pageType: "login" | "account" | "dashboard"
func ThemeSnippet(pageType string) string {
	return `
<!-- ═══════════ THEME SYSTEM ═══════════ -->
<div id="bgLayerTheme"></div>

<button id="themeTrigger" onclick="themeTogglePanel(event)" title="Customize theme" aria-label="Theme settings">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/>
        <line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/>
        <line x1="4.22" y1="4.22" x2="7.05" y2="7.05"/><line x1="16.95" y1="16.95" x2="19.78" y2="19.78"/>
        <line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/>
        <line x1="4.22" y1="19.78" x2="7.05" y2="16.95"/><line x1="16.95" y1="7.05" x2="19.78" y2="4.22"/>
    </svg>
</button>

<div id="themePanel">
    <div class="tp-head">Theme</div>

    <div class="tp-sec">
        <div class="tp-label">Background</div>
        <div class="tp-chips">
            <span class="tp-chip" id="tpChipDefault" onclick="themeSet('default')">Default</span>
            <span class="tp-chip" id="tpChipDark"    onclick="themeSet('dark')">Dark</span>
            <span class="tp-chip tp-chip-rainbow"     id="tpChipRainbow" onclick="themeSet('rainbow')">Rainbow</span>
            <span class="tp-chip" id="tpChipImage"   onclick="themeSet('image')">Image / GIF</span>
            <span class="tp-chip" id="tpChipPalette" onclick="themeSet('palette')">Custom</span>
        </div>
    </div>

    <div class="tp-sub" id="tpImageSec">
        <div class="tp-label">URL (image or GIF)</div>
        <input type="text" id="tpBgUrl" class="tp-input" placeholder="https://example.com/bg.gif">
        <button class="tp-apply-btn" onclick="themeApplyImage()">Apply</button>
    </div>

    <div class="tp-sub" id="tpPaletteSec">
        <div class="tp-label">Custom Color Palette</div>
        <div class="tp-palette-grid">
            <label class="tp-clabel">Page BG
                <input type="color" id="pcPageBg"  value="#fafafa" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Card BG
                <input type="color" id="pcCardBg"  value="#ffffff" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Text
                <input type="color" id="pcText"    value="#1a1a1a" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Border
                <input type="color" id="pcBorder"  value="#e0e0e0" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Accent / Btn
                <input type="color" id="pcAccent"  value="#1a1a1a" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Header BG
                <input type="color" id="pcHeader"  value="#ffffff" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Footer BG
                <input type="color" id="pcFooterBg" value="#f5f5f5" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Footer Text
                <input type="color" id="pcFooterText" value="#999999" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Link Color
                <input type="color" id="pcLink"    value="#0066cc" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Input BG
                <input type="color" id="pcInputBg" value="#ffffff" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Modal BG
                <input type="color" id="pcModalBg" value="#ffffff" oninput="themeApplyPalette()">
            </label>
            <label class="tp-clabel">Progress Bar
                <input type="color" id="pcProgress" value="#1a1a1a" oninput="themeApplyPalette()">
            </label>
        </div>
        <button class="tp-apply-btn" style="margin-top:6px" onclick="themeResetPalette()">Reset</button>
    </div>

    <div class="tp-divider"></div>

    <div class="tp-sec">
        <div class="tp-label">Accent Color</div>
        <div class="tp-dots" id="tpDots">
            <span class="tp-dot" style="background:#1a1a1a" data-c="#1a1a1a" onclick="themeSetAccent(this)"></span>
            <span class="tp-dot" style="background:#1565c0" data-c="#1565c0" onclick="themeSetAccent(this)"></span>
            <span class="tp-dot" style="background:#6a1b9a" data-c="#6a1b9a" onclick="themeSetAccent(this)"></span>
            <span class="tp-dot" style="background:#ad1457" data-c="#ad1457" onclick="themeSetAccent(this)"></span>
            <span class="tp-dot" style="background:#c62828" data-c="#c62828" onclick="themeSetAccent(this)"></span>
            <span class="tp-dot" style="background:#e65100" data-c="#e65100" onclick="themeSetAccent(this)"></span>
            <span class="tp-dot" style="background:#00695c" data-c="#00695c" onclick="themeSetAccent(this)"></span>
            <span class="tp-dot" style="background:#283593" data-c="#283593" onclick="themeSetAccent(this)"></span>
        </div>
    </div>

    <div class="tp-divider"></div>

    <div class="tp-sec">
        <div class="tp-row">
            <div>
                <div class="tp-toggle-label">Liquid Glass</div>
                <div class="tp-toggle-sub">Translucent frosted effect</div>
            </div>
            <label class="tp-tgl">
                <input type="checkbox" id="tpLiquidToggle" onchange="themeSetLiquid(this.checked)">
                <span class="tp-tgl-track"></span>
                <span class="tp-tgl-thumb"></span>
            </label>
        </div>
    </div>

    <div class="tp-sec">
        <div class="tp-row">
            <div>
                <div class="tp-toggle-label">Hide Footer</div>
                <div class="tp-toggle-sub">Remove version bar at bottom</div>
            </div>
            <label class="tp-tgl">
                <input type="checkbox" id="tpHideFooterToggle" onchange="themeSetHideFooter(this.checked)">
                <span class="tp-tgl-track"></span>
                <span class="tp-tgl-thumb"></span>
            </label>
        </div>
    </div>
</div>

<style>
/* ── BG layer ── */
#bgLayerTheme {
    position: fixed; inset: 0; z-index: -1;
    background-size: cover; background-position: center; background-repeat: no-repeat;
    opacity: 0; transition: opacity 0.4s; pointer-events: none;
}

/* ── Theme trigger button ── */
#themeTrigger {
    position: fixed; bottom: 20px; right: 20px; z-index: 400;
    width: 44px; height: 44px; border-radius: 50%;
    background: rgba(20,20,20,0.82);
    border: 1px solid rgba(255,255,255,0.16);
    backdrop-filter: blur(16px) saturate(150%);
    -webkit-backdrop-filter: blur(16px) saturate(150%);
    color: #fff; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    box-shadow: 0 4px 18px rgba(0,0,0,0.28), inset 0 1px 0 rgba(255,255,255,0.12);
    transition: transform 0.2s, background 0.2s;
}
#themeTrigger:hover { transform: scale(1.1) rotate(22deg); background: rgba(40,40,40,0.92); }

/* ── Theme panel ── */
#themePanel {
    position: fixed; bottom: 74px; right: 16px; z-index: 300;
    width: 296px;
    background: rgba(14,14,14,0.92);
    backdrop-filter: blur(32px) saturate(200%);
    -webkit-backdrop-filter: blur(32px) saturate(200%);
    border: 1px solid rgba(255,255,255,0.11);
    border-radius: 20px; padding: 16px 18px 18px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.07);
    display: none; color: #fff;
    max-height: calc(100vh - 100px); overflow-y: auto;
}
#themePanel::-webkit-scrollbar { width: 4px; }
#themePanel::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 2px; }
.tp-head { font-size: 12px; font-weight: 700; letter-spacing: 0.7px; color: rgba(255,255,255,0.4); text-transform: uppercase; margin-bottom: 14px; }
.tp-sec { margin-bottom: 14px; }
.tp-sub { margin-bottom: 14px; display: none; }
.tp-label { font-size: 10px; font-weight: 600; color: rgba(255,255,255,0.35); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
.tp-divider { height: 1px; background: rgba(255,255,255,0.08); margin: 12px 0; }

/* Chips */
.tp-chips { display: flex; gap: 5px; flex-wrap: wrap; }
.tp-chip {
    padding: 4px 11px; border-radius: 20px; font-size: 12px; font-weight: 500;
    cursor: pointer; border: 1.5px solid rgba(255,255,255,0.1);
    color: rgba(255,255,255,0.7); background: rgba(255,255,255,0.06);
    transition: all 0.15s; user-select: none;
}
.tp-chip:hover { background: rgba(255,255,255,0.13); color: #fff; }
.tp-chip.active { border-color: rgba(255,255,255,0.6); color: #fff; background: rgba(255,255,255,0.14); box-shadow: 0 0 0 2px rgba(255,255,255,0.12); }
.tp-chip-rainbow {
    background: linear-gradient(90deg, rgba(255,0,85,.5), rgba(255,119,0,.5), rgba(255,204,0,.5), rgba(0,204,68,.5), rgba(0,136,255,.5), rgba(170,0,255,.5));
    border-color: transparent; color: #fff;
}

/* Color dots */
.tp-dots { display: flex; gap: 7px; flex-wrap: wrap; }
.tp-dot {
    width: 24px; height: 24px; border-radius: 50%; cursor: pointer;
    border: 2px solid rgba(255,255,255,0.08); transition: transform 0.15s, border-color 0.15s;
}
.tp-dot:hover { transform: scale(1.2); }
.tp-dot.active { border-color: #fff; box-shadow: 0 0 0 2px rgba(255,255,255,0.22); }

/* Toggle */
.tp-row { display: flex; align-items: center; justify-content: space-between; }
.tp-toggle-label { font-size: 13px; color: rgba(255,255,255,0.85); }
.tp-toggle-sub { font-size: 10px; color: rgba(255,255,255,0.35); margin-top: 2px; }
.tp-tgl { position: relative; width: 40px; height: 22px; cursor: pointer; flex-shrink: 0; display: inline-block; }
.tp-tgl input { opacity: 0; width: 0; height: 0; }
.tp-tgl-track {
    position: absolute; inset: 0; border-radius: 11px;
    background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.15);
    transition: background 0.2s; display: block;
}
.tp-tgl input:checked ~ .tp-tgl-track { background: rgba(100,200,100,0.38); border-color: rgba(100,255,100,0.25); }
.tp-tgl-thumb {
    position: absolute; top: 3px; left: 3px;
    width: 14px; height: 14px; border-radius: 50%;
    background: rgba(255,255,255,0.88);
    box-shadow: 0 1px 4px rgba(0,0,0,0.3); transition: transform 0.2s; display: block;
}
.tp-tgl input:checked ~ .tp-tgl-thumb { transform: translateX(18px); }

/* URL input */
.tp-input {
    width: 100%; padding: 7px 10px; border-radius: 8px;
    border: 1px solid rgba(255,255,255,0.13);
    background: rgba(255,255,255,0.07); color: #fff;
    font-size: 12px; outline: none; transition: border-color 0.15s;
}
.tp-input::placeholder { color: rgba(255,255,255,0.25); }
.tp-input:focus { border-color: rgba(255,255,255,0.32); }
.tp-apply-btn {
    margin-top: 7px; width: 100%; padding: 7px; border-radius: 8px;
    background: rgba(255,255,255,0.09); border: 1px solid rgba(255,255,255,0.14);
    color: rgba(255,255,255,0.8); font-size: 12px; cursor: pointer; transition: background 0.15s;
}
.tp-apply-btn:hover { background: rgba(255,255,255,0.18); color: #fff; }

/* Custom palette grid */
.tp-palette-grid {
    display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px;
}
.tp-clabel {
    display: flex; flex-direction: column; align-items: center; gap: 4px;
    font-size: 10px; color: rgba(255,255,255,0.45); cursor: pointer;
}
.tp-clabel input[type="color"] {
    width: 32px; height: 28px; border: 1px solid rgba(255,255,255,0.15);
    border-radius: 6px; background: none; cursor: pointer; padding: 0;
}

/* ═══ BODY THEME CLASSES ═══ */
@keyframes rainbowBg {
    0%   { background-position: 0% 50%; }
    50%  { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}
body.th-rainbow {
    background: linear-gradient(270deg,#ff0055,#ff6600,#ffcc00,#00cc44,#0066ff,#9900ff,#ff0055) !important;
    background-size: 400% 400% !important;
    animation: rainbowBg 10s ease infinite;
}
body.th-dark { background: #0d0d0d !important; color: #ddd !important; }
body.th-image { background: rgba(0,0,0,0.15) !important; }

/* ═══ LIQUID GLASS — global card/element targets ═══ */
body.th-liquid .card,
body.th-liquid .stat-card,
body.th-liquid .upload-section,
body.th-liquid .file-item,
body.th-liquid .files-section,
body.th-liquid .bulk-actions,
body.th-liquid .progress-section,
body.th-liquid #breadcrumb,
body.th-liquid .login-box,
body.th-liquid .modal-content,
body.th-liquid .container {
    background: rgba(255,255,255,0.08) !important;
    backdrop-filter: blur(24px) saturate(180%) brightness(1.05) !important;
    -webkit-backdrop-filter: blur(24px) saturate(180%) brightness(1.05) !important;
    border-color: rgba(255,255,255,0.18) !important;
    box-shadow: 0 8px 32px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.3) !important;
}
body.th-liquid .file-item {
    border-radius: 12px !important;
    margin-bottom: 4px !important;
}
body.th-liquid.th-dark .card,
body.th-liquid.th-dark .stat-card,
body.th-liquid.th-dark .file-item {
    background: rgba(255,255,255,0.06) !important;
}
/* Liquid on its own (default bg) gets a dark gradient automatically */
body.th-liquid:not(.th-dark):not(.th-rainbow):not(.th-image):not(.th-palette) {
    color: rgba(255,255,255,0.92) !important;
}
body.th-liquid .file-name,
body.th-liquid .file-meta,
body.th-liquid .stat-label,
body.th-liquid .info-label,
body.th-liquid .footer,
body.th-liquid .breadcrumb,
body.th-liquid #breadcrumb {
    color: rgba(255,255,255,0.82) !important;
}
body.th-liquid .btn { color: #fff !important; }
body.th-liquid .footer { background: rgba(0,0,0,0.3) !important; border-color: rgba(255,255,255,0.12) !important; }
body.th-liquid .header {
    background: rgba(255,255,255,0.07) !important;
    backdrop-filter: blur(20px) saturate(160%) !important;
    -webkit-backdrop-filter: blur(20px) saturate(160%) !important;
    border-color: rgba(255,255,255,0.14) !important;
}
/* Text on liquid */
body.th-liquid .info-label,
body.th-liquid .stat-label,
body.th-liquid .stat-sub { color: rgba(255,255,255,0.65) !important; }
body.th-liquid .stat-value,
body.th-liquid h1, body.th-liquid h2,
body.th-liquid .login-title { color: rgba(255,255,255,0.92) !important; }
body.th-liquid .info-value { color: rgba(255,255,255,0.82) !important; }
body.th-liquid .file-name { color: rgba(255,255,255,0.88) !important; }
body.th-liquid .file-meta { color: rgba(255,255,255,0.5) !important; }
body.th-liquid .file-link { color: rgba(150,200,255,0.8) !important; }
body.th-liquid input,
body.th-liquid select,
body.th-liquid textarea,
body.th-liquid .token-input {
    background: rgba(255,255,255,0.10) !important;
    border-color: rgba(255,255,255,0.2) !important;
    color: #fff !important;
}
body.th-liquid input::placeholder { color: rgba(255,255,255,0.35) !important; }
body.th-liquid .cp-toggle-btn {
    background: rgba(255,255,255,0.1) !important;
    border-color: rgba(255,255,255,0.2) !important;
    color: rgba(255,255,255,0.85) !important;
}
body.th-liquid .upload-area {
    background: rgba(255,255,255,0.05) !important;
    border-color: rgba(255,255,255,0.2) !important;
}
body.th-liquid .upload-text { color: rgba(255,255,255,0.6) !important; }
body.th-liquid .menu-btn { background: rgba(255,255,255,0.12) !important; border-color: rgba(255,255,255,0.2) !important; color: rgba(255,255,255,0.85) !important; }
body.th-liquid .context-menu { background: rgba(20,20,30,0.92) !important; backdrop-filter: blur(20px) !important; border-color: rgba(255,255,255,0.15) !important; }
body.th-liquid .context-menu-item { color: rgba(255,255,255,0.8) !important; }
body.th-liquid .context-menu-item:hover { background: rgba(255,255,255,0.12) !important; }
/* FIX: backdrop-filter on .file-item creates a new stacking context that traps .context-menu
   (even at z-index:1000) behind sibling elements. We lift the stacking context so the
   context-menu can appear above everything else in the document. */
body.th-liquid .file-item { isolation: auto !important; }
/* position:fixed escapes the backdrop-filter stacking context; top/right reset to auto so JS can place it precisely */
body.th-liquid .context-menu { position: fixed !important; z-index: 99999 !important; top: auto !important; right: auto !important; left: auto !important; }
/* Need a bg for liquid to look good */
body.th-liquid:not(.th-rainbow):not(.th-dark) {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%) !important;
}

/* ═══ DARK THEME ═══ */
body.th-dark .card,
body.th-dark .stat-card { background: #181818 !important; border-color: #2a2a2a !important; color: #ccc !important; }
body.th-dark .header { background: #111 !important; border-color: #2a2a2a !important; }
body.th-dark .info-label { color: #888 !important; }
body.th-dark .stat-label { color: #666 !important; }
body.th-dark .token-input { background: #111 !important; border-color: #333 !important; color: #ccc !important; }
body.th-dark .cp-toggle-btn { background: #222 !important; border-color: #333 !important; color: #ccc !important; }
body.th-dark input { background: #111 !important; border-color: #333 !important; color: #ddd !important; }
body.th-dark .upload-area { background: #111 !important; border-color: #2a2a2a !important; }
body.th-dark .file-item { background: #181818 !important; border-color: #2a2a2a !important; }
body.th-dark .breadcrumb, body.th-dark [id="breadcrumb"] { background: #111 !important; border-color: #2a2a2a !important; color: #888 !important; }
body.th-dark .footer { background: #0d0d0d !important; border-color: #2a2a2a !important; color: #555 !important; }

/* ═══ CSS VARS for Custom Palette ═══ */
body.th-palette {
    background: var(--tp-page-bg, #fafafa) !important;
    color: var(--tp-text, #1a1a1a) !important;
}
body.th-palette .card,
body.th-palette .stat-card,
body.th-palette .upload-section,
body.th-palette .file-item,
body.th-palette .login-box {
    background: var(--tp-card-bg, #fff) !important;
    border-color: var(--tp-border, #e0e0e0) !important;
    color: var(--tp-text, #1a1a1a) !important;
}
body.th-palette .header { background: var(--tp-header, #fff) !important; border-color: var(--tp-border, #e0e0e0) !important; }
body.th-palette .breadcrumb, body.th-palette [id="breadcrumb"] { background: var(--tp-card-bg, #fff) !important; border-color: var(--tp-border, #e0e0e0) !important; }
body.th-palette .btn,
body.th-palette .submit-btn,
body.th-palette .cp-save-btn { background: var(--tp-accent, #1a1a1a) !important; }
body.th-palette .footer { background: var(--tp-footer-bg, #f5f5f5) !important; color: var(--tp-footer-text, #999) !important; border-color: var(--tp-border, #e0e0e0) !important; }
body.th-palette a, body.th-palette .file-link { color: var(--tp-link, #0066cc) !important; }
body.th-palette input, body.th-palette select, body.th-palette textarea { background: var(--tp-input-bg, #fff) !important; border-color: var(--tp-border, #e0e0e0) !important; color: var(--tp-text, #1a1a1a) !important; }
body.th-palette .modal-content { background: var(--tp-modal-bg, #fff) !important; }
body.th-palette .progress-fill { background: var(--tp-progress, #1a1a1a) !important; }
</style>

<script>
(function(){
'use strict';
const LS_KEY = 'snd_theme_v2';
let S = {
    bg: 'default',
    bgUrl: '',
    accent: '#1a1a1a',
    liquid: false,
    hideFooter: false,
    palette: { pageBg:'#fafafa', cardBg:'#ffffff', text:'#1a1a1a', border:'#e0e0e0', accent:'#1a1a1a', header:'#ffffff', footerBg:'#f5f5f5', footerText:'#999999', link:'#0066cc', inputBg:'#ffffff', modalBg:'#ffffff', progress:'#1a1a1a' }
};

function loadS() {
    try { S = Object.assign(S, JSON.parse(localStorage.getItem(LS_KEY)||'{}')); S.palette = Object.assign({pageBg:'#fafafa',cardBg:'#ffffff',text:'#1a1a1a',border:'#e0e0e0',accent:'#1a1a1a',header:'#ffffff',footerBg:'#f5f5f5',footerText:'#999999',link:'#0066cc',inputBg:'#ffffff',modalBg:'#ffffff',progress:'#1a1a1a'}, S.palette); } catch(e){}
}
function saveS() { localStorage.setItem(LS_KEY, JSON.stringify(S)); }

function applyAll() {
    const body = document.body;
    const bg = document.getElementById('bgLayerTheme');

    // Remove all theme classes
    body.classList.remove('th-rainbow','th-dark','th-image','th-palette','th-liquid');

    // Background
    bg.style.opacity = '0';
    bg.style.backgroundImage = '';
    if (S.bg === 'rainbow') {
        body.classList.add('th-rainbow');
    } else if (S.bg === 'dark') {
        body.classList.add('th-dark');
    } else if (S.bg === 'image' && S.bgUrl) {
        body.classList.add('th-image');
        bg.style.backgroundImage = 'url(' + S.bgUrl + ')';
        bg.style.opacity = '1';
    } else if (S.bg === 'palette') {
        body.classList.add('th-palette');
        applyPaletteVars();
    }

    // Liquid glass
    if (S.liquid) body.classList.add('th-liquid');

    // Accent color - use CSS custom property so dynamically added elements get it too
    document.documentElement.style.setProperty('--accent-color', S.accent);
    if (!S.liquid) {
        const accentStyle = document.getElementById('_accentStyleTag') || (() => {
            const s = document.createElement('style');
            s.id = '_accentStyleTag';
            document.head.appendChild(s);
            return s;
        })();
        accentStyle.textContent = '.btn, .submit-btn, .cp-save-btn, .upload-btn { background: ' + S.accent + ' !important; } .btn:hover, .submit-btn:hover { filter: brightness(1.2); }';
    } else {
        const t = document.getElementById('_accentStyleTag');
        if (t) t.textContent = '';
    }

    // Sync panel UI
    ['default','dark','rainbow','image','palette'].forEach(t => {
        const el = document.getElementById('tpChip' + t.charAt(0).toUpperCase() + t.slice(1));
        if (el) el.classList.toggle('active', t === S.bg);
    });
    document.querySelectorAll('.tp-dot').forEach(d => d.classList.toggle('active', d.dataset.c === S.accent));
    document.getElementById('tpLiquidToggle').checked = S.liquid;
    const hfToggle = document.getElementById('tpHideFooterToggle');
    if (hfToggle) hfToggle.checked = !!S.hideFooter;

    // Hide/show footer
    document.querySelectorAll('.footer').forEach(function(el) {
        el.style.display = S.hideFooter ? 'none' : '';
    });

    const imgSec = document.getElementById('tpImageSec');
    const palSec = document.getElementById('tpPaletteSec');
    if (imgSec) imgSec.style.display = S.bg === 'image' ? 'block' : 'none';
    if (palSec) palSec.style.display = S.bg === 'palette' ? 'block' : 'none';

    if (S.bgUrl) { const el = document.getElementById('tpBgUrl'); if(el) el.value = S.bgUrl; }
    syncPaletteInputs();
}

function applyPaletteVars() {
    const r = document.documentElement;
    r.style.setProperty('--tp-page-bg',    S.palette.pageBg);
    r.style.setProperty('--tp-card-bg',    S.palette.cardBg);
    r.style.setProperty('--tp-text',       S.palette.text);
    r.style.setProperty('--tp-border',     S.palette.border);
    r.style.setProperty('--tp-accent',     S.palette.accent);
    r.style.setProperty('--tp-header',     S.palette.header);
    r.style.setProperty('--tp-footer-bg',  S.palette.footerBg);
    r.style.setProperty('--tp-footer-text',S.palette.footerText);
    r.style.setProperty('--tp-link',       S.palette.link);
    r.style.setProperty('--tp-input-bg',   S.palette.inputBg);
    r.style.setProperty('--tp-modal-bg',   S.palette.modalBg);
    r.style.setProperty('--tp-progress',   S.palette.progress);
}

function syncPaletteInputs() {
    const map = { pcPageBg:'pageBg', pcCardBg:'cardBg', pcText:'text', pcBorder:'border', pcAccent:'accent', pcHeader:'header', pcFooterBg:'footerBg', pcFooterText:'footerText', pcLink:'link', pcInputBg:'inputBg', pcModalBg:'modalBg', pcProgress:'progress' };
    Object.entries(map).forEach(([id, key]) => {
        const el = document.getElementById(id);
        if (el) el.value = S.palette[key] || '#ffffff';
    });
}

/* ── Public API ── */
window.themeSet = function(t) { S.bg = t; saveS(); applyAll(); };
window.themeApplyImage = function() {
    const url = (document.getElementById('tpBgUrl')||{}).value || '';
    if (url.trim()) { S.bgUrl = url.trim(); S.bg = 'image'; saveS(); applyAll(); }
};
window.themeApplyPalette = function() {
    const map = { pcPageBg:'pageBg', pcCardBg:'cardBg', pcText:'text', pcBorder:'border', pcAccent:'accent', pcHeader:'header', pcFooterBg:'footerBg', pcFooterText:'footerText', pcLink:'link', pcInputBg:'inputBg', pcModalBg:'modalBg', pcProgress:'progress' };
    Object.entries(map).forEach(([id, key]) => {
        const el = document.getElementById(id);
        if (el) S.palette[key] = el.value;
    });
    S.accent = S.palette.accent;
    saveS(); applyAll();
};
window.themeResetPalette = function() {
    S.palette = { pageBg:'#fafafa', cardBg:'#ffffff', text:'#1a1a1a', border:'#e0e0e0', accent:'#1a1a1a', header:'#ffffff', footerBg:'#f5f5f5', footerText:'#999999', link:'#0066cc', inputBg:'#ffffff', modalBg:'#ffffff', progress:'#1a1a1a' };
    saveS(); applyAll();
};
window.themeSetAccent = function(el) { S.accent = el.dataset.c; if (S.bg === 'palette') S.palette.accent = S.accent; saveS(); applyAll(); };
window.themeSetLiquid = function(v) { S.liquid = v; saveS(); applyAll(); };
window.themeSetHideFooter = function(v) { S.hideFooter = v; saveS(); applyAll(); };
window.themeTogglePanel = function(e) {
    e.stopPropagation();
    const p = document.getElementById('themePanel');
    p.style.display = p.style.display === 'block' ? 'none' : 'block';
};
document.addEventListener('click', function(e) {
    const p = document.getElementById('themePanel');
    if (p && p.style.display === 'block' && !p.contains(e.target) && e.target.closest('#themeTrigger') === null) {
        p.style.display = 'none';
    }
});

loadS(); applyAll();
})();
</script>
<!-- ═══════════════════════════════════ -->`
}
