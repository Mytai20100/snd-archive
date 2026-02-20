/**
 * csa-js v0.1
 */
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined'
    ? (module.exports = factory())
    : typeof define === 'function' && define.amd
    ? define(factory)
    : (global.csa = factory());
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  const STYLE_ID = '__csa_v01__';
  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement('style');
    s.id = STYLE_ID;
    s.textContent = `@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=DM+Mono:wght@400;500&display=swap');
:root{--csa-bg:#09090f;--csa-surface:#111119;--csa-border:rgba(255,255,255,.08);--csa-accent:#e8ff47;--csa-accent2:#47b8ff;--csa-text:#f0f0f8;--csa-muted:#6b6b8a;--csa-radius:14px;--csa-font:'Syne',sans-serif;--csa-mono:'DM Mono',monospace;--csa-shadow:0 36px 90px rgba(0,0,0,.75)}
.csa-overlay{position:fixed;inset:0;z-index:9990;background:rgba(0,0,0,.82);backdrop-filter:blur(10px);display:flex;align-items:center;justify-content:center;opacity:0;animation:csaFadeIn .25s ease forwards}
.csa-overlay.csa-closing{animation:csaFadeOut .22s ease forwards}
.csa-wrap{position:relative;background:var(--csa-bg);border-radius:var(--csa-radius);border:1px solid var(--csa-border);box-shadow:var(--csa-shadow);display:flex;flex-direction:column;overflow:hidden;transform:translateY(24px) scale(.97);animation:csaSlideUp .3s cubic-bezier(.16,1,.3,1) forwards;font-family:var(--csa-font);color:var(--csa-text);user-select:none}
.csa-wrap.csa-closing{animation:csaSlideDown .22s ease forwards}
.csa-wrap.csa-mode-modal{width:min(92vw,900px)}.csa-wrap.csa-mode-card{width:min(92vw,560px)}.csa-wrap.csa-mode-box{width:min(92vw,370px)}
.csa-bar{display:flex;align-items:center;gap:10px;padding:11px 15px 10px;background:linear-gradient(180deg,rgba(255,255,255,.04) 0%,transparent 100%);border-bottom:1px solid var(--csa-border);flex-shrink:0}
.csa-wrap:-webkit-full-screen .csa-bar,.csa-wrap:-moz-full-screen .csa-bar,.csa-wrap:fullscreen .csa-bar{display:none}
.csa-dots{display:flex;gap:7px}.csa-dot{width:12px;height:12px;border-radius:50%;cursor:pointer;transition:filter .15s}.csa-dot:hover{filter:brightness(1.4)}.csa-dot-r{background:#ff5f56}.csa-dot-y{background:#ffbd2e}.csa-dot-g{background:#27c93f}
.csa-title{flex:1;font-size:13px;font-weight:700;letter-spacing:.04em;color:var(--csa-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.csa-badge{font-family:var(--csa-mono);font-size:10px;padding:2px 8px;border-radius:20px;background:rgba(232,255,71,.1);color:var(--csa-accent);border:1px solid rgba(232,255,71,.2)}
.csa-stage{position:relative;background:#000;flex:1;aspect-ratio:16/9;overflow:hidden;cursor:pointer}
.csa-wrap:-webkit-full-screen .csa-stage,.csa-wrap:-moz-full-screen .csa-stage,.csa-wrap:fullscreen .csa-stage{aspect-ratio:unset;flex:1}
.csa-wrap:-webkit-full-screen,.csa-wrap:-moz-full-screen,.csa-wrap:fullscreen{width:100vw!important;max-width:100vw!important;height:100vh;border-radius:0;display:flex;flex-direction:column}
.csa-video{width:100%;height:100%;display:block;object-fit:contain;outline:none}
.csa-thumb{position:absolute;inset:0;z-index:2;background-size:cover;background-position:center;display:flex;align-items:center;justify-content:center;transition:opacity .35s}
.csa-thumb.csa-hidden{opacity:0;pointer-events:none}
.csa-loader{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:16px;background:rgba(9,9,15,.92);transition:opacity .35s;z-index:3}
.csa-loader.csa-hidden{opacity:0;pointer-events:none}
.csa-ldr-gif{height:64px;width:auto;object-fit:contain}
.csa-ldr-ring{width:50px;height:50px;border:3px solid rgba(255,255,255,.07);border-top-color:var(--csa-accent);border-radius:50%;animation:csaSpin 1s linear infinite}
.csa-ldr-bars{display:flex;gap:5px;align-items:flex-end;height:34px}.csa-ldr-bars span{width:5px;border-radius:3px;background:var(--csa-accent);animation:csaBarBounce 1s ease-in-out infinite}.csa-ldr-bars span:nth-child(2){animation-delay:.12s}.csa-ldr-bars span:nth-child(3){animation-delay:.24s}.csa-ldr-bars span:nth-child(4){animation-delay:.36s}.csa-ldr-bars span:nth-child(5){animation-delay:.48s}
.csa-ldr-dots{display:flex;gap:10px}.csa-ldr-dots span{width:10px;height:10px;border-radius:50%;background:var(--csa-accent);animation:csaDotPulse 1.1s ease-in-out infinite;opacity:.2}.csa-ldr-dots span:nth-child(2){animation-delay:.2s}.csa-ldr-dots span:nth-child(3){animation-delay:.4s}
.csa-ldr-shimmer{position:absolute;inset:0;background:linear-gradient(110deg,transparent 30%,rgba(232,255,71,.055) 50%,transparent 70%);background-size:200% 100%;animation:csaShimmer 1.5s infinite}
.csa-error{position:absolute;inset:0;z-index:3;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;background:rgba(9,9,15,.96);animation:csaFadeIn .25s ease}
.csa-error-icon{font-size:42px;line-height:1}
.csa-error-msg{font-family:var(--csa-mono);font-size:13px;color:var(--csa-muted);letter-spacing:.05em;text-align:center;max-width:280px;line-height:1.65}
.csa-play-btn{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;z-index:4;transition:opacity .2s}
.csa-play-btn.csa-hide{opacity:0;pointer-events:none}
.csa-play-icon{width:64px;height:64px;display:flex;align-items:center;justify-content:center;transition:transform .18s,opacity .18s;opacity:.85}
.csa-play-icon:hover{transform:scale(1.12);opacity:1}
.csa-sub-display{position:absolute;bottom:64px;left:0;right:0;text-align:center;padding:0 14px;pointer-events:none;z-index:5}
.csa-sub-text{display:inline-block;font-family:var(--csa-font);font-weight:700;padding:4px 12px;border-radius:4px;line-height:1.5;max-width:86%;text-shadow:0 1px 5px rgba(0,0,0,.95);transition:color .2s,background .2s,font-size .2s}
.csa-controls{position:absolute;bottom:0;left:0;right:0;background:linear-gradient(0deg,rgba(0,0,0,.9) 0%,transparent 100%);display:flex;flex-direction:column;padding:0 11px 9px;z-index:6;transition:opacity .24s}
.csa-controls.csa-hide{opacity:0;pointer-events:none}.csa-stage:hover .csa-controls{opacity:1!important}
.csa-prog-row{padding:7px 0 4px}
.csa-progress-wrap{width:100%;height:16px;display:flex;align-items:center;cursor:pointer;position:relative}
.csa-progress-track{width:100%;height:3px;border-radius:2px;background:rgba(255,255,255,.14);position:relative;transition:height .15s}
.csa-progress-wrap:hover .csa-progress-track{height:5px}
.csa-progress-buf{position:absolute;top:0;left:0;height:100%;background:rgba(255,255,255,.18);border-radius:2px}
.csa-progress-fill{position:absolute;top:0;left:0;height:100%;background:var(--csa-accent);border-radius:2px}
.csa-progress-thumb{position:absolute;top:50%;width:12px;height:12px;background:var(--csa-accent);border-radius:50%;transform:translate(-50%,-50%) scale(0);transition:transform .15s;box-shadow:0 0 10px rgba(232,255,71,.5)}
.csa-progress-wrap:hover .csa-progress-thumb{transform:translate(-50%,-50%) scale(1)}
.csa-btn-row{display:flex;align-items:center;gap:3px}
.csa-btn{background:none;border:none;cursor:pointer;padding:5px;color:var(--csa-text);display:flex;align-items:center;opacity:.75;transition:opacity .14s,color .14s,background .14s;flex-shrink:0;border-radius:6px}
.csa-btn:hover{opacity:1;color:var(--csa-accent);background:rgba(255,255,255,.06)}.csa-btn.csa-active{color:var(--csa-accent);opacity:1}
.csa-vol-wrap{display:flex;align-items:center;gap:5px}
.csa-vol-slider{width:58px;height:3px;border-radius:2px;background:rgba(255,255,255,.16);-webkit-appearance:none;cursor:pointer;outline:none;transition:width .18s}
.csa-vol-wrap:hover .csa-vol-slider{width:74px}
.csa-vol-slider::-webkit-slider-thumb{-webkit-appearance:none;width:12px;height:12px;border-radius:50%;background:var(--csa-accent);cursor:pointer}
.csa-time{font-family:var(--csa-mono);font-size:11px;color:rgba(255,255,255,.55);white-space:nowrap;letter-spacing:.04em;padding:0 4px}
.csa-spacer{flex:1}
.csa-speed-badge{font-family:var(--csa-mono);font-size:11px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.65);border-radius:5px;padding:3px 8px;cursor:pointer;letter-spacing:.03em;transition:all .14s;position:relative}
.csa-speed-badge:hover{background:rgba(232,255,71,.1);color:var(--csa-accent);border-color:rgba(232,255,71,.25)}
.csa-qual-badge{font-family:var(--csa-mono);font-size:10px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.65);border-radius:5px;padding:3px 8px;cursor:pointer;letter-spacing:.05em;transition:all .14s;position:relative}
.csa-qual-badge:hover{background:rgba(71,184,255,.1);color:var(--csa-accent2);border-color:rgba(71,184,255,.3)}
.csa-settings-btn{display:flex;align-items:center;justify-content:center;width:28px;height:22px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:5px;cursor:pointer;transition:all .14s;flex-shrink:0;padding:0}
.csa-settings-btn:hover{background:rgba(232,255,71,.1);border-color:rgba(232,255,71,.25)}.csa-settings-btn svg{pointer-events:none}
.csa-settings-btn.csa-active{background:rgba(232,255,71,.12);border-color:rgba(232,255,71,.3)}
.csa-popup{position:absolute;bottom:calc(100% + 8px);right:0;background:#161620;border:1px solid var(--csa-border);border-radius:10px;min-width:150px;box-shadow:0 16px 50px rgba(0,0,0,.7);padding:5px 0;z-index:20;animation:csaFadeIn .13s ease}
.csa-popup-item{display:flex;align-items:center;justify-content:space-between;padding:8px 12px;font-size:13px;cursor:pointer;transition:background .11s;color:var(--csa-text);gap:8px}
.csa-popup-item:hover{background:rgba(255,255,255,.05);color:var(--csa-accent)}.csa-popup-item.csa-selected{color:var(--csa-accent);font-weight:700}
.csa-settings{position:absolute;inset:0;background:var(--csa-bg);z-index:10;overflow-y:auto;display:flex;flex-direction:column;animation:csaFadeIn .16s ease}
.csa-settings-head{display:flex;align-items:center;justify-content:space-between;padding:13px 16px 12px;border-bottom:1px solid var(--csa-border);flex-shrink:0}
.csa-settings-head-title{font-size:13px;font-weight:700;letter-spacing:.04em;color:var(--csa-muted)}
.csa-settings-close{background:none;border:none;cursor:pointer;color:var(--csa-muted);font-size:20px;line-height:1;transition:color .14s;padding:0 4px}.csa-settings-close:hover{color:var(--csa-text)}
.csa-tabs{display:flex;border-bottom:1px solid var(--csa-border);flex-shrink:0}
.csa-tab{flex:1;padding:10px 4px;text-align:center;font-family:var(--csa-mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--csa-muted);cursor:pointer;transition:color .14s;border-bottom:2px solid transparent;margin-bottom:-1px}
.csa-tab:hover{color:var(--csa-text)}.csa-tab.csa-tab-active{color:var(--csa-accent);border-bottom-color:var(--csa-accent)}
.csa-tab-panel{display:none;padding:18px 16px;flex-direction:column;gap:18px}.csa-tab-panel.csa-panel-active{display:flex}
.csa-set-row{display:flex;flex-direction:column;gap:8px}
.csa-set-label{font-family:var(--csa-mono);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--csa-muted)}
.csa-set-desc{font-size:11px;color:var(--csa-muted);line-height:1.5}
.csa-opt-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(74px,1fr));gap:7px}
.csa-opt-btn{padding:10px 6px;border-radius:8px;border:1px solid var(--csa-border);background:rgba(255,255,255,.03);cursor:pointer;text-align:center;font-family:var(--csa-mono);font-size:11px;color:var(--csa-muted);transition:all .14s;line-height:1.3}
.csa-opt-btn:hover{border-color:rgba(232,255,71,.35);color:var(--csa-text);background:rgba(232,255,71,.05)}.csa-opt-btn.csa-active{border-color:var(--csa-accent);color:var(--csa-accent);background:rgba(232,255,71,.08);font-weight:700}
.csa-opt-main{font-size:14px;font-weight:800;margin-bottom:2px}.csa-opt-sub{font-size:9px;opacity:.55;letter-spacing:.04em}
.csa-speed-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:6px}
.csa-speed-btn{padding:9px 4px;border-radius:7px;border:1px solid var(--csa-border);background:rgba(255,255,255,.03);cursor:pointer;text-align:center;font-family:var(--csa-mono);font-size:12px;color:var(--csa-muted);transition:all .14s}
.csa-speed-btn:hover{border-color:rgba(232,255,71,.35);color:var(--csa-text);background:rgba(232,255,71,.05)}.csa-speed-btn.csa-active{border-color:var(--csa-accent);color:var(--csa-accent);background:rgba(232,255,71,.08);font-weight:700}
.csa-color-row{display:flex;gap:7px;flex-wrap:wrap}
.csa-color-swatch{width:26px;height:26px;border-radius:50%;cursor:pointer;border:2px solid transparent;transition:border-color .14s,transform .14s}.csa-color-swatch:hover{transform:scale(1.15)}.csa-color-swatch.csa-active{border-color:#fff}
.csa-range{width:100%;height:3px;border-radius:2px;background:rgba(255,255,255,.12);-webkit-appearance:none;cursor:pointer;outline:none}
.csa-range::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;border-radius:50%;background:var(--csa-accent);cursor:pointer}
.csa-range-row{display:flex;align-items:center;gap:10px}
.csa-range-val{font-family:var(--csa-mono);font-size:11px;color:var(--csa-accent);min-width:32px;text-align:right;flex-shrink:0}
.csa-gif-input{width:100%;background:rgba(255,255,255,.04);border:1px solid var(--csa-border);border-radius:6px;padding:8px 10px;font-family:var(--csa-mono);font-size:11px;color:var(--csa-text);outline:none;margin-top:4px}
.csa-ctx{position:fixed;z-index:10000;background:#161620;border:1px solid var(--csa-border);border-radius:10px;min-width:210px;box-shadow:0 18px 52px rgba(0,0,0,.7);padding:5px 0;font-family:var(--csa-font);animation:csaFadeIn .12s ease}
.csa-ctx-title{font-size:9px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:var(--csa-muted);padding:7px 13px 3px}
.csa-ctx-item{display:flex;align-items:center;gap:9px;padding:8px 13px;font-size:13px;cursor:pointer;transition:background .11s;color:var(--csa-text)}
.csa-ctx-item:hover{background:rgba(255,255,255,.05);color:var(--csa-accent)}.csa-ctx-item svg{flex-shrink:0;opacity:.55}
.csa-ctx-sep{height:1px;background:var(--csa-border);margin:3px 0}
.csa-ctx-item.csa-danger{color:#ff6b6b}.csa-ctx-item.csa-danger:hover{background:rgba(255,107,107,.07)}
.csa-ctx-badge{margin-left:auto;font-family:var(--csa-mono);font-size:10px;color:var(--csa-accent2);opacity:.65}
.csa-props{position:absolute;inset:0;background:var(--csa-bg);z-index:9;overflow-y:auto;padding:18px;animation:csaFadeIn .16s ease;display:flex;flex-direction:column;gap:12px}
.csa-props-title{font-size:14px;font-weight:800;color:var(--csa-accent);display:flex;align-items:center;justify-content:space-between}
.csa-props-close{background:none;border:none;cursor:pointer;color:var(--csa-muted);font-size:20px;line-height:1;transition:color .14s}.csa-props-close:hover{color:var(--csa-text)}
.csa-props-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.csa-prop-card{background:rgba(255,255,255,.04);border:1px solid var(--csa-border);border-radius:8px;padding:10px 12px}
.csa-prop-label{font-family:var(--csa-mono);font-size:9px;letter-spacing:.12em;color:var(--csa-muted);text-transform:uppercase;margin-bottom:4px}
.csa-prop-val{font-family:var(--csa-mono);font-size:12px;color:var(--csa-text);word-break:break-all}
.csa-debug{background:#060609;border-top:1px solid var(--csa-border);padding:10px 12px;font-family:var(--csa-mono);font-size:11px;max-height:120px;overflow-y:auto;flex-shrink:0;display:none}
.csa-debug.csa-show{display:block}
.csa-debug-line{color:var(--csa-muted);margin-bottom:3px}
.csa-debug-line .ts{color:rgba(71,184,255,.5);margin-right:7px}.csa-debug-line .ev{color:var(--csa-accent2);margin-right:6px}.csa-debug-line .val{color:var(--csa-accent)}
@keyframes csaFadeIn{from{opacity:0}to{opacity:1}}
@keyframes csaFadeOut{from{opacity:1}to{opacity:0}}
@keyframes csaSlideUp{from{transform:translateY(24px) scale(.97);opacity:0}to{transform:none;opacity:1}}
@keyframes csaSlideDown{from{transform:none;opacity:1}to{transform:translateY(24px) scale(.97);opacity:0}}
@keyframes csaSpin{to{transform:rotate(360deg)}}
@keyframes csaShimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
@keyframes csaBarBounce{0%,100%{height:8px}40%{height:28px}60%{height:14px}}
@keyframes csaDotPulse{0%,100%{opacity:.2;transform:scale(1)}50%{opacity:1;transform:scale(1.3)}}`;
    document.head.appendChild(s);
  }

  const ic = d => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
  const I = {
    play:   `<svg width="36" height="36" viewBox="0 0 24 24" fill="white" stroke="none"><polygon points="6,3 21,12 6,21"/></svg>`,
    pause:  `<svg width="28" height="28" viewBox="0 0 24 24" fill="white" stroke="none"><rect x="5" y="3" width="4" height="18"/><rect x="15" y="3" width="4" height="18"/></svg>`,
    playS:  ic('<polygon points="5,3 19,12 5,21" fill="currentColor" stroke="none"/>'),
    pauseS: ic('<rect x="5" y="3" width="4" height="18" fill="currentColor" stroke="none"/><rect x="15" y="3" width="4" height="18" fill="currentColor" stroke="none"/>'),
    mute:   ic('<polygon points="11,5 6,9 2,9 2,15 6,15 11,19" fill="currentColor" stroke="none"/><line x1="22" y1="9" x2="16" y2="15"/><line x1="16" y1="9" x2="22" y2="15"/>'),
    vol:    ic('<polygon points="11,5 6,9 2,9 2,15 6,15 11,19" fill="currentColor" stroke="none"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/>'),
    full:   ic('<polyline points="15,3 21,3 21,9"/><polyline points="9,21 3,21 3,15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/>'),
    exitF:  ic('<polyline points="4,14 4,20 10,20"/><polyline points="20,10 20,4 14,4"/><line x1="4" y1="20" x2="11" y2="13"/><line x1="20" y1="4" x2="13" y2="11"/>'),
    close:  ic('<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>'),
    info:   ic('<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'),
    bug:    ic('<path d="M12 2a4 4 0 0 1 4 4"/><path d="M8 6a4 4 0 0 1 4-4"/><rect x="8" y="6" width="8" height="12" rx="4"/><line x1="8" y1="11" x2="4" y2="11"/><line x1="20" y1="11" x2="16" y2="11"/><line x1="8" y1="15" x2="4" y2="15"/><line x1="20" y1="15" x2="16" y2="15"/><line x1="12" y1="18" x2="12" y2="22"/>'),
    sub:    ic('<rect x="2" y="5" width="20" height="14" rx="2"/><line x1="6" y1="11" x2="18" y2="11"/><line x1="6" y1="15" x2="14" y2="15"/>'),
    loop:   ic('<polyline points="17,1 21,5 17,9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7,23 3,19 7,15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>'),
    copy:   ic('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'),
    pip:    ic('<rect x="2" y="3" width="20" height="14" rx="2"/><rect x="12" y="10" width="8" height="5" rx="1"/>'),
    check:  ic('<polyline points="20,6 9,17 4,12"/>'),
    sliders:`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.65)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="6" x2="20" y2="6"/><line x1="8" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/><circle cx="6" cy="6" r="2" fill="rgba(255,255,255,0.65)" stroke="none"/><circle cx="16" cy="12" r="2" fill="rgba(255,255,255,0.65)" stroke="none"/><circle cx="10" cy="18" r="2" fill="rgba(255,255,255,0.65)" stroke="none"/></svg>`,
  };

  function mkBtn(icon, title) {
    const b = document.createElement('button');
    b.className = 'csa-btn'; b.title = title; b.innerHTML = icon; return b;
  }
  function fmt(s) {
    if (!s || isNaN(s)) return '0:00';
    const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=Math.floor(s%60);
    return h?`${h}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`:`${m}:${String(sec).padStart(2,'0')}`;
  }
  function uid()  { return Math.random().toString(36).slice(2,9); }
  function ts()   { return new Date().toLocaleTimeString('en-GB',{hour12:false}); }
  function parseVTT(text) {
    const cues=[];
    for (const block of text.trim().split(/\n\n+/)) {
      const lines=block.split('\n'), tl=lines.find(l=>l.includes('-->'));
      if (!tl) continue;
      const [a,b]=tl.split('-->').map(s=>s.trim());
      const pt=t=>{ const p=t.split(':').map(Number); return p.length===3?p[0]*3600+p[1]*60+p[2]:p[0]*60+p[1]; };
      cues.push({start:pt(a),end:pt(b),text:lines.slice(lines.indexOf(tl)+1).join('<br>')});
    }
    return cues;
  }
  function closePopups() { document.querySelectorAll('.csa-ctx,.csa-popup').forEach(el=>el.remove()); }
  document.addEventListener('click', closePopups);

  class CSAPlayer {
    constructor(opts) {
      this.opts=opts; this.src=opts.src; this.title=opts.title||'Video'; this.mode=opts.mode||'modal';
      this.qualities=opts.qualities||[]; this.activeQI=opts.defaultQuality??0;
      this.subs=[]; this.subEnabled=true;
      this.subColor=opts.subtitle?.color||'#ffffff'; this.subBg=opts.subtitle?.bg||'rgba(0,0,0,0.72)';
      this.subOpacity=opts.subtitle?.opacity??1; this.subSize=opts.subtitle?.size??16;
      this.debugLines=[]; this.loop=opts.loop||false; this.speed=1;
      this._id=uid(); this._ctrlTimer=null; this._dragging=false;
      if (this.qualities.length) this.src=this.qualities[this.activeQI].src;
      this._applyTheme(); this._build(); this._bindEvents();
      const ss=opts.subtitle?.src||(typeof opts.subtitle==='string'?opts.subtitle:null);
      if (ss) this.loadSubtitle(ss);
    }
    _applyTheme() {
      const t=this.opts.theme||{},r=document.documentElement;
      if(t.accent)r.style.setProperty('--csa-accent',t.accent);
      if(t.accent2)r.style.setProperty('--csa-accent2',t.accent2);
      if(t.bg)r.style.setProperty('--csa-bg',t.bg);
      if(t.surface)r.style.setProperty('--csa-surface',t.surface);
      if(t.radius)r.style.setProperty('--csa-radius',t.radius);
    }
    _build() {
      injectStyles();
      this.overlay=document.createElement('div'); this.overlay.className='csa-overlay';
      this.wrap=document.createElement('div'); this.wrap.className=`csa-wrap csa-mode-${this.mode}`;
      if(this.opts.width)this.wrap.style.width=this.opts.width;
      this.bar=document.createElement('div'); this.bar.className='csa-bar';
      this.bar.innerHTML=`<div class="csa-dots"><div class="csa-dot csa-dot-r" title="Close"></div><div class="csa-dot csa-dot-y"></div><div class="csa-dot csa-dot-g" title="Fullscreen"></div></div><span class="csa-title">${this.title}</span><span class="csa-badge">v0.1</span>`;
      this.bar.querySelector('.csa-dot-r').onclick=()=>this.close();
      this.bar.querySelector('.csa-dot-g').onclick=()=>this._toggleFullscreen();
      this.stage=document.createElement('div'); this.stage.className='csa-stage';
      this.thumb=document.createElement('div'); this.thumb.className='csa-thumb'+(this.opts.thumbnail?'':' csa-hidden');
      if(this.opts.thumbnail){
        this.thumb.style.backgroundImage=`url('${this.opts.thumbnail}')`;
        const tp=document.createElement('div'); tp.className='csa-play-icon'; tp.innerHTML=I.play;
        tp.style.cssText='pointer-events:auto;cursor:pointer;width:64px;height:64px;display:flex;align-items:center;justify-content:center;opacity:.85;transition:transform .18s,opacity .18s';
        tp.onmouseenter=()=>{tp.style.transform='scale(1.12)';tp.style.opacity='1'};
        tp.onmouseleave=()=>{tp.style.transform='';tp.style.opacity='.85'};
        tp.onclick=()=>{this.thumb.classList.add('csa-hidden');this.video.play()};
        this.thumb.appendChild(tp);
      }
      this.loader=document.createElement('div'); this.loader.className='csa-loader'; this._buildLoader();
      this.errorEl=null;
      this.video=document.createElement('video'); this.video.className='csa-video'; this.video.src=this.src; this.video.preload='auto';
      if(this.opts.autoplay&&!this.opts.thumbnail)this.video.autoplay=true;
      if(this.opts.muted)this.video.muted=true;
      this.bigPlay=document.createElement('div'); this.bigPlay.className='csa-play-btn'+(this.opts.thumbnail?' csa-hide':'');
      this.bigPlayIcon=document.createElement('div'); this.bigPlayIcon.className='csa-play-icon'; this.bigPlayIcon.innerHTML=I.play;
      this.bigPlay.appendChild(this.bigPlayIcon); this.bigPlay.onclick=()=>this._togglePlay();
      this.subDisplay=document.createElement('div'); this.subDisplay.className='csa-sub-display';
      this.subText=document.createElement('div'); this.subText.className='csa-sub-text'; this.subText.style.display='none';
      this._applySubStyle(); this.subDisplay.appendChild(this.subText);
      this._buildControls();
      this.debugPanel=document.createElement('div'); this.debugPanel.className='csa-debug';
      this.stage.append(this.thumb,this.loader,this.video,this.bigPlay,this.subDisplay,this.controls);
      this.wrap.append(this.bar,this.stage,this.debugPanel);
      this.overlay.appendChild(this.wrap); document.body.appendChild(this.overlay);
      this._log('init',this.src);
    }
    _buildLoader() {
      this.loader.innerHTML='';
      const t=this.opts.loader||'ring';
      if(t==='gif'&&this.opts.loaderGif){const img=document.createElement('img');img.className='csa-ldr-gif';img.src=this.opts.loaderGif;this.loader.appendChild(img);}
      else if(t==='bars')this.loader.innerHTML='<div class="csa-ldr-bars"><span></span><span></span><span></span><span></span><span></span></div>';
      else if(t==='dots')this.loader.innerHTML='<div class="csa-ldr-dots"><span></span><span></span><span></span></div>';
      else if(t==='shimmer')this.loader.innerHTML='<div class="csa-ldr-shimmer"></div><div class="csa-ldr-ring" style="position:relative;z-index:1"></div>';
      else if(t==='custom'&&this.opts.loaderHTML)this.loader.innerHTML=this.opts.loaderHTML;
      else this.loader.innerHTML='<div class="csa-ldr-ring"></div>';
    }
    _buildControls() {
      this.controls=document.createElement('div'); this.controls.className='csa-controls';
      const progRow=document.createElement('div'); progRow.className='csa-prog-row';
      this.progressWrap=document.createElement('div'); this.progressWrap.className='csa-progress-wrap';
      this.progressWrap.innerHTML='<div class="csa-progress-track"><div class="csa-progress-buf"></div><div class="csa-progress-fill"></div><div class="csa-progress-thumb"></div></div>';
      this.progBuf=this.progressWrap.querySelector('.csa-progress-buf');
      this.progFill=this.progressWrap.querySelector('.csa-progress-fill');
      this.progThumb=this.progressWrap.querySelector('.csa-progress-thumb');
      progRow.appendChild(this.progressWrap);
      const btnRow=document.createElement('div'); btnRow.className='csa-btn-row';
      this.btnPlay=mkBtn(I.playS,'Play / Pause'); this.btnPlay.onclick=()=>this._togglePlay();
      const volWrap=document.createElement('div'); volWrap.className='csa-vol-wrap';
      this.btnMute=mkBtn(I.vol,'Mute'); this.btnMute.onclick=()=>this._toggleMute();
      this.volSlider=document.createElement('input'); this.volSlider.type='range'; this.volSlider.min=0; this.volSlider.max=1; this.volSlider.step=.01; this.volSlider.value=1; this.volSlider.className='csa-vol-slider';
      this.volSlider.oninput=()=>{this.video.volume=+this.volSlider.value;this._log('volume',this.volSlider.value)};
      volWrap.append(this.btnMute,this.volSlider);
      this.timeEl=document.createElement('div'); this.timeEl.className='csa-time'; this.timeEl.textContent='0:00 / 0:00';
      const spacer=document.createElement('div'); spacer.className='csa-spacer';
      this.speedBadge=document.createElement('button'); this.speedBadge.className='csa-speed-badge'; this.speedBadge.textContent='1x'; this.speedBadge.title='Speed'; this.speedBadge.style.position='relative';
      this.speedBadge.onclick=e=>{e.stopPropagation();this._toggleSpeedPopup()};
      this.qualBadge=null;
      if(this.qualities.length>1){
        this.qualBadge=document.createElement('button'); this.qualBadge.className='csa-qual-badge'; this.qualBadge.textContent=this.qualities[this.activeQI].label; this.qualBadge.title='Quality'; this.qualBadge.style.position='relative';
        this.qualBadge.onclick=e=>{e.stopPropagation();this._toggleQualPopup()};
      }
      this.btnLoop=mkBtn(I.loop,'Loop'); this.btnLoop.onclick=()=>{this.loop=!this.loop;this.video.loop=this.loop;this.btnLoop.classList.toggle('csa-active',this.loop);this._log('loop',this.loop)};
      if(this.loop){this.btnLoop.classList.add('csa-active');this.video.loop=true}
      this.btnSub=mkBtn(I.sub,'Subtitles'); this.btnSub.classList.add('csa-active');
      this.btnSub.onclick=()=>{this.subEnabled=!this.subEnabled;this.btnSub.classList.toggle('csa-active',this.subEnabled);if(!this.subEnabled)this.subText.style.display='none'};
      this.btnPip=mkBtn(I.pip,'PiP'); this.btnPip.onclick=()=>{document.pictureInPictureElement?document.exitPictureInPicture():this.video.requestPictureInPicture&&this.video.requestPictureInPicture()};
      this.btnSettings=document.createElement('button'); this.btnSettings.className='csa-settings-btn'; this.btnSettings.title='Settings'; this.btnSettings.innerHTML=I.sliders;
      this.btnSettings.onclick=()=>this._toggleSettings();
      this.btnFull=mkBtn(I.full,'Fullscreen'); this.btnFull.onclick=()=>this._toggleFullscreen();
      const right=[this.speedBadge];
      if(this.qualBadge)right.push(this.qualBadge);
      right.push(this.btnLoop,this.btnSub,this.btnPip,this.btnSettings,this.btnFull);
      btnRow.append(this.btnPlay,volWrap,this.timeEl,spacer,...right);
      this.controls.append(progRow,btnRow);
    }
    _applySubStyle() {
      this.subText.style.color=this.subColor; this.subText.style.background=this.subBg;
      this.subText.style.opacity=this.subOpacity; this.subText.style.fontSize=this.subSize+'px';
    }
    _toggleSpeedPopup() {
      const ex=this.controls.querySelector('.csa-popup'); if(ex){ex.remove();return}
      const popup=document.createElement('div'); popup.className='csa-popup';
      [0.25,0.5,0.75,1,1.25,1.5,1.75,2].forEach(sp=>{
        const row=document.createElement('div'); row.className='csa-popup-item'+(this.speed===sp?' csa-selected':'');
        row.innerHTML=`<span>${sp}x</span>${this.speed===sp?`<span>${I.check}</span>`:''}`;
        row.onclick=e=>{e.stopPropagation();this.setSpeed(sp);popup.remove()};
        popup.appendChild(row);
      });
      this.speedBadge.appendChild(popup);
    }
    _toggleQualPopup() {
      if(!this.qualBadge)return;
      const ex=this.controls.querySelector('.csa-popup'); if(ex){ex.remove();return}
      const popup=document.createElement('div'); popup.className='csa-popup';
      this.qualities.forEach((q,i)=>{
        const row=document.createElement('div'); row.className='csa-popup-item'+(this.activeQI===i?' csa-selected':'');
        row.innerHTML=`<span>${q.label}${q.badge?` <span style="opacity:.45;font-size:10px">${q.badge}</span>`:''}</span>${this.activeQI===i?`<span>${I.check}</span>`:''}`;
        row.onclick=e=>{e.stopPropagation();this.setQuality(i);popup.remove()};
        popup.appendChild(row);
      });
      this.qualBadge.appendChild(popup);
    }
    _toggleSettings() {
      const ex=this.stage.querySelector('.csa-settings');
      if(ex){ex.remove();this.btnSettings.classList.remove('csa-active');return}
      this.btnSettings.classList.add('csa-active');
      const drawer=document.createElement('div'); drawer.className='csa-settings';
      drawer.innerHTML=`
        <div class="csa-settings-head">
          <span class="csa-settings-head-title">Settings</span>
          <button class="csa-settings-close">&times;</button>
        </div>
        <div class="csa-tabs">
          <div class="csa-tab csa-tab-active" data-tab="quality">Quality</div>
          <div class="csa-tab" data-tab="speed">Speed</div>
          <div class="csa-tab" data-tab="subtitle">Subtitle</div>
          <div class="csa-tab" data-tab="loader">Loader</div>
        </div>
        <div class="csa-tab-panel csa-panel-active" data-panel="quality">${this._tplQuality()}</div>
        <div class="csa-tab-panel" data-panel="speed">${this._tplSpeed()}</div>
        <div class="csa-tab-panel" data-panel="subtitle">${this._tplSub()}</div>
        <div class="csa-tab-panel" data-panel="loader">${this._tplLoader()}</div>`;
      drawer.querySelector('.csa-settings-close').onclick=()=>{drawer.remove();this.btnSettings.classList.remove('csa-active')};
      drawer.querySelectorAll('.csa-tab').forEach(tab=>{
        tab.onclick=()=>{
          drawer.querySelectorAll('.csa-tab').forEach(t=>t.classList.remove('csa-tab-active'));
          drawer.querySelectorAll('.csa-tab-panel').forEach(p=>p.classList.remove('csa-panel-active'));
          tab.classList.add('csa-tab-active');
          drawer.querySelector(`[data-panel="${tab.dataset.tab}"]`).classList.add('csa-panel-active');
        };
      });
      drawer.querySelectorAll('.csa-quality-btn').forEach((b,i)=>{b.onclick=()=>{this.setQuality(i);drawer.querySelectorAll('.csa-quality-btn').forEach(x=>x.classList.remove('csa-active'));b.classList.add('csa-active')}});
      drawer.querySelectorAll('.csa-speed-btn').forEach(b=>{b.onclick=()=>{this.setSpeed(+b.dataset.speed);drawer.querySelectorAll('.csa-speed-btn').forEach(x=>x.classList.remove('csa-active'));b.classList.add('csa-active')}});
      drawer.querySelectorAll('.csa-loader-btn').forEach(b=>{
        b.onclick=()=>{
          this.opts.loader=b.dataset.loader; this._buildLoader();
          drawer.querySelectorAll('.csa-loader-btn').forEach(x=>x.classList.remove('csa-active'));
          b.classList.add('csa-active'); this._log('loader',b.dataset.loader);
          const gifRow=drawer.querySelector('.csa-gif-row');
          if(gifRow)gifRow.style.display=b.dataset.loader==='gif'?'flex':'none';
        };
      });
      this._bindSubControls(drawer);
      this.stage.appendChild(drawer);
    }
    _tplQuality() {
      if(!this.qualities.length)return`<div class="csa-set-row"><div class="csa-set-desc">No quality levels defined. Pass <code style="color:var(--csa-accent2)">qualities:[{label,src}]</code></div></div>`;
      return`<div class="csa-set-row"><div class="csa-opt-grid">${this.qualities.map((q,i)=>`<div class="csa-opt-btn csa-quality-btn${this.activeQI===i?' csa-active':''}"><div class="csa-opt-main">${q.label}</div>${q.badge?`<div class="csa-opt-sub">${q.badge}</div>`:''}</div>`).join('')}</div></div>`;
    }
    _tplSpeed() {
      return`<div class="csa-set-row"><div class="csa-speed-grid">${[0.25,0.5,0.75,1,1.25,1.5,1.75,2].map(sp=>`<button class="csa-speed-btn${this.speed===sp?' csa-active':''}" data-speed="${sp}">${sp}x</button>`).join('')}</div></div>`;
    }
    _tplSub() {
      const tc=['#ffffff','#e8ff47','#47b8ff','#ff6b6b','#ff9f47','#b847ff','#47ffb8'];
      const bc=[{l:'Dark',v:'rgba(0,0,0,0.72)'},{l:'Black',v:'rgba(0,0,0,0.95)'},{l:'50%',v:'rgba(0,0,0,0.5)'},{l:'20%',v:'rgba(0,0,0,0.2)'},{l:'None',v:'transparent'}];
      return`
        <div class="csa-set-row"><div class="csa-set-label">Text Color</div><div class="csa-color-row sub-tc">${tc.map(c=>`<div class="csa-color-swatch${this.subColor===c?' csa-active':''}" data-color="${c}" style="background:${c}"></div>`).join('')}</div></div>
        <div class="csa-set-row"><div class="csa-set-label">Background</div><div class="csa-color-row sub-bc">${bc.map(b=>`<div class="csa-color-swatch${this.subBg===b.v?' csa-active':''}" data-bg="${b.v}" style="background:${b.v};border-color:rgba(255,255,255,.3)" title="${b.l}"></div>`).join('')}</div></div>
        <div class="csa-set-row"><div class="csa-set-label">Font Size</div><div class="csa-range-row"><input type="range" class="csa-range" id="csSz" min="11" max="30" value="${this.subSize}" step="1"><span class="csa-range-val">${this.subSize}px</span></div></div>
        <div class="csa-set-row"><div class="csa-set-label">Opacity</div><div class="csa-range-row"><input type="range" class="csa-range" id="csOp" min="0.1" max="1" value="${this.subOpacity}" step="0.05"><span class="csa-range-val">${Math.round(this.subOpacity*100)}%</span></div></div>`;
    }
    _tplLoader() {
      const items=[{id:'ring',m:'Ring',s:'spinner'},{id:'bars',m:'Bars',s:'bounce'},{id:'dots',m:'Dots',s:'pulse'},{id:'shimmer',m:'Shimmer',s:'sweep'},{id:'gif',m:'GIF',s:'custom'},{id:'custom',m:'HTML',s:'inject'}];
      const cur=this.opts.loader||'ring';
      return`<div class="csa-set-row"><div class="csa-opt-grid">${items.map(l=>`<div class="csa-opt-btn csa-loader-btn${cur===l.id?' csa-active':''}" data-loader="${l.id}"><div class="csa-opt-main">${l.m}</div><div class="csa-opt-sub">${l.s}</div></div>`).join('')}</div></div>
        <div class="csa-set-row csa-gif-row" style="display:${cur==='gif'?'flex':'none'}"><div class="csa-set-label">GIF URL</div><input class="csa-gif-input" id="csGifUrl" type="text" placeholder="https://..." value="${this.opts.loaderGif||''}"/></div>`;
    }
    _bindSubControls(drawer) {
      drawer.querySelectorAll('.sub-tc .csa-color-swatch').forEach(sw=>{sw.onclick=()=>{this.subColor=sw.dataset.color;drawer.querySelectorAll('.sub-tc .csa-color-swatch').forEach(s=>s.classList.remove('csa-active'));sw.classList.add('csa-active');this._applySubStyle()}});
      drawer.querySelectorAll('.sub-bc .csa-color-swatch').forEach(sw=>{sw.onclick=()=>{this.subBg=sw.dataset.bg;drawer.querySelectorAll('.sub-bc .csa-color-swatch').forEach(s=>s.classList.remove('csa-active'));sw.classList.add('csa-active');this._applySubStyle()}});
      const szR=drawer.querySelector('#csSz'); if(szR){const v=szR.nextElementSibling;szR.oninput=()=>{this.subSize=+szR.value;v.textContent=szR.value+'px';this._applySubStyle()}}
      const opR=drawer.querySelector('#csOp'); if(opR){const v=opR.nextElementSibling;opR.oninput=()=>{this.subOpacity=+opR.value;v.textContent=Math.round(opR.value*100)+'%';this._applySubStyle()}}
      const gi=drawer.querySelector('#csGifUrl'); if(gi){gi.oninput=()=>{this.opts.loaderGif=gi.value;this._buildLoader()}}
    }
    _bindEvents() {
      const v=this.video;
      v.addEventListener('canplay',()=>{this.loader.classList.add('csa-hidden');this._log('canplay','ready')});
      v.addEventListener('waiting',()=>{if(!this.errorEl)this.loader.classList.remove('csa-hidden');this._log('waiting','buffering')});
      v.addEventListener('playing',()=>{this.loader.classList.add('csa-hidden');this.bigPlay.classList.add('csa-hide');this.btnPlay.innerHTML=I.pauseS;this.bigPlayIcon.innerHTML=I.pause;this._log('playing',fmt(v.currentTime))});
      v.addEventListener('pause',()=>{this.bigPlay.classList.remove('csa-hide');this.btnPlay.innerHTML=I.playS;this.bigPlayIcon.innerHTML=I.play;this._log('pause',fmt(v.currentTime))});
      v.addEventListener('ended',()=>{this.bigPlay.classList.remove('csa-hide');this.btnPlay.innerHTML=I.playS;this.bigPlayIcon.innerHTML=I.play;this._log('ended','done');this.opts.onEnd&&this.opts.onEnd()});
      v.addEventListener('error',()=>{this.loader.classList.add('csa-hidden');this._showError();this._log('error',v.error?.message||'unknown')});
      v.addEventListener('timeupdate',()=>{
        const pct=v.duration?v.currentTime/v.duration*100:0;
        this.progFill.style.width=pct+'%';this.progThumb.style.left=pct+'%';
        this.timeEl.textContent=fmt(v.currentTime)+' / '+fmt(v.duration);
        this._updateSub(v.currentTime);
      });
      v.addEventListener('progress',()=>{if(v.buffered.length)this.progBuf.style.width=(v.buffered.end(v.buffered.length-1)/v.duration*100)+'%'});
      v.addEventListener('volumechange',()=>{this.btnMute.innerHTML=(v.muted||v.volume===0)?I.mute:I.vol});
      const seek=e=>{const r=this.progressWrap.getBoundingClientRect(),pct=Math.max(0,Math.min(1,(e.clientX-r.left)/r.width));if(v.duration)v.currentTime=pct*v.duration;this._log('seek',fmt(v.currentTime))};
      this.progressWrap.addEventListener('mousedown',e=>{this._dragging=true;seek(e)});
      document.addEventListener('mousemove',e=>{if(this._dragging)seek(e)});
      document.addEventListener('mouseup',()=>{this._dragging=false});
      this.stage.addEventListener('mousemove',()=>{this.controls.classList.remove('csa-hide');clearTimeout(this._ctrlTimer);if(!v.paused)this._ctrlTimer=setTimeout(()=>this.controls.classList.add('csa-hide'),2800)});
      this.stage.addEventListener('contextmenu',e=>{e.preventDefault();this._showCtx(e)});
      this._keyHandler=e=>{
        if(!this.overlay.isConnected)return;
        if(['INPUT','SELECT','TEXTAREA'].includes(document.activeElement.tagName))return;
        if(e.key===' '||e.key==='k'){e.preventDefault();this._togglePlay()}
        if(e.key==='ArrowRight'){v.currentTime=Math.min(v.duration,v.currentTime+5);this._log('skip','+5s')}
        if(e.key==='ArrowLeft'){v.currentTime=Math.max(0,v.currentTime-5);this._log('skip','-5s')}
        if(e.key==='ArrowUp')this.setVolume(Math.min(1,v.volume+.1));
        if(e.key==='ArrowDown')this.setVolume(Math.max(0,v.volume-.1));
        if(e.key==='m')this._toggleMute();
        if(e.key==='f')this._toggleFullscreen();
        if(e.key==='Escape'){const s=this.stage.querySelector('.csa-settings');s?s.remove():this.close()}
      };
      document.addEventListener('keydown',this._keyHandler);
      document.addEventListener('fullscreenchange',()=>{this.btnFull.innerHTML=document.fullscreenElement?I.exitF:I.full});
      this.overlay.addEventListener('click',e=>{if(e.target===this.overlay)this.close()});
    }
    _showError() {
      if(this.errorEl)return;
      this.errorEl=document.createElement('div'); this.errorEl.className='csa-error';
      this.errorEl.innerHTML=`<div class="csa-error-icon">${this.opts.errorIcon||'⚠️'}</div><div class="csa-error-msg">${this.opts.errorMessage||'Failed to load video.'}</div>`;
      this.stage.appendChild(this.errorEl);
    }
    _togglePlay(){this.video.paused?this.video.play():this.video.pause()}
    _toggleMute(){this.video.muted=!this.video.muted}
    _toggleFullscreen(){!document.fullscreenElement?this.wrap.requestFullscreen&&this.wrap.requestFullscreen():document.exitFullscreen&&document.exitFullscreen()}
    _updateSub(t){
      if(!this.subEnabled||!this.subs.length)return;
      const cue=this.subs.find(c=>t>=c.start&&t<=c.end);
      if(cue){this.subText.innerHTML=cue.text;this.subText.style.display='inline-block'}else{this.subText.style.display='none'}
    }
    _log(event,value){
      const line=document.createElement('div'); line.className='csa-debug-line';
      line.innerHTML=`<span class="ts">${ts()}</span><span class="ev">${event}</span><span class="val">${value}</span>`;
      this.debugPanel.appendChild(line); this.debugPanel.scrollTop=this.debugPanel.scrollHeight;
      this.debugLines.push({ts:ts(),event,value});
    }
    _showCtx(e){
      closePopups();
      const menu=document.createElement('div'); menu.className='csa-ctx';
      const tEl=document.createElement('div'); tEl.className='csa-ctx-title'; tEl.textContent='csa-js'; menu.appendChild(tEl);
      const items=[
        {label:'Properties',icon:I.info,action:()=>this._showProps()},{sep:true},
        {label:'Debug Console',icon:I.bug,action:()=>{this.debugPanel.classList.toggle('csa-show');this._log('debug',this.debugPanel.classList.contains('csa-show')?'opened':'closed')},badge:this.debugLines.length+'ev'},
        {label:'Copy Log',icon:I.copy,action:()=>navigator.clipboard&&navigator.clipboard.writeText(this.debugLines.map(l=>`[${l.ts}] ${l.event}: ${l.value}`).join('\n'))},{sep:true},
        {label:'Settings',icon:I.sliders,action:()=>this._toggleSettings()},
        {label:'Copy URL',icon:I.copy,action:()=>navigator.clipboard&&navigator.clipboard.writeText(this.src)},
        {label:'Picture-in-Picture',icon:I.pip,action:()=>this.video.requestPictureInPicture&&this.video.requestPictureInPicture()},
        {label:'Toggle Loop',icon:I.loop,action:()=>this.btnLoop.click(),badge:this.loop?'on':''},{sep:true},
        {label:'Close',icon:I.close,action:()=>this.close(),danger:true},
      ];
      items.forEach(it=>{
        if(it.sep){const s=document.createElement('div');s.className='csa-ctx-sep';menu.appendChild(s);return}
        const row=document.createElement('div'); row.className='csa-ctx-item'+(it.danger?' csa-danger':'');
        row.innerHTML=it.icon+`<span>${it.label}</span>`+(it.badge?`<span class="csa-ctx-badge">${it.badge}</span>`:'');
        row.onclick=()=>{closePopups();it.action()}; menu.appendChild(row);
      });
      menu.style.left=Math.min(e.clientX,window.innerWidth-220)+'px';
      menu.style.top=Math.min(e.clientY,window.innerHeight-310)+'px';
      document.body.appendChild(menu);
    }
    _showProps(){
      const ex=this.stage.querySelector('.csa-props'); if(ex){ex.remove();return}
      const v=this.video;
      const fields=[['URL',(this.qualities[this.activeQI]?.src||this.src).slice(0,45)+'…'],['Title',this.title],['Duration',fmt(v.duration)],['Current',fmt(v.currentTime)],['Resolution',v.videoWidth?`${v.videoWidth}x${v.videoHeight}`:'loading…'],['Volume',Math.round(v.volume*100)+'%'],['Speed',v.playbackRate+'x'],['Quality',this.qualities[this.activeQI]?.label||'default'],['Buffered',v.buffered.length?fmt(v.buffered.end(v.buffered.length-1)):'0:00'],['ReadyState',['NOTHING','METADATA','CURRENT','FUTURE','ENOUGH'][v.readyState]],['Loop',v.loop?'On':'Off'],['Subs',this.subs.length+' cues'],['Mode',this.mode],['Loader',this.opts.loader||'ring']];
      const props=document.createElement('div'); props.className='csa-props';
      props.innerHTML=`<div class="csa-props-title">Properties <button class="csa-props-close">&times;</button></div><div class="csa-props-grid">${fields.map(([l,v])=>`<div class="csa-prop-card"><div class="csa-prop-label">${l}</div><div class="csa-prop-val">${v}</div></div>`).join('')}</div>`;
      props.querySelector('.csa-props-close').onclick=()=>props.remove();
      this.stage.appendChild(props);
    }
    loadSubtitle(src){src.startsWith('http')||src.startsWith('/')?fetch(src).then(r=>r.text()).then(t=>{this.subs=parseVTT(t);this._log('subtitle',`${this.subs.length} cues`)}):(this.subs=parseVTT(src),this._log('subtitle',`${this.subs.length} cues`))}
    addCue(s,e,t){this.subs.push({start:s,end:e,text:t});this.subs.sort((a,b)=>a.start-b.start)}
    setSubtitleStyle(o={}){if(o.color!==undefined)this.subColor=o.color;if(o.bg!==undefined)this.subBg=o.bg;if(o.opacity!==undefined)this.subOpacity=o.opacity;if(o.size!==undefined)this.subSize=o.size;this._applySubStyle()}
    setQuality(i){if(!this.qualities.length||i<0||i>=this.qualities.length)return;const wp=!this.video.paused,t=this.video.currentTime;this.activeQI=i;this.src=this.qualities[i].src;this.video.src=this.src;this.video.currentTime=t;if(wp)this.video.play();if(this.qualBadge)this.qualBadge.textContent=this.qualities[i].label;this._log('quality',this.qualities[i].label)}
    setLoader(type){this.opts.loader=type;this._buildLoader()}
    play(){this.video.play()}
    pause(){this.video.pause()}
    seek(t){this.video.currentTime=t}
    setVolume(v){this.video.volume=Math.max(0,Math.min(1,v));this.volSlider.value=v;this._log('volume',v)}
    setSpeed(r){this.video.playbackRate=r;this.speed=r;this.speedBadge.textContent=r+'x';this._log('speed',r+'x')}
    setLoop(b){this.video.loop=this.loop=b;this.btnLoop.classList.toggle('csa-active',b)}
    setMode(m){this.wrap.className=`csa-wrap csa-mode-${m}`;this.mode=m}
    debug(show){this.debugPanel.classList[show===undefined?'toggle':show?'add':'remove']('csa-show')}
    info(){const v=this.video;return{src:this.src,title:this.title,duration:v.duration,current:v.currentTime,width:v.videoWidth,height:v.videoHeight,volume:v.volume,speed:v.playbackRate,loop:v.loop,quality:this.qualities[this.activeQI]?.label||'default',subs:this.subs.length,mode:this.mode}}
    close(){this.video.pause();document.removeEventListener('keydown',this._keyHandler);this.overlay.classList.add('csa-closing');this.wrap.classList.add('csa-closing');setTimeout(()=>{this.overlay.remove();this.opts.onClose&&this.opts.onClose()},220)}
  }

  const instances=new Map();
  function player(opts={}){
    if(!opts.src&&!(opts.qualities&&opts.qualities.length))throw new Error('csa: src required');
    if(!opts.src&&opts.qualities)opts.src=opts.qualities[opts.defaultQuality||0].src;
    const p=new CSAPlayer(opts),id=p._id;instances.set(id,p);
    const oc=opts.onClose;p.opts.onClose=()=>{instances.delete(id);oc&&oc()};
    return p;
  }
  function modal(src,title,opts={}){return player({...opts,src,title:title||'Video',mode:'modal'})}
  function card(src,title,opts={}){return player({...opts,src,title:title||'Video',mode:'card'})}
  function box(src,title,opts={}){return player({...opts,src,title:title||'Video',mode:'box'})}
  function from(el,opts={}){const src=opts.src||el.dataset.csaSrc,title=opts.title||el.dataset.csaTitle,mode=opts.mode||el.dataset.csaMode||'modal';if(!src)throw new Error('csa.from: no src');el.addEventListener('click',()=>player({...opts,src,title,mode}))}
  function init(){document.querySelectorAll('[data-csa]').forEach(el=>from(el))}
  function closeAll(){instances.forEach(p=>p.close())}
  return{player,modal,card,box,from,init,closeAll,_instances:instances};
});
