(function () {
    'use strict';

    var TURNSTILE_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    var VERIFY_URL = '/api/challenge/verify';
    var CONFIG_URL = '/api/challenge/config';
    var WIDGET_ID = 'sndChallengeWidget';

    var overlay = null;
    var widgetReady = false;
    var pending = null;
    var langPromise = null;

    function t(key) {
        return (window._lang && window._lang[key]) || key;
    }

    function ensureLang() {
        if (window._lang) return Promise.resolve(window._lang);
        if (langPromise) return langPromise;
        langPromise = fetch('/api/lang')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && typeof data === 'object') {
                    window._lang = data;
                    document.querySelectorAll('[data-i18n]').forEach(function (el) {
                        var k = el.getAttribute('data-i18n');
                        if (data[k]) el.textContent = data[k];
                    });
                }
                return window._lang || {};
            })
            .catch(function () { return {}; });
        return langPromise;
    }

    function shell() {
        if (overlay) return overlay;
        var el = document.createElement('div');
        el.id = 'sndChallengeOverlay';
        el.className = 'modal';
        el.setAttribute('style', 'display:flex;align-items:center;justify-content:center;');
        el.innerHTML = [
            '<div class="modal-content" style="max-width:420px;">',
            '    <div class="modal-header"><h3 data-i18n="challenge_title"></h3></div>',
            '    <div class="modal-body">',
            '        <p style="font-size:13px;color:#666;margin-bottom:16px;" data-i18n="challenge_waiting"></p>',
            '        <div id="' + WIDGET_ID + '"></div>',
            '        <div id="sndChallengeError" style="display:none;margin-top:16px;padding:12px;background:#fff3f3;border-left:3px solid #d32f2f;border-radius:0 4px 4px 0;font-size:13px;color:#c62828;"></div>',
            '    </div>',
            '    <div class="modal-footer">',
            '        <button type="button" class="btn-small" id="sndChallengeRetry" style="display:none;" data-i18n="challenge_retry"></button>',
            '    </div>',
            '</div>'
        ].join('');
        document.body.appendChild(el);
        overlay = el;
        el.querySelectorAll('[data-i18n]').forEach(function (node) {
            var k = node.getAttribute('data-i18n');
            if (window._lang && window._lang[k]) node.textContent = window._lang[k];
        });
        el.querySelector('#sndChallengeRetry').addEventListener('click', function () {
            showChallengeOverlay();
        });
        return el;
    }

    function showError(code) {
        if (!overlay) return;
        var box = overlay.querySelector('#sndChallengeError');
        var btn = overlay.querySelector('#sndChallengeRetry');
        if (!box) return;
        box.textContent = t('challenge_error_' + code);
        box.style.display = 'block';
        if (btn) btn.style.display = '';
    }

    function clearError() {
        if (!overlay) return;
        var box = overlay.querySelector('#sndChallengeError');
        var btn = overlay.querySelector('#sndChallengeRetry');
        if (box) { box.style.display = 'none'; box.textContent = ''; }
        if (btn) btn.style.display = 'none';
    }

    function loadTurnstile(cb) {
        var existing = document.querySelector('script[data-snd-turnstile]');
        if (existing && window.turnstile) { cb(); return; }
        if (existing) {
            existing.addEventListener('load', function () { cb(); });
            existing.addEventListener('error', function () { showError('widget_unavailable'); });
            return;
        }
        var s = document.createElement('script');
        s.src = TURNSTILE_SRC;
        s.async = true;
        s.defer = true;
        s.setAttribute('data-snd-turnstile', '1');
        s.addEventListener('load', function () { cb(); });
        s.addEventListener('error', function () { showError('widget_unavailable'); });
        document.head.appendChild(s);
    }

    function renderWidget(cfg) {
        var host = overlay ? overlay.querySelector('#' + WIDGET_ID) : null;
        if (!host || !window.turnstile) { showError('widget_unavailable'); return; }
        host.innerHTML = '';
        var opts = {
            sitekey: cfg.site_key,
            action: 'snd_challenge',
            theme: cfg.theme || 'auto',
            appearance: cfg.appearance || 'always',
            callback: function (token) { verify(token); },
            'error-callback': function () { showError('verification_failed'); },
            'expired-callback': function () { showError('verification_failed'); }
        };
        try {
            window.turnstile.render('#' + WIDGET_ID, opts);
            widgetReady = true;
        } catch (e) {
            showError('widget_unavailable');
        }
    }

    function verify(token) {
        fetch(VERIFY_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ token: token })
        })
        .then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (d) {
                return { status: r.status, data: d || {} };
            });
        })
        .then(function (res) {
            if (res.status === 200 && res.data && res.data.success) {
                clearError();
                if (overlay) { overlay.remove(); overlay = null; }
                widgetReady = false;
                if (pending) {
                    var p = pending;
                    pending = null;
                    p(true);
                } else {
                    window.location.reload();
                }
                return;
            }
            showError((res.data && res.data.error) || 'verification_failed');
        })
        .catch(function () {
            showError('verify_unavailable');
        });
    }

    function showChallengeOverlay() {
        if (document.getElementById('sndChallengeOverlay')) return Promise.resolve();
        ensureLang()
        .then(function () { shell(); })
        .then(function () {
            clearError();
            return fetch(CONFIG_URL, { credentials: 'same-origin' }).then(function (r) { return r.json(); });
        })
        .then(function (cfg) {
            if (!cfg || !cfg.configured || !cfg.site_key) {
                if (overlay) {
                    var host = overlay.querySelector('#' + WIDGET_ID);
                    if (host) {
                        host.innerHTML = '<div class="empty-state" style="padding:24px;" data-i18n="challenge_not_configured"></div>';
                        var k = 'challenge_not_configured';
                        host.firstChild.textContent = t(k);
                    }
                }
                return;
            }
            loadTurnstile(function () { renderWidget(cfg); });
        })
        .catch(function () { showError('verify_unavailable'); });
        return new Promise(function (resolve) { pending = resolve; });
    }

    window.showChallengeOverlay = showChallengeOverlay;

    if (!window.__sndChallengeFetchPatched) {
        window.__sndChallengeFetchPatched = true;
        var origFetch = window.fetch.bind(window);
        window.fetch = function (input, init) {
            var retry = function (input, init) { return origFetch(input, init); };
            return origFetch(input, init).then(function (res) {
                if (!res || res.status !== 403) return res;
                if (res.headers.get('X-Challenge') !== 'required') return res;
                var isRetry = init && init.__sndChallengeRetry;
                if (isRetry) return res;
                return new Promise(function (resolve) {
                    showChallengeOverlay().then(function () {
                        var next = Object.assign({}, init || {}, { __sndChallengeRetry: true });
                        origFetch(input, next).then(resolve);
                    });
                });
            });
        };
    }

    document.addEventListener('DOMContentLoaded', function () {
        if (!document.getElementById('challengeRoot')) return;
        showChallengeOverlay();
    });
})();