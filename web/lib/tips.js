(function () {
    'use strict';

    var KEY_PLACEHOLDER = 'YOUR_API_KEY';

    function t(key) {
        return (window._lang && window._lang[key]) || key;
    }

    function fill(template, vars) {
        return String(template).replace(/\{(\w+)\}/g, function (m, k) {
            return Object.prototype.hasOwnProperty.call(vars, k) ? vars[k] : m;
        });
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function apiOrigin() {
        return String(window.location.origin || '') + '/up';
    }

    function snippet(id, title, command, note) {
        var noteHtml = note ? '<div style="font-size:12px;color:#888;margin-top:6px;">' + escapeHtml(note) + '</div>' : '';
        return [
            '<div style="margin-top:16px;">',
            '    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;gap:12px;">',
            '        <div style="font-size:13px;font-weight:500;color:#333;">' + escapeHtml(title) + '</div>',
            '        <button type="button" class="btn" data-tips-copy="' + id + '">' + escapeHtml(t('tips_copy')) + '</button>',
            '    </div>',
            '    <pre class="code-block" style="margin:0;background:#f5f5f5;padding:12px;border-radius:4px;overflow-x:auto;font-family:\'SF Mono\',monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;"><code id="' + id + '">' + escapeHtml(command) + '</code></pre>',
            noteHtml,
            '</div>'
        ].join('');
    }

    function renderTipsCard() {
        var host = document.getElementById('tipsCard');
        if (!host) return;
        var account = window._tipsAccount || { isAdmin: true, username: '' };
        var origin = apiOrigin();
        var key = KEY_PLACEHOLDER;
        var vars = { origin: origin, key: key, username: account.username || '' };

        var folderLine = account.isAdmin
            ? t('tips_folder_admin')
            : fill(t('tips_folder_user'), vars);
        var perUserLine = account.isAdmin ? t('tips_admin_each_user') : '';

        var cmds = [];
        cmds.push({
            title: t('tips_one_file'),
            command: 'curl -H "X-API-Token: ' + key + '" -F "file=@./photo.jpg" "' + origin + '?path=folder"'
        });
        cmds.push({
            title: t('tips_many_files'),
            command: 'curl -H "X-API-Token: ' + key + '" -F "file=@./a.jpg" -F "file=@./b.jpg" "' + origin + '?path=photos"'
        });
        cmds.push({
            title: t('tips_big_file'),
            command: 'curl -T ./big.mkv -H "X-API-Token: ' + key + '" "' + origin + '?filename=big.mkv&path=folder"',
            note: t('tips_big_file_note')
        });
        cmds.push({
            title: t('tips_chunked'),
            command: [
                'split -b 8M big.mkv part_',
                'TOTAL=$(stat -c%s big.mkv)',
                'LAST=$(ls part_* | tail -1)',
                'OFFSET=0',
                'for p in part_*; do',
                '  SIZE=$(stat -c%s "$p")',
                '  FINAL=0; [ "$p" = "$LAST" ] && FINAL=1',
                '  curl -H "X-API-Token: ' + key + '" --data-binary "@$p" \\',
                '    "' + origin + '?path=folder&filename=big.mkv&offset=$OFFSET&total=$TOTAL&final=$FINAL&action=overwrite"',
                '  OFFSET=$((OFFSET + SIZE))',
                'done'
            ].join('\n'),
            note: t('tips_chunked_note')
        });
        cmds.push({
            title: t('tips_actions'),
            command: [
                '# action=rename keeps both files, action=overwrite replaces',
                'curl -H "X-API-Token: ' + key + '" -F "file=@./photo.jpg" \\',
                '  "' + origin + '?path=folder&action=rename"',
                '',
                '# the JSON response reports the owning account and the stored path',
                'curl -s -H "X-API-Token: ' + key + '" -F "file=@./photo.jpg" "' + origin + '?path=folder"'
            ].join('\n'),
            note: t('tips_actions_note')
        });

        var body = [
            '<div class="card" style="background:white;padding:24px;border:1px solid #e0e0e0;border-radius:4px;margin-top:16px;">',
            '    <h2 style="font-size:18px;font-weight:500;margin:0 0 12px;">' + escapeHtml(t('tips_title')) + '</h2>',
            '    <div style="font-size:13px;color:#555;line-height:1.7;">',
            '        <div>' + escapeHtml(folderLine) + '</div>',
            perUserLine ? '<div style="margin-top:6px;">' + escapeHtml(perUserLine) + '</div>' : '',
            '        <div style="margin-top:6px;">' + escapeHtml(t('tips_key_in_header')) + '</div>',
            '        <div>' + escapeHtml(t('tips_path_relative')) + '</div>',
            '        <div>' + escapeHtml(t('tips_rotate')) + '</div>',
            '        <div style="margin-top:6px;color:#888;">' + escapeHtml(t('tips_route_public')) + '</div>',
            '    </div>',
            cmds.map(function(c, i) {
                return snippet('tipsCmd' + (i + 1), c.title, c.command, c.note);
            }).join(''),
            '</div>'
        ].join('');

        host.innerHTML = body;
        host.querySelectorAll('[data-tips-copy]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var code = document.getElementById(btn.getAttribute('data-tips-copy'));
                if (!code) return;
                var text = code.textContent;
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(function () {
                        flashCopy(btn, true);
                    }).catch(function () {
                        flashCopy(btn, false);
                    });
                    return;
                }
                var ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); flashCopy(btn, true); }
                catch (e) { flashCopy(btn, false); }
                document.body.removeChild(ta);
            });
        });
    }

    function flashCopy(btn, ok) {
        var original = btn.textContent;
        btn.textContent = ok ? t('tips_copied') : t('tips_copy_failed');
        setTimeout(function () { btn.textContent = original; }, 1600);
    }

    window.renderTipsCard = renderTipsCard;

    document.addEventListener('DOMContentLoaded', function () {
        if (!document.getElementById('tipsCard')) return;
        if (window._lang) { renderTipsCard(); return; }
        if (typeof window._sndLoadLang === 'function') {
            window._sndLoadLang().then(renderTipsCard);
            return;
        }
        fetch('/api/lang')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && typeof data === 'object') window._lang = data;
                renderTipsCard();
            })
            .catch(renderTipsCard);
    });
})();