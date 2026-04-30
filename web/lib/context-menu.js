// ===== lib/context-menu.js — three-dot context menu with mobile fix =====

/**
 * Toggle the context-menu associated with a file/folder button.
 *
 * MOBILE FIX:
 *  - Uses touchend to fire on iOS/Android (onclick alone can be swallowed
 *    by scroll-detection logic in mobile browsers).
 *  - Calls e.preventDefault() on touchend so the synthesised click event
 *    is NOT fired a second time (avoids double-toggle on Android Chrome).
 *  - Position is computed from getBoundingClientRect() so the menu always
 *    appears next to the button even when the page is scrolled.
 *  - On liquid-glass theme the menu uses position:fixed to escape the
 *    backdrop-filter stacking context; on all other themes it falls back
 *    to position:absolute inside .file-actions.
 *
 * @param {Event}  e   The click or touchend event from the ⋮ button.
 * @param {string} id  The unique identifier suffix for the menu element.
 */
function toggleContextMenu(e, id) {
    e.stopPropagation();
    if (e.cancelable) e.preventDefault();   // prevent ghost-click on mobile

    // Close every other open menu first
    document.querySelectorAll('.context-menu').forEach(function (m) {
        if (m.id !== 'menu-' + id) m.classList.remove('show');
    });

    var menu = document.getElementById('menu-' + id);
    if (!menu) return;

    // Resolve the button element (handle text-node e.target on some browsers)
    var btn = e.currentTarget || e.target;
    if (btn && btn.nodeType !== 1) btn = btn.parentElement;
    if (!btn) return;

    var rect = btn.getBoundingClientRect();
    var menuH = 220;   // approximate height for flip-above logic

    var isLiquid = document.body.classList.contains('th-liquid');

    if (isLiquid) {
        // Liquid Glass: use position:fixed to escape the backdrop-filter
        // stacking context that would otherwise clip the menu.
        var top = rect.bottom + 4;
        if (rect.bottom + menuH > window.innerHeight) {
            top = rect.top - menuH - 4;
            if (top < 4) top = 4;
        }
        menu.style.position = 'fixed';
        menu.style.top      = top + 'px';
        menu.style.right    = (window.innerWidth - rect.right) + 'px';
        menu.style.left     = 'auto';
        menu.style.bottom   = 'auto';
    } else {
        // Normal mode: position:absolute inside .file-actions (CSS default).
        menu.style.position = '';
        menu.style.top      = '';
        menu.style.bottom   = '';
        menu.style.right    = '0';
        menu.style.left     = 'auto';
    }

    menu.classList.toggle('show');
}

// ── Close all open menus ──────────────────────────────────────────────────────
function _closeAllMenus() {
    document.querySelectorAll('.context-menu.show').forEach(function (m) {
        m.classList.remove('show');
    });
}

// Desktop: close on click anywhere (menu items stop propagation after running)
document.addEventListener('click', _closeAllMenus);

// Mobile: close on touchstart ONLY when the touch is outside any open menu
// and outside the three-dot button itself.
//
// BUG FIX: Previously _closeAllMenus ran on every touchstart including touches
// on context-menu items. That hid the menu (display:none) before the synthetic
// click could fire, so iOS never delivered the click to the item's onclick handler.
// Now we bail out when touching inside .context-menu or on .menu-btn.
document.addEventListener('touchstart', function (e) {
    var t = e.target;
    if (t && t.closest) {
        if (t.closest('.context-menu')) return;   // inside open menu — let click fire
        if (t.closest('.menu-btn'))     return;   // three-dot button — touchend handles it
    }
    _closeAllMenus();
}, { passive: true });

// ── Touchend delegation for menu buttons (mobile fix) ────────────────────────
//
// Buttons are injected via innerHTML after page load, so we attach on body.
// We call the onclick ourselves via new Function and prevent the ghost-click.
//
document.body.addEventListener('touchend', function (e) {
    var btn = e.target.closest && e.target.closest('.menu-btn');
    if (!btn) return;

    var onclickAttr = btn.getAttribute('onclick');
    if (onclickAttr) {
        e.stopPropagation();
        e.preventDefault();   // suppress the 300 ms synthesised click
        // Build a synthetic event-like object so toggleContextMenu can read
        // currentTarget (native TouchEvent.currentTarget is read-only).
        var synth = { stopPropagation: function(){}, preventDefault: function(){},
                      currentTarget: btn, target: btn, cancelable: false };
        // eslint-disable-next-line no-new-func
        (new Function('event', onclickAttr))(synth);
    }
}, { passive: false });
