// lib/context-menu.js — three-dot context menu with mobile fix

/**
 * Toggle the context-menu associated with a file/folder button.
 *
 * Mobile notes:
 *  - Uses touchend to fire on iOS/Android (onclick can be swallowed by
 *    scroll-detection logic in mobile browsers).
 *  - Calls e.preventDefault() on touchend to prevent the synthesised click
 *    from double-toggling on Android Chrome.
 *  - Position is computed from getBoundingClientRect() so the menu stays
 *    next to the button even when the page is scrolled.
 *  - On the liquid-glass theme the menu uses position:fixed to escape the
 *    backdrop-filter stacking context; otherwise falls back to position:absolute.
 *
 * @param {Event}  e   Click or touchend event from the ⋮ button.
 * @param {string} id  Unique identifier suffix for the menu element.
 */
function toggleContextMenu(e, id) {
    e.stopPropagation();
    if (e.cancelable) e.preventDefault();

    // Close every other open menu first
    document.querySelectorAll('.context-menu').forEach(m => {
        if (m.id !== 'menu-' + id) m.classList.remove('show');
    });

    const menu = document.getElementById('menu-' + id);
    if (!menu) return;

    // Handle text-node e.target on some browsers
    let btn = e.currentTarget || e.target;
    if (btn && btn.nodeType !== 1) btn = btn.parentElement;
    if (!btn) return;

    const rect      = btn.getBoundingClientRect();
    const menuH     = 220; // approximate height used for flip-above logic
    const isLiquid  = document.body.classList.contains('th-liquid');

    if (isLiquid) {
        // Use position:fixed to escape the backdrop-filter stacking context
        let top = rect.bottom + 4;
        if (rect.bottom + menuH > window.innerHeight) {
            top = Math.max(4, rect.top - menuH - 4);
        }
        menu.style.position = 'fixed';
        menu.style.top      = top + 'px';
        menu.style.right    = (window.innerWidth - rect.right) + 'px';
        menu.style.left     = 'auto';
        menu.style.bottom   = 'auto';
    } else {
        // Normal mode: position:absolute inside .file-actions (CSS default)
        menu.style.position = '';
        menu.style.top      = '';
        menu.style.bottom   = '';
        menu.style.right    = '0';
        menu.style.left     = 'auto';
    }

    menu.classList.toggle('show');
}

function _closeAllMenus() {
    document.querySelectorAll('.context-menu.show').forEach(m => m.classList.remove('show'));
}

// Desktop: close on any click outside a menu
document.addEventListener('click', _closeAllMenus);

// Mobile: close on touchstart, but only when the touch is outside an open
// menu or the three-dot button itself.
// Previously _closeAllMenus ran on every touchstart including touches on
// context-menu items, hiding the menu before the synthetic click could fire
// on iOS. Now we bail out when touching inside .context-menu or .menu-btn.
document.addEventListener('touchstart', e => {
    const t = e.target;
    if (t && t.closest) {
        if (t.closest('.context-menu')) return;
        if (t.closest('.menu-btn'))     return;
    }
    _closeAllMenus();
}, { passive: true });

// Touchend delegation for dynamically injected menu buttons (mobile fix).
// Buttons are injected via innerHTML so we attach on body.
document.body.addEventListener('touchend', e => {
    // ── Case 1: ⋮ button tap ─────────────────────────────────────────────
    const btn = e.target.closest && e.target.closest('.menu-btn');
    if (btn) {
        const onclickAttr = btn.getAttribute('onclick');
        if (onclickAttr) {
            e.stopPropagation();
            e.preventDefault(); // suppress the 300 ms synthesised click
            const synth = {
                stopPropagation: () => {},
                preventDefault:  () => {},
                currentTarget: btn,
                target: btn,
                cancelable: false
            };
            // eslint-disable-next-line no-new-func
            (new Function('event', onclickAttr))(synth);
        }
        return;
    }

    // ── Case 2: context-menu item tap ────────────────────────────────────
    // On iOS the synthesised click fires reliably after touchend on static
    // elements, but for *dynamically-injected* elements inside an absolutely-
    // positioned container the click sometimes never arrives.  We fire the
    // onclick handler ourselves on touchend so the action always triggers.
    const item = e.target.closest && e.target.closest('.context-menu-item');
    if (item) {
        // Close menus immediately so the UI feels snappy
        _closeAllMenus();
        // If the item contains an <a> (e.g. Download), activate it
        const anchor = item.querySelector('a');
        if (anchor) {
            e.preventDefault();
            anchor.click();
            return;
        }
        const onclickAttr = item.getAttribute('onclick');
        if (onclickAttr) {
            e.preventDefault();
            // eslint-disable-next-line no-new-func
            (new Function('event', onclickAttr))({ target: item, currentTarget: item, stopPropagation: ()=>{}, preventDefault: ()=>{} });
        }
        return;
    }
}, { passive: false });
