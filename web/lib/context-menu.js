

function toggleContextMenu(e, id) {
    e.stopPropagation();
    if (e.cancelable) e.preventDefault();

    
    document.querySelectorAll('.context-menu').forEach(m => {
        if (m.id !== 'menu-' + id) m.classList.remove('show');
    });

    const menu = document.getElementById('menu-' + id);
    if (!menu) return;

    
    let btn = e.currentTarget || e.target;
    if (btn && btn.nodeType !== 1) btn = btn.parentElement;
    if (!btn) return;

    const rect      = btn.getBoundingClientRect();
    const menuH     = 220; 
    const isLiquid  = document.body.classList.contains('th-liquid');

    if (isLiquid) {
        
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


document.addEventListener('click', _closeAllMenus);






document.addEventListener('touchstart', e => {
    const t = e.target;
    if (t && t.closest) {
        if (t.closest('.context-menu')) return;
        if (t.closest('.menu-btn'))     return;
    }
    _closeAllMenus();
}, { passive: true });



document.body.addEventListener('touchend', e => {
    
    const btn = e.target.closest && e.target.closest('.menu-btn');
    if (btn) {
        const onclickAttr = btn.getAttribute('onclick');
        if (onclickAttr) {
            e.stopPropagation();
            e.preventDefault(); 
            const synth = {
                stopPropagation: () => {},
                preventDefault:  () => {},
                currentTarget: btn,
                target: btn,
                cancelable: false
            };
            
            (new Function('event', onclickAttr))(synth);
        }
        return;
    }

    
    
    
    
    
    const item = e.target.closest && e.target.closest('.context-menu-item');
    if (item) {
        
        _closeAllMenus();
        
        const anchor = item.querySelector('a');
        if (anchor) {
            e.preventDefault();
            anchor.click();
            return;
        }
        const onclickAttr = item.getAttribute('onclick');
        if (onclickAttr) {
            e.preventDefault();
            
            (new Function('event', onclickAttr))({ target: item, currentTarget: item, stopPropagation: ()=>{}, preventDefault: ()=>{} });
        }
        return;
    }
}, { passive: false });
