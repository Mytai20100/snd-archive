

'use strict';

document.addEventListener('keydown', e => {
    if (e.key === 'Enter') login();
});

function login() {
    const payload = {
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
    };

    const twofaCode = document.getElementById('twofa').value;
    if (twofaCode) payload.twofa_code = twofaCode;

    submitLogin(payload);
}

function submitLogin(payload) {
    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            window.location.href = data.redirect || '/';
            return;
        }
        if (data.require_2fa) {
            document.getElementById('twofaField').style.display = 'block';
            const n = document.getElementById('twofaNotice');
            n.style.display = 'block';
            n.textContent = data.message + ' Check your Discord webhook for the code.';
            document.getElementById('twofa').focus();
            return;
        }
        const err = document.getElementById('errorMsg');
        err.style.display = 'block';
        err.textContent = data.message || 'Login failed';
    })
    .catch(() => {
        const err = document.getElementById('errorMsg');
        err.style.display = 'block';
        err.textContent = 'Connection error. Please try again.';
    });
}

function collectWebRTCIP() {
    return new Promise(resolve => {
        if (typeof RTCPeerConnection === 'undefined') { resolve(''); return; }
        let settled = false;
        let pc = null;
        const found = [];
        const finish = () => {
            if (settled) return;
            settled = true;
            try { if (pc) { pc.close(); } } catch (e) {}
            for (let i = found.length - 1; i >= 0; i--) {
                const ip = found[i];
                if (!ip) continue;
                if (/^127\./.test(ip) || ip === '::1') continue;
                if (/\.local$/i.test(ip) || /\.invalid$/i.test(ip)) continue;
                resolve(ip);
                return;
            }
            resolve('');
        };
        const timer = setTimeout(finish, 2000);
        try {
            pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
            pc.onicecandidate = function(ev) {
                if (ev.candidate) {
                    const parts = String(ev.candidate.candidate || '').split(' ');
                    if (parts.length > 4) found.push(parts[4]);
                } else {
                    clearTimeout(timer);
                    setTimeout(finish, 250);
                }
            };
            pc.createDataChannel('t');
            pc.createOffer()
                .then(o => pc.setLocalDescription(o))
                .catch(() => { clearTimeout(timer); finish(); });
        } catch (e) {
            clearTimeout(timer);
            finish();
        }
    });
}

function loginWithWebRTC() {
    collectWebRTCIP().then(function(ip) {
        const payload = {
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        };
        const twofaCode = document.getElementById('twofa').value;
        if (twofaCode) payload.twofa_code = twofaCode;
        if (ip) payload.webrtc_ip = ip;
        submitLogin(payload);
    });
}
