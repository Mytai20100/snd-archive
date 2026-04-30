// ===== lib/login.js — login page logic =====

'use strict';

document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') login();
});

function login() {
    const payload = {
        username: document.getElementById('username').value,
        password: document.getElementById('password').value
    };
    const twofaCode = document.getElementById('twofa').value;
    if (twofaCode) payload.twofa_code = twofaCode;

    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            window.location.href = data.redirect || '/';
        } else if (data.require_2fa) {
            document.getElementById('twofaField').style.display = 'block';
            const n = document.getElementById('twofaNotice');
            n.style.display = 'block';
            n.textContent = data.message + ' Check your Discord webhook for the code.';
            document.getElementById('twofa').focus();
        } else {
            const err = document.getElementById('errorMsg');
            err.style.display = 'block';
            err.textContent = data.message || 'Login failed';
        }
    })
    .catch(function () {
        const err = document.getElementById('errorMsg');
        err.style.display = 'block';
        err.textContent = 'Connection error. Please try again.';
    });
}
