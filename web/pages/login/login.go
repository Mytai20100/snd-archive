package login

import "net/http"

func Handler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: #fafafa;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .login-box {
            background: white;
            padding: 48px 40px;
            border: 1px solid #e0e0e0;
            width: 420px;
            max-width: 95vw;
        }
        .login-title {
            font-size: 22px;
            font-weight: 500;
            color: #1a1a1a;
            margin-bottom: 32px;
        }
        .field {
            margin-bottom: 16px;
        }
        label {
            display: block;
            font-size: 13px;
            color: #555;
            margin-bottom: 6px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 11px 12px;
            border: 1px solid #d0d0d0;
            font-size: 14px;
            background: #fff;
            color: #1a1a1a;
            outline: none;
            transition: border-color 0.15s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color: #1a1a1a;
        }
        .submit-btn {
            width: 100%;
            padding: 12px;
            background: #1a1a1a;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 14px;
            margin-top: 8px;
            letter-spacing: 0.02em;
        }
        .submit-btn:hover { background: #333; }
        .submit-btn:active { background: #000; }
        .twofa-notice {
            margin-top: 20px;
            padding: 14px;
            background: #f5f5f5;
            border-left: 3px solid #1a1a1a;
            display: none;
            font-size: 13px;
            color: #444;
            line-height: 1.5;
        }
        .error-msg {
            margin-top: 16px;
            padding: 12px;
            background: #fff3f3;
            border-left: 3px solid #d32f2f;
            font-size: 13px;
            color: #c62828;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="login-title">Login</div>
        <div class="field">
            <label for="username">Username</label>
            <input type="text" id="username" autocomplete="username" placeholder="Enter username">
        </div>
        <div class="field">
            <label for="password">Password</label>
            <input type="password" id="password" autocomplete="current-password" placeholder="Enter password">
        </div>
        <div class="field" id="twofaField" style="display: none;">
            <label for="twofa">2FA Code</label>
            <input type="text" id="twofa" placeholder="Enter 2FA code from Discord">
        </div>
        <button class="submit-btn" onclick="login()">Sign in</button>
        <div class="twofa-notice" id="twofaNotice"></div>
        <div class="error-msg" id="errorMsg"></div>
    </div>

    <script>
        document.addEventListener('keydown', function(e) {
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
                    window.location.href = '/';
                } else if (data.require_2fa) {
                    document.getElementById('twofaField').style.display = 'block';
                    const notice = document.getElementById('twofaNotice');
                    notice.style.display = 'block';
                    notice.textContent = data.message + ' Check your Discord webhook for the code.';
                    document.getElementById('twofa').focus();
                } else {
                    const err = document.getElementById('errorMsg');
                    err.style.display = 'block';
                    err.textContent = data.message || 'Login failed';
                }
            })
            .catch(() => {
                const err = document.getElementById('errorMsg');
                err.style.display = 'block';
                err.textContent = 'Connection error. Please try again.';
            });
        }
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
