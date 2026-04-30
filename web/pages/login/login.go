package login

import (
	"net/http"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>Login</title>
    <link rel="stylesheet" href="/css/main.css">
    <style>
        body {
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; padding-bottom: 0;
            background: #fafafa; transition: background 0.3s;
        }
        .login-box {
            position: relative; z-index: 10;
            background: white; padding: 48px 40px;
            border: 1px solid #e0e0e0; width: 420px; max-width: 95vw;
            border-radius: 6px;
        }
        .login-title { font-size: 22px; font-weight: 500; color: #1a1a1a; margin-bottom: 32px; }
        .field { margin-bottom: 16px; }
        label { display: block; font-size: 13px; color: #555; margin-bottom: 6px; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 11px 12px; border: 1px solid #d0d0d0;
            font-size: 14px; background: #fff; color: #1a1a1a;
            outline: none; border-radius: 4px; transition: border-color 0.15s;
        }
        input:focus { border-color: #1a1a1a; }
        .submit-btn {
            width: 100%; padding: 12px; background: #1a1a1a; color: white;
            border: none; cursor: pointer; font-size: 14px; margin-top: 8px;
            border-radius: 4px; transition: background 0.2s;
            touch-action: manipulation;
        }
        .submit-btn:hover { background: #333; }
        .twofa-notice {
            margin-top: 20px; padding: 14px; background: #f5f5f5;
            border-left: 3px solid #1a1a1a; display: none;
            font-size: 13px; color: #444; line-height: 1.5; border-radius: 0 4px 4px 0;
        }
        .error-msg {
            margin-top: 16px; padding: 12px; background: #fff3f3;
            border-left: 3px solid #d32f2f; font-size: 13px; color: #c62828;
            display: none; border-radius: 0 4px 4px 0;
        }
        /* Liquid glass overrides */
        body.th-liquid .login-box {
            background: rgba(255,255,255,0.10) !important;
            backdrop-filter: blur(32px) saturate(200%) brightness(1.08) !important;
            -webkit-backdrop-filter: blur(32px) saturate(200%) brightness(1.08) !important;
            border: 1px solid rgba(255,255,255,0.28) !important;
            border-radius: 28px !important;
            box-shadow: 0 12px 48px rgba(0,0,0,0.22), inset 0 1.5px 0 rgba(255,255,255,0.5) !important;
        }
        body.th-liquid .login-title { color: rgba(255,255,255,0.92) !important; }
        body.th-liquid label { color: rgba(255,255,255,0.7) !important; }
        body.th-liquid .twofa-notice { background: rgba(255,255,255,0.08) !important; border-color: rgba(255,255,255,0.3) !important; color: rgba(255,255,255,0.8) !important; }
        body.th-liquid .error-msg { background: rgba(200,0,0,0.14) !important; border-color: rgba(255,100,100,0.4) !important; color: #ffaaaa !important; }
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
    <div class="field" id="twofaField" style="display:none">
        <label for="twofa">2FA Code</label>
        <input type="text" id="twofa" placeholder="Enter 2FA code from Discord">
    </div>
    <button class="submit-btn" id="submitBtn" onclick="login()">Sign in</button>
    <div class="twofa-notice" id="twofaNotice"></div>
    <div class="error-msg" id="errorMsg"></div>
</div>

<script src="/lib/login.js"></script>
` + snd.ThemeSnippet("login") + `
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
