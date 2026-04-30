package share

import (
	"net/http"

	"snd-archive/snd"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	// Prefer SiteSettings embed values (set via admin panel), fallback to config.yml
	snd.SiteSettingsMu.RLock()
	ssEmbedTitle := snd.SiteSettingsData.EmbedTitle
	ssEmbedDesc  := snd.SiteSettingsData.EmbedDescription
	ssEmbedImg   := snd.SiteSettingsData.EmbedImageURL
	snd.SiteSettingsMu.RUnlock()

	embedTitle := ssEmbedTitle
	if embedTitle == "" { embedTitle = snd.Cfg.EmbedTitle }
	if embedTitle == "" { embedTitle = "Public Files — " + snd.Cfg.SiteName }

	embedDesc := ssEmbedDesc
	if embedDesc == "" { embedDesc = snd.Cfg.EmbedDescription }
	if embedDesc == "" { embedDesc = "File sharing powered by " + snd.Cfg.SiteName }

	embedImage := ssEmbedImg
	if embedImage == "" { embedImage = snd.Cfg.EmbedImageURL }
	if embedImage == "" { embedImage = snd.Cfg.IconURL }

	// Build origin for absolute URLs (Discord and other crawlers require absolute image URLs)
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	origin := scheme + "://" + r.Host
	pageURL := origin + "/share"

	// Ensure og:image is absolute — relative paths like /favicon.ico won't load on Discord
	if embedImage != "" && len(embedImage) > 0 && embedImage[0] == '/' {
		embedImage = origin + embedImage
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <title>Public Files - ` + snd.Cfg.SiteName + `</title>
    <meta property="og:title"       content="` + embedTitle + `">
    <meta property="og:description" content="` + embedDesc + `">
    <meta property="og:image"       content="` + embedImage + `">
    <meta property="og:image:secure_url" content="` + embedImage + `">
    <meta property="og:url"         content="` + pageURL + `">
    <meta property="og:type"        content="website">
    <meta property="og:site_name"   content="` + snd.Cfg.SiteName + `">
    <meta name="twitter:card"        content="summary_large_image">
    <meta name="twitter:title"       content="` + embedTitle + `">
    <meta name="twitter:description" content="` + embedDesc + `">
    <meta name="twitter:image"       content="` + embedImage + `">
    ` + snd.EmbedLoaderSnippet() + `
    <link rel="stylesheet" href="/css/main.css">
    <style>
        /* share-page specific */
        .header-sub   { font-size: 13px; color: #888; margin-top: 2px; }
        .search-bar   { padding: 16px 20px; border-bottom: 1px solid #e0e0e0; background: #fafafa; }
        .search-bar input {
            width: 100%; padding: 10px 14px; border: 1px solid #d0d0d0;
            font-size: 14px; outline: none; border-radius: 4px;
        }
        .search-bar input:focus { border-color: #1a1a1a; }
        .file-item    { grid-template-columns: auto 1fr auto; align-items: center; padding: 16px 12px; }
        .file-url     { font-size: 11px; color: #0066cc; margin-top: 4px; font-family: monospace; word-break: break-all; cursor: pointer; }
        .file-url:hover { text-decoration: underline; }
        .file-uploader { margin-top: 2px; }
        .file-owner-tag {
            display: inline-block; font-size: 11px; font-weight: 600;
            padding: 1px 7px; border-radius: 999px;
            background: #e8f5e9; color: #2e7d32; letter-spacing: 0.01em;
        }
        .file-owner-tag.file-owner-admin {
            background: #e8eaf6; color: #3949ab;
        }
        .action-btn   {
            padding: 7px 12px; background: white; border: 1px solid #d0d0d0;
            border-radius: 4px; cursor: pointer; font-size: 12px; color: #1a1a1a;
            text-decoration: none; white-space: nowrap;
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
        }
        .action-btn:hover { background: #fafafa; border-color: #1a1a1a; }
        .stats-bar    {
            padding: 12px 20px; background: #f5f5f5; border-bottom: 1px solid #e0e0e0;
            font-size: 13px; color: #666; display: flex; gap: 24px; flex-wrap: wrap;
        }
        .stats-bar strong { color: #1a1a1a; }
        .empty-state .title    { font-size: 18px; margin-bottom: 8px; color: #555; }
        .empty-state .subtitle { font-size: 14px; }

        /* Liquid Glass */
        body.th-liquid .file-item, body.th-liquid .container, body.th-liquid .header, body.th-liquid .modal-content {
            background: rgba(255,255,255,0.08) !important;
            backdrop-filter: blur(24px) saturate(180%) !important;
            -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
            border-color: rgba(255,255,255,0.18) !important;
            box-shadow: 0 8px 32px rgba(0,0,0,0.18), inset 0 1px 0 rgba(255,255,255,0.3) !important;
        }
        body.th-liquid .file-item  { border-radius: 12px !important; margin-bottom: 4px !important; }
        body.th-liquid .file-name  { color: rgba(255,255,255,0.88) !important; }
        body.th-liquid .file-meta, body.th-liquid .stats-bar { color: rgba(255,255,255,0.55) !important; }
        body.th-liquid .file-url   { color: rgba(150,200,255,0.75) !important; }
        body.th-liquid .file-owner-tag { background: rgba(255,255,255,0.12) !important; color: rgba(200,255,200,0.85) !important; }
        body.th-liquid .file-owner-tag.file-owner-admin { background: rgba(255,255,255,0.12) !important; color: rgba(180,190,255,0.85) !important; }
        body.th-liquid h1, body.th-liquid h2, body.th-liquid h3 { color: rgba(255,255,255,0.92) !important; }
        body.th-liquid .action-btn { background: rgba(255,255,255,0.12) !important; border-color: rgba(255,255,255,0.2) !important; color: rgba(255,255,255,0.85) !important; }
        body.th-liquid:not(.th-rainbow):not(.th-dark) { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%) !important; }
        body.th-dark .file-item { background: #181818 !important; border-color: #2a2a2a !important; }
        body.th-dark .header    { background: #111 !important; border-color: #2a2a2a !important; }

        @media (max-width: 768px) {
            .file-item { grid-template-columns: auto 1fr; }
            .file-actions { grid-column: 2; justify-content: flex-start; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>` + snd.Cfg.SiteName + `</h1>
                <div class="header-sub">Public Files</div>
            </div>
            <div class="header-actions">
                <a href="/ac" class="btn">Login</a>
            </div>
        </div>

        <div class="search-bar">
            <input type="text" id="searchInput" placeholder="Search public files..." autocomplete="off" oninput="filterFiles()">
        </div>

        <div class="stats-bar" id="statsBar">
            <span>Loading...</span>
        </div>

        <div class="files-section" id="filesSection">
            <div class="empty-state"><div class="title">Loading...</div></div>
        </div>
    </div>

    <!-- View Modal -->
    <div class="modal" id="viewModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="viewTitle">View File</h3>
                <button class="close-btn" onclick="closeModal('viewModal')">&times;</button>
            </div>
            <div class="modal-body" id="viewBody"></div>
        </div>
    </div>

    <div class="footer" id="siteFooter">
        <strong>` + snd.Cfg.SiteName + `</strong> — public files — v` + snd.VERSION + `
    </div>

    <script src="/lib/utils.js"></script>
    <script src="/lib/share.js"></script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
