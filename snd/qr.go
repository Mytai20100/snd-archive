package snd

// QR Code handler using github.com/skip2/go-qrcode — standards-compliant QR generation.
// Exposes HandleQR as an HTTP handler: GET /api/qr?url=...&size=256

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net/http"
	"strconv"

	qrcode "github.com/skip2/go-qrcode"
)

// HandleQR serves GET /api/qr?url=...&size=256
// Returns a PNG QR code for the given URL.
// No auth required — the URL already encodes whatever tokens are needed.
func HandleQR(w http.ResponseWriter, r *http.Request) {
	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}
	if len(rawURL) > 2048 {
		http.Error(w, "url too long", http.StatusBadRequest)
		return
	}

	size := 256
	if s := r.URL.Query().Get("size"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 64 && n <= 1024 {
			size = n
		}
	}

	// Generate QR using skip2/go-qrcode (Medium error correction)
	qr, err := qrcode.New(rawURL, qrcode.Medium)
	if err != nil {
		http.Error(w, "QR generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	qr.DisableBorder = false

	// Get QR image at requested size
	img := qr.Image(size)

	// If a logo URL is configured, overlay it in the center
	SiteSettingsMu.RLock()
	// (logo overlay via URL is done client-side in qr.js — server just returns the QR PNG)
	SiteSettingsMu.RUnlock()

	// Ensure we always return a white-background image
	out := image.NewRGBA(img.Bounds())
	draw.Draw(out, out.Bounds(), &image.Uniform{color.White}, image.Point{}, draw.Src)
	draw.Draw(out, img.Bounds(), img, image.Point{}, draw.Over)

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	png.Encode(w, out)
}
