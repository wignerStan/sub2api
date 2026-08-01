//go:build embed || unit

package web

import (
	"net/http"
	"path"
	"strings"
)

// Vite emits content-hashed filenames under assets/, so the backend can apply
// immutable caching without relying on a reverse proxy to classify paths.
const staticAssetsCacheControl = "public, max-age=31536000, immutable"

// isFingerprintedEmbeddedAssetPath reports whether a cleaned URL path refers to
// a Vite asset whose filename contains the default eight-character build hash.
func isFingerprintedEmbeddedAssetPath(cleanPath string) bool {
	cleanPath = strings.TrimPrefix(cleanPath, "/")
	if !strings.HasPrefix(cleanPath, "assets/") {
		return false
	}

	filename := path.Base(cleanPath)
	extension := path.Ext(filename)
	stem := strings.TrimSuffix(filename, extension)
	const fingerprintLength = 8
	delimiterIndex := len(stem) - fingerprintLength - 1
	if extension == "" || delimiterIndex < 1 || stem[delimiterIndex] != '-' {
		return false
	}

	// Vite hashes use URL-safe characters and are stable for immutable caching.
	fingerprint := stem[delimiterIndex+1:]
	for _, char := range fingerprint {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

// looksLikeStaticAssetRequest reports whether cleanPath resembles a static
// file (e.g. assets/index-AbCd1234.js, logo.svg, favicon.ico, manifest.json)
// rather than a client-side SPA route. Heuristic: the final path segment
// carries a dot-delimited extension; SPA route segments (/dashboard,
// /users/123, /settings/profile) have none.
//
// This drives the not-found behaviour: a missing static asset must return 404
// and must NOT fall back to the index.html shell. Serving text/html for a
// missing .js — together with X-Content-Type-Options: nosniff — makes the
// browser refuse to execute the module and renders a blank page, which is the
// exact failure seen when a stale client holds asset hashes from a previous
// deploy. A 404 lets the client revalidate index.html and pick up the current
// hashes. index.html itself is excluded so the shell path keeps ownership.
func looksLikeStaticAssetRequest(cleanPath string) bool {
	cleanPath = strings.TrimPrefix(cleanPath, "/")
	if cleanPath == "" || cleanPath == "index.html" {
		return false
	}
	return path.Ext(path.Base(cleanPath)) != ""
}

// applyStaticAssetCacheHeaders sets Cache-Control for long-cacheable static paths.
// index.html / SPA routes must keep no-cache and are not handled here.
func applyStaticAssetCacheHeaders(header http.Header, cleanPath string) {
	if header == nil || !isFingerprintedEmbeddedAssetPath(cleanPath) {
		return
	}
	header.Set("Cache-Control", staticAssetsCacheControl)
}
