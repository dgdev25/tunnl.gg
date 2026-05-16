package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"tunnl.gg/internal/config"
	"tunnl.gg/internal/subdomain"
	"tunnl.gg/internal/tunnel"
)

var errResponseTooLarge = errors.New("response body too large")

// ServeHTTP implements http.Handler for HTTPS requests
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)

	// Enforce request body size limit
	if r.ContentLength > config.MaxRequestBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, config.MaxRequestBodySize)

	host := strings.ToLower(stripPort(r.Host))
	domain := strings.ToLower(s.domain)

	if host == domain {
		s.serveBareDomain(w, r)
		return
	}

	if !strings.HasSuffix(host, "."+domain) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sub := strings.TrimSuffix(host, "."+domain)

	if !subdomain.IsValid(sub) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tun := s.GetTunnel(sub)
	if tun == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if !tun.AllowRequest() {
		// Record violation and kill tunnel + block SSH client IP if too many violations
		if tun.RecordRateLimitHit() {
			log.Printf("Tunnel %s killed due to rate limit abuse, blocking SSH client %s", sub, tun.ClientIP)
			s.BlockIP(tun.ClientIP)
			tun.CloseSSH()
		}
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	tun.Touch()
	s.IncrementRequests()

	// Show interstitial warning for browser requests
	if isBrowserRequest(r) &&
		r.Header.Get("tunnl-skip-browser-warning") == "" &&
		!hasWarningCookie(r, sub) {
		s.redirectToWarningPage(w, r, sub)
		return
	}

	if isWebSocketRequest(r) {
		s.handleWebSocket(w, r, tun, sub)
		return
	}

	requestStart := time.Now()
	sw := &statusCaptureWriter{ResponseWriter: w}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = tun.Listener.Addr().String()
			req.Host = r.Host
		},
		Transport: tun.Transport(),
		ModifyResponse: func(resp *http.Response) error {
			// Enforce response body size limit
			if resp.ContentLength > config.MaxResponseBodySize {
				return fmt.Errorf("%w: %d bytes (max %d)", errResponseTooLarge, resp.ContentLength, config.MaxResponseBodySize)
			}
			// Wrap body with size limiter for chunked/unknown-length responses
			resp.Body = &limitedReadCloser{
				rc:    resp.Body,
				limit: config.MaxResponseBodySize,
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for %s: %v", sub, err)
			if errors.Is(err, errResponseTooLarge) {
				http.Error(w, "Response Too Large", http.StatusBadGateway)
				return
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(sw, r)

	if logger := tun.Logger(); logger != nil {
		logger.LogRequest(r.Method, r.URL.Path, sw.status, time.Since(requestStart))
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request, tun *tunnel.Tunnel, sub string) {
	backendConn, err := net.DialTimeout("tcp", tun.Listener.Addr().String(), 10*time.Second)
	if err != nil {
		log.Printf("WebSocket backend dial error for %s: %v", sub, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("WebSocket hijack not supported for %s", sub)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		// After Hijack() is called (even on failure), ResponseWriter may be invalid
		// Just log the error and return - the connection will be closed
		log.Printf("WebSocket hijack error for %s: %v", sub, err)
		return
	}
	defer clientConn.Close()

	if err := r.Write(backendConn); err != nil {
		log.Printf("WebSocket request write error for %s: %v", sub, err)
		return
	}

	logger := tun.Logger()
	wsPath := r.URL.Path
	wsStart := time.Now()
	if logger != nil {
		logger.LogWebSocketOpen(wsPath)
	}

	// Copy data bidirectionally with limits
	var backendBytes, clientBytes int64
	done := make(chan struct{})
	go func() {
		backendBytes, _ = copyWithLimits(backendConn, clientConn, config.MaxWebSocketTransfer, config.WebSocketIdleTimeout)
		// Signal backend we're done sending
		if tc, ok := backendConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer close(done)
		clientBytes, _ = copyWithLimits(clientConn, backendConn, config.MaxWebSocketTransfer, config.WebSocketIdleTimeout)
	}()
	<-done

	if logger != nil {
		logger.LogWebSocketClose(wsPath, time.Since(wsStart), backendBytes+clientBytes)
	}
}

// copyWithLimits copies from src to dst with a byte transfer limit and idle timeout.
// It resets the read deadline on src after each successful read.
// Returns the number of bytes written and any error.
func copyWithLimits(dst, src net.Conn, maxBytes int64, idleTimeout time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, readErr := src.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > maxBytes {
				return written, fmt.Errorf("transfer limit exceeded")
			}
			dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return written, writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

func isBrowserRequest(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	browserKeywords := []string{"mozilla", "chrome", "safari", "firefox", "edge", "opera"}
	for _, kw := range browserKeywords {
		if strings.Contains(ua, kw) {
			return true
		}
	}
	return false
}

func hasWarningCookie(r *http.Request, sub string) bool {
	cookie, err := r.Cookie(config.WarningCookieName + "_" + sub)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte("1")) == 1
}

func (s *Server) redirectToWarningPage(w http.ResponseWriter, r *http.Request, sub string) {
	originalURL := "https://" + r.Host + r.URL.RequestURI()
	fullSubdomain := sub + "." + s.domain
	warningURL := fmt.Sprintf("https://%s/warning?redirect=%s&subdomain=%s",
		s.domain,
		url.QueryEscape(originalURL),
		url.QueryEscape(fullSubdomain))
	http.Redirect(w, r, warningURL, http.StatusTemporaryRedirect)
}

func (s *Server) serveBareDomain(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/warning":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveWarningPage(w, r)
	case "/warning/continue":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleWarningContinue(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveWarningPage(w http.ResponseWriter, r *http.Request) {
	redirectURL, _, fullSubdomain, err := s.validWarningTarget(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	continueURL := "/warning/continue?redirect=" + url.QueryEscape(redirectURL.String()) +
		"&subdomain=" + url.QueryEscape(fullSubdomain)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Continue to %s</title>
<style>
:root { color-scheme: light; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f5f1; color: #171717; }
main { width: min(92vw, 560px); border: 1px solid #d8d5ca; background: #fffefa; padding: 32px; box-shadow: 0 24px 80px rgb(40 35 20 / 12%%); }
.eyebrow { margin: 0 0 14px; color: #8a4b19; font-size: 13px; font-weight: 700; letter-spacing: 0; text-transform: uppercase; }
h1 { margin: 0; font-size: 40px; line-height: 1; letter-spacing: 0; }
p { color: #4a4740; font-size: 16px; line-height: 1.6; }
code { font: inherit; color: #171717; overflow-wrap: anywhere; }
.actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 26px; }
a { min-height: 44px; display: inline-flex; align-items: center; justify-content: center; padding: 0 18px; border: 1px solid #171717; color: #171717; text-decoration: none; font-weight: 700; }
a.primary { background: #171717; color: #fffefa; }
@media (max-width: 520px) { main { padding: 24px; } h1 { font-size: 30px; } }
</style>
</head>
<body>
<main>
<p class="eyebrow">Public tunnel warning</p>
<h1>Check this destination before continuing.</h1>
<p>You are opening <code>%s</code>, a site published through a temporary tunnel. Only continue if you trust the person who sent this link.</p>
<div class="actions">
<a class="primary" href="%s">Continue to site</a>
<a href="https://%s/">Leave</a>
</div>
</main>
</body>
</html>`, html.EscapeString(fullSubdomain), html.EscapeString(fullSubdomain), html.EscapeString(continueURL), html.EscapeString(s.domain))

}

func (s *Server) handleWarningContinue(w http.ResponseWriter, r *http.Request) {
	redirectURL, sub, _, err := s.validWarningTarget(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     config.WarningCookieName + "_" + sub,
		Value:    "1",
		Path:     "/",
		Domain:   s.domain,
		MaxAge:   config.WarningCookieMaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (s *Server) validWarningTarget(r *http.Request) (*url.URL, string, string, error) {
	rawRedirect := r.URL.Query().Get("redirect")
	if rawRedirect == "" {
		return nil, "", "", fmt.Errorf("missing redirect")
	}

	redirectURL, err := url.Parse(rawRedirect)
	if err != nil {
		return nil, "", "", err
	}
	if redirectURL.Scheme != "https" || redirectURL.Host == "" {
		return nil, "", "", fmt.Errorf("invalid redirect URL")
	}

	domain := strings.ToLower(s.domain)
	fullSubdomain := strings.ToLower(stripPort(redirectURL.Host))
	if !strings.HasSuffix(fullSubdomain, "."+domain) {
		return nil, "", "", fmt.Errorf("redirect host outside domain")
	}

	sub := strings.TrimSuffix(fullSubdomain, "."+domain)
	if !subdomain.IsValid(sub) {
		return nil, "", "", fmt.Errorf("invalid subdomain")
	}

	if expected := r.URL.Query().Get("subdomain"); expected != "" {
		expectedHost := strings.ToLower(stripPort(expected))
		if expectedHost != fullSubdomain {
			return nil, "", "", fmt.Errorf("subdomain mismatch")
		}
	}

	return redirectURL, sub, fullSubdomain, nil
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// stripPort removes the port from a host string (e.g., "example.com:443" -> "example.com")
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if strings.Count(host, ":") == 1 {
		idx := strings.LastIndex(host, ":")
		return host[:idx]
	}
	return host
}

// limitedReadCloser wraps an io.ReadCloser and limits the number of bytes read
type limitedReadCloser struct {
	rc    io.ReadCloser
	limit int64
	read  int64
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if l.read >= l.limit {
		var probe [1]byte
		n, err := l.rc.Read(probe[:])
		if n > 0 {
			l.read += int64(n)
			return 0, fmt.Errorf("%w (exceeded %d bytes)", errResponseTooLarge, l.limit)
		}
		return 0, err
	}
	remaining := l.limit - l.read
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err = l.rc.Read(p)
	l.read += int64(n)
	return n, err
}

func (l *limitedReadCloser) Close() error {
	return l.rc.Close()
}

// statusCaptureWriter wraps http.ResponseWriter to capture the status code.
type statusCaptureWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusCaptureWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCaptureWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter for interface passthrough (e.g., http.Flusher).
func (w *statusCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// HTTPRedirectHandler returns an http.Handler that redirects HTTP to HTTPS
func (s *Server) HTTPRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(stripPort(r.Host))
		domain := strings.ToLower(s.domain)
		if !strings.HasSuffix(host, "."+domain) && host != domain {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
