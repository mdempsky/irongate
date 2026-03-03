package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"
)

const (
	// SessionCookieName is the name of the authentication cookie.
	SessionCookieName = "_irongate_session"
	// sessionDataLen is: 8 bytes (issued-at unix timestamp) + 32 bytes (HMAC-SHA256).
	sessionDataLen = 8 + 32
)

// SessionManager handles creating and validating signed session cookies.
type SessionManager struct {
	key []byte
	ttl time.Duration
}

// NewSessionManager creates a new session manager. If key is nil, a random
// 32-byte key is generated (sessions won't survive restarts).
func NewSessionManager(key []byte, ttl time.Duration) *SessionManager {
	if key == nil {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic(fmt.Sprintf("irongate: failed to generate session key: %v", err))
		}
	}
	return &SessionManager{key: key, ttl: ttl}
}

// Issue writes a session cookie to the response.
func (sm *SessionManager) Issue(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(now.Unix()))

	mac := hmac.New(sha256.New, sm.key)
	mac.Write(data)
	data = mac.Sum(data)

	encoded := base64.RawURLEncoding.EncodeToString(data)

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sm.ttl.Seconds()),
	})
}

// Validate checks whether the request has a valid session cookie.
func (sm *SessionManager) Validate(r *http.Request) bool {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return false
	}

	data, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(data) != sessionDataLen {
		return false
	}

	payload := data[:8]
	sig := data[8:]

	// Verify HMAC.
	mac := hmac.New(sha256.New, sm.key)
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return false
	}

	// Check expiration.
	issuedAt := time.Unix(int64(binary.BigEndian.Uint64(payload)), 0)
	if time.Since(issuedAt) > sm.ttl {
		return false
	}

	return true
}

// Clear removes the session cookie.
func (sm *SessionManager) Clear(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// isSecure determines whether to set the Secure flag on cookies.
func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Trust upstream proxy headers.
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	return false
}
