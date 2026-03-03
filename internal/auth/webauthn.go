package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ownerUser implements webauthn.User for the single owner account.
type ownerUser struct {
	credentials []webauthn.Credential
}

func (u *ownerUser) WebAuthnID() []byte                         { return []byte("owner") }
func (u *ownerUser) WebAuthnName() string                       { return "owner" }
func (u *ownerUser) WebAuthnDisplayName() string                { return "Owner" }
func (u *ownerUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// Handler manages WebAuthn enrollment and login ceremonies.
type Handler struct {
	wa      *webauthn.WebAuthn
	store   Store
	session *SessionManager
	hash    string // hex-encoded SHA-256 hash of the enrollment seed

	// In-flight ceremony state. Since this is single-user, we only need
	// one session at a time for each ceremony type.
	mu            sync.Mutex
	enrollSession *webauthn.SessionData
	loginSession  *webauthn.SessionData
}

// NewHandler creates a new WebAuthn handler.
// rpID is the relying party ID (hostname). rpOrigins is the set of allowed
// origins (e.g., "https://example.com"). hash is the hex-encoded SHA-256
// hash of the enrollment seed.
func NewHandler(rpID string, rpOrigins []string, hash string, store Store, session *SessionManager) (*Handler, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Irongate",
		RPID:          rpID,
		RPOrigins:     rpOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}

	return &Handler{
		wa:      wa,
		store:   store,
		session: session,
		hash:    hash,
	}, nil
}

// owner returns the current owner user with all stored credentials.
func (h *Handler) owner() *ownerUser {
	creds := h.store.GetCredentials()
	waCreds := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		waCreds[i] = c.Credential
	}
	return &ownerUser{credentials: waCreds}
}

// BeginEnroll starts a WebAuthn registration ceremony.
// POST prefix/enroll/begin
func (h *Handler) BeginEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := h.owner()
	options, sessionData, err := h.wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		log.Printf("irongate: begin enrollment error: %v", err)
		http.Error(w, "failed to begin enrollment", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	h.enrollSession = sessionData
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// FinishEnroll completes a WebAuthn registration ceremony.
// POST prefix/enroll/finish
//
// The request body is a JSON object containing the seed and the WebAuthn
// attestation response. We parse the seed/name from a wrapper, then pass
// the raw body to the WebAuthn library for attestation verification.
func (h *Handler) FinishEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse our wrapper to get the seed and name.
	var req struct {
		Seed       string          `json:"seed"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Authorization check: either the seed is correct, or the user has a valid session.
	hasSession := h.session.Validate(r)
	seedValid := false
	if req.Seed != "" {
		computed := sha256.Sum256([]byte(req.Seed))
		seedValid = hex.EncodeToString(computed[:]) == h.hash
	}

	if !seedValid && !hasSession {
		http.Error(w, "unauthorized: invalid seed and no active session", http.StatusForbidden)
		return
	}

	// If no credentials exist yet, the seed is required (can't use session for first enrollment).
	if !h.store.HasAnyCredential() && !seedValid {
		http.Error(w, "unauthorized: seed required for initial enrollment", http.StatusForbidden)
		return
	}

	h.mu.Lock()
	sessionData := h.enrollSession
	h.enrollSession = nil
	h.mu.Unlock()

	if sessionData == nil {
		http.Error(w, "no enrollment in progress", http.StatusBadRequest)
		return
	}

	// Parse the WebAuthn credential response.
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		bytes.NewReader(req.Credential),
	)
	if err != nil {
		log.Printf("irongate: parse attestation error: %v", err)
		http.Error(w, "invalid attestation response", http.StatusBadRequest)
		return
	}

	user := h.owner()
	credential, err := h.wa.CreateCredential(user, *sessionData, parsedResponse)
	if err != nil {
		log.Printf("irongate: create credential error: %v", err)
		http.Error(w, "failed to create credential", http.StatusInternalServerError)
		return
	}

	name := req.Name
	if name == "" {
		name = fmt.Sprintf("Passkey %d", len(h.store.GetCredentials())+1)
	}

	if err := h.store.SaveCredential(StoredCredential{
		Name:       name,
		CreatedAt:  time.Now(),
		Credential: *credential,
	}); err != nil {
		log.Printf("irongate: save credential error: %v", err)
		http.Error(w, "failed to save credential", http.StatusInternalServerError)
		return
	}

	// Auto-login: issue a session cookie.
	h.session.Issue(w, r)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// BeginLogin starts a WebAuthn authentication ceremony.
// POST prefix/login/begin
func (h *Handler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.store.HasAnyCredential() {
		http.Error(w, "no credentials enrolled", http.StatusPreconditionFailed)
		return
	}

	user := h.owner()
	options, sessionData, err := h.wa.BeginLogin(user)
	if err != nil {
		log.Printf("irongate: begin login error: %v", err)
		http.Error(w, "failed to begin login", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	h.loginSession = sessionData
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// FinishLogin completes a WebAuthn authentication ceremony.
// POST prefix/login/finish
func (h *Handler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.Lock()
	sessionData := h.loginSession
	h.loginSession = nil
	h.mu.Unlock()

	if sessionData == nil {
		http.Error(w, "no login in progress", http.StatusBadRequest)
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		log.Printf("irongate: parse assertion error: %v", err)
		http.Error(w, "invalid assertion response", http.StatusBadRequest)
		return
	}

	user := h.owner()
	_, err = h.wa.ValidateLogin(user, *sessionData, parsedResponse)
	if err != nil {
		log.Printf("irongate: validate login error: %v", err)
		http.Error(w, "authentication failed", http.StatusForbidden)
		return
	}

	h.session.Issue(w, r)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Logout clears the session cookie.
// POST prefix/logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.session.Clear(w, r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ListCredentials returns the list of enrolled credentials (for the manage page).
// GET prefix/manage/credentials
func (h *Handler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	creds := h.store.GetCredentials()
	type credInfo struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
	}
	var out []credInfo
	for _, c := range creds {
		out = append(out, credInfo{
			ID:        credIDString(c.Credential.ID),
			Name:      c.Name,
			CreatedAt: c.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// DeleteCredential removes a credential by ID.
// DELETE prefix/manage/credentials?id=...
func (h *Handler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id parameter", http.StatusBadRequest)
		return
	}

	// Don't allow deleting the last credential.
	creds := h.store.GetCredentials()
	if len(creds) <= 1 {
		http.Error(w, "cannot delete the last credential", http.StatusBadRequest)
		return
	}

	if err := h.store.DeleteCredential(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HasAnyCredential returns whether any credentials have been enrolled.
func (h *Handler) HasAnyCredential() bool {
	return h.store.HasAnyCredential()
}

// IsAuthenticated returns whether the request has a valid session.
func (h *Handler) IsAuthenticated(r *http.Request) bool {
	return h.session.Validate(r)
}
