// Package auth handles WebAuthn authentication, session management,
// and credential storage for irongate.
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// StoredCredential wraps a WebAuthn credential with metadata.
type StoredCredential struct {
	// Name is a user-assigned friendly name (e.g., "MacBook Pro", "iPhone").
	Name string `json:"name"`
	// CreatedAt is when this credential was enrolled.
	CreatedAt time.Time `json:"created_at"`
	// Credential is the WebAuthn credential data.
	Credential webauthn.Credential `json:"credential"`
}

// Store defines the interface for credential persistence.
type Store interface {
	// SaveCredential adds a new credential to the store.
	SaveCredential(cred StoredCredential) error
	// GetCredentials returns all stored credentials.
	GetCredentials() []StoredCredential
	// DeleteCredential removes a credential by its ID (base64url-encoded).
	DeleteCredential(id string) error
	// HasAnyCredential returns true if at least one credential exists.
	HasAnyCredential() bool
}

// MemoryStore keeps credentials in memory. They are lost on restart.
type MemoryStore struct {
	mu    sync.RWMutex
	creds []StoredCredential
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) SaveCredential(cred StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds = append(s.creds, cred)
	return nil
}

func (s *MemoryStore) GetCredentials() []StoredCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]StoredCredential, len(s.creds))
	copy(out, s.creds)
	return out
}

func (s *MemoryStore) DeleteCredential(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.creds {
		if credIDString(c.Credential.ID) == id {
			s.creds = append(s.creds[:i], s.creds[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("credential not found: %s", id)
}

func (s *MemoryStore) HasAnyCredential() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.creds) > 0
}

// FileStore persists credentials to a JSON file on disk.
type FileStore struct {
	mu   sync.RWMutex
	path string
	data fileData
}

type fileData struct {
	Credentials []StoredCredential `json:"credentials"`
}

func NewFileStore(path string) (*FileStore, error) {
	s := &FileStore{path: path}

	// Try to load existing data.
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("parsing credentials file %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading credentials file %s: %w", path, err)
	}

	return s, nil
}

func (s *FileStore) SaveCredential(cred StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Credentials = append(s.data.Credentials, cred)
	return s.flush()
}

func (s *FileStore) GetCredentials() []StoredCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]StoredCredential, len(s.data.Credentials))
	copy(out, s.data.Credentials)
	return out
}

func (s *FileStore) DeleteCredential(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.data.Credentials {
		if credIDString(c.Credential.ID) == id {
			s.data.Credentials = append(s.data.Credentials[:i], s.data.Credentials[i+1:]...)
			return s.flush()
		}
	}
	return fmt.Errorf("credential not found: %s", id)
}

func (s *FileStore) HasAnyCredential() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Credentials) > 0
}

func (s *FileStore) flush() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0600)
}

// credIDString returns a hex-encoded string of a credential ID for comparison.
func credIDString(id []byte) string {
	return fmt.Sprintf("%x", id)
}
