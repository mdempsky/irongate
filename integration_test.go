package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdempsky/irongate/internal/auth"
	"github.com/mdempsky/irongate/internal/proxy"
	"github.com/playwright-community/playwright-go"
)

// TestEnrollmentFlow performs an end-to-end test of the enrollment flow, including:
// - Starting a mock backend server
// - Starting the irongate server with the auth handler and proxy
// - Using Playwright to navigate to the enrollment page and complete the flow
// - Verifying that the backend received the expected requests
func TestEnrollmentFlow(t *testing.T) {
	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("run playwright: %v", err)
	}
	defer pw.Stop()

	browser, err := pw.Chromium.Launch()
	if err != nil {
		t.Fatalf("launch browser: %v", err)
	}
	defer browser.Close()

	context, err := browser.NewContext()
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	defer context.Close()

	page, err := context.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}
	defer page.Close()

	seed := "test-seed-12345"
	hash := sha256.Sum256([]byte(seed))
	hashHex := hex.EncodeToString(hash[:])

	var backendRequests atomic.Int32

	mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequests.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from backend"))
	}))
	defer mockBackend.Close()

	store := auth.NewMemoryStore()
	sessionMgr := auth.NewSessionManager(nil, 24*time.Hour)

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	authHandler, err := auth.NewHandler(
		"localhost",
		[]string{fmt.Sprintf("http://localhost:%s", port)},
		hashHex,
		store,
		sessionMgr,
	)
	if err != nil {
		t.Fatalf("new auth handler: %v", err)
	}

	rp, err := proxy.New(mockBackend.Listener.Addr().String(), "", "")
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	mux := buildMux("/_irongate/", authHandler, rp, sessionMgr)

	server := &http.Server{
		Addr:    ln.Addr().String(),
		Handler: mux,
	}
	go server.Serve(ln)
	defer server.Close()

	serverURL := "http://localhost:" + port

	if _, err := page.Goto(serverURL+"/", playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	}); err != nil {
		t.Fatalf("goto: %v", err)
	}

	if backendRequests.Load() != 0 {
		t.Fatal("backend should not have received any requests yet")
	}

	if _, err := page.Goto(serverURL+"/_irongate/enroll#"+seed, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	}); err != nil {
		t.Fatalf("goto enroll: %v", err)
	}

	cdp, err := context.NewCDPSession(page)
	if err != nil {
		t.Fatalf("new CDP session: %v", err)
	}
	defer cdp.Detach()

	_, err = cdp.Send("WebAuthn.enable", nil)
	if err != nil {
		t.Fatalf("WebAuthn.enable: %v", err)
	}

	_, err = cdp.Send("WebAuthn.addVirtualAuthenticator", map[string]any{
		"options": map[string]any{
			"protocol":                    "ctap2",
			"transport":                   "usb",
			"hasResidentKey":              true,
			"hasUserVerification":         true,
			"isUserVerified":              true,
			"automaticPresenceSimulation": true,
		},
	})
	if err != nil {
		t.Fatalf("addVirtualAuthenticator: %v", err)
	}

	if err := page.GetByLabel("Passkey name").Fill("Test Passkey"); err != nil {
		t.Fatalf("fill name: %v", err)
	}

	if err := page.GetByText("Register Passkey").Click(); err != nil {
		t.Fatalf("click enroll: %v", err)
	}

	page.WaitForURL(serverURL + "/")

	if backendRequests.Load() < 1 {
		t.Errorf("expected at least 1 backend request, got %d", backendRequests.Load())
	}
}
