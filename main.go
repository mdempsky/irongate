// Irongate is a passkey-authenticated reverse proxy for single-user web applications.
//
// Usage:
//
//	irongate [flags] command [args...]
//
// Irongate spawns the given command as a child process, waits for it to start
// listening on the backend port, and then reverse-proxies authenticated traffic
// to it. All access requires WebAuthn passkey authentication.
//
// Environment:
//
//	HASH    Hex-encoded SHA-256 hash of the enrollment seed (required for first enrollment)
package main

import (
	"context"
	cryptotls "crypto/tls"
	"embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mdempsky/irongate/internal/auth"
	"github.com/mdempsky/irongate/internal/process"
	"github.com/mdempsky/irongate/internal/proxy"
	igtls "github.com/mdempsky/irongate/internal/tls"
)

//go:embed web/*.html
var webFS embed.FS

func main() {
	var origins multiFlag

	var (
		listen      = flag.String("listen", ":443", "Address to listen on")
		backend     = flag.String("backend", "127.0.0.1:8080", "Backend address to proxy to")
		tlsMode     = flag.String("tls", "off", "TLS mode: off, self-signed")
		credentials = flag.String("credentials", "", "Path to credentials JSON file (empty = in-memory)")
		sessionTTL  = flag.Duration("session-ttl", 24*time.Hour, "Session cookie lifetime")
		rpID        = flag.String("rpid", "", "WebAuthn Relying Party ID (defaults to hostname from request)")
		prefix      = flag.String("prefix", "/_irongate/", "URL prefix for auth endpoints")
	)
	flag.Var(&origins, "origin", "Allowed WebAuthn origin (repeatable, e.g. https://example.com:8443)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "irongate: no command specified\n")
		fmt.Fprintf(os.Stderr, "Usage: irongate [flags] command [args...]\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Normalize prefix: ensure it starts and ends with /.
	pfx := *prefix
	if !strings.HasPrefix(pfx, "/") {
		pfx = "/" + pfx
	}
	if !strings.HasSuffix(pfx, "/") {
		pfx = pfx + "/"
	}

	// Get the enrollment hash from environment.
	hash := os.Getenv("HASH")
	if hash == "" {
		log.Printf("irongate: WARNING: HASH environment variable not set; initial enrollment will be impossible")
	}

	// Set up credential store.
	var store auth.Store
	if *credentials != "" {
		var err error
		store, err = auth.NewFileStore(*credentials)
		if err != nil {
			log.Fatalf("irongate: %v", err)
		}
		log.Printf("irongate: using file credential store: %s", *credentials)
	} else {
		store = auth.NewMemoryStore()
		log.Printf("irongate: using in-memory credential store (credentials lost on restart)")
	}

	// Set up session manager.
	sessionMgr := auth.NewSessionManager(nil, *sessionTTL)

	// Determine RPID. If not set, we'll use the hostname from the first request.
	// For now, require it to be set or default to the listen address hostname.
	effectiveRPID := *rpID
	if effectiveRPID == "" {
		host, _, err := net.SplitHostPort(*listen)
		if err != nil {
			host = *listen
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			effectiveRPID = "localhost"
			log.Printf("irongate: WARNING: --rpid not set and listen address is wildcard; defaulting to 'localhost'. Set --rpid for production use.")
		} else {
			effectiveRPID = host
		}
	}

	// Determine origins. If --origin flags were provided, use those directly.
	// Otherwise, auto-derive from the RPID and listen address.
	if len(origins) == 0 {
		origins = append(origins, "https://"+effectiveRPID)
		// Also allow with port if the listen port is not standard.
		_, port, _ := net.SplitHostPort(*listen)
		if port != "" && port != "443" && port != "80" {
			origins = append(origins, "https://"+effectiveRPID+":"+port)
		}
		if *tlsMode == "off" {
			origins = append(origins, "http://"+effectiveRPID)
			if port != "" && port != "443" && port != "80" {
				origins = append(origins, "http://"+effectiveRPID+":"+port)
			}
		}
	}

	// Set up WebAuthn handler.
	log.Printf("irongate: WebAuthn origins: %v", []string(origins))
	authHandler, err := auth.NewHandler(effectiveRPID, origins, hash, store, sessionMgr)
	if err != nil {
		log.Fatalf("irongate: %v", err)
	}

	// Start the child process.
	ctx := context.Background()
	child, err := process.Start(ctx, args[0], args[1:])
	if err != nil {
		log.Fatalf("irongate: %v", err)
	}

	// Wait for backend to be ready.
	log.Printf("irongate: waiting for backend at %s...", *backend)
	if err := process.WaitForBackend(ctx, *backend, 30*time.Second); err != nil {
		log.Fatalf("irongate: %v", err)
	}
	log.Printf("irongate: backend is ready")

	// Set up reverse proxy.
	// The username "opencode" matches opencode's OPENCODE_SERVER_USERNAME default.
	rp, err := proxy.New(*backend, "opencode", child.BackendPassword)
	if err != nil {
		log.Fatalf("irongate: %v", err)
	}

	// Build the HTTP handler.
	mux := buildMux(pfx, authHandler, rp, sessionMgr)

	// Start the server.
	server := &http.Server{
		Addr:    *listen,
		Handler: mux,
	}

	// Handle child exit: shut down the server.
	go func() {
		<-child.Done()
		log.Printf("irongate: child process exited, shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	log.Printf("irongate: listening on %s (prefix: %s, tls: %s, rpid: %s)", *listen, pfx, *tlsMode, effectiveRPID)

	switch *tlsMode {
	case "self-signed":
		cert, err := igtls.SelfSignedCert(effectiveRPID, "localhost", "127.0.0.1")
		if err != nil {
			log.Fatalf("irongate: generating self-signed cert: %v", err)
		}
		tlsCfg := &cryptotls.Config{Certificates: []cryptotls.Certificate{cert}}
		ln, err := cryptotls.Listen("tcp", *listen, tlsCfg)
		if err != nil {
			log.Fatalf("irongate: %v", err)
		}
		err = server.Serve(ln)

	case "off":
		err = server.ListenAndServe()

	default:
		log.Fatalf("irongate: unknown tls mode: %s", *tlsMode)
	}

	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("irongate: server error: %v", err)
	}

	os.Exit(child.Wait())
}

// buildMux creates the HTTP handler that routes between irongate endpoints
// and the reverse proxy.
func buildMux(prefix string, h *auth.Handler, rp http.Handler, sm *auth.SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Health check — always accessible (for load balancers).
		if path == prefix+"health" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok"}`))
			return
		}

		// Irongate auth endpoints.
		if strings.HasPrefix(path, prefix) {
			subpath := strings.TrimPrefix(path, prefix)
			switch subpath {
			// Enrollment pages and API.
			case "enroll":
				serveEmbedded(w, r, "web/enroll.html")
				return
			case "enroll/begin":
				h.BeginEnroll(w, r)
				return
			case "enroll/finish":
				h.FinishEnroll(w, r)
				return

			// Login pages and API.
			case "login":
				serveEmbedded(w, r, "web/login.html")
				return
			case "login/begin":
				h.BeginLogin(w, r)
				return
			case "login/finish":
				h.FinishLogin(w, r)
				return

			// Logout.
			case "logout":
				h.Logout(w, r)
				return

			// Manage page and API (requires authentication).
			case "manage":
				if !h.IsAuthenticated(r) {
					redirectToLogin(w, r, prefix)
					return
				}
				serveEmbedded(w, r, "web/manage.html")
				return
			case "manage/credentials":
				if !h.IsAuthenticated(r) {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				if r.Method == http.MethodDelete {
					h.DeleteCredential(w, r)
				} else {
					h.ListCredentials(w, r)
				}
				return
			}

			http.NotFound(w, r)
			return
		}

		// All other paths: require authentication.
		if !h.IsAuthenticated(r) {
			// If no credentials enrolled, redirect to enrollment info.
			if !h.HasAnyCredential() {
				http.Error(w, "Irongate: no passkeys enrolled. Use the enrollment URL to set up access.", http.StatusServiceUnavailable)
				return
			}
			redirectToLogin(w, r, prefix)
			return
		}

		// Authenticated: proxy to backend.
		rp.ServeHTTP(w, r)
	})
}

func redirectToLogin(w http.ResponseWriter, r *http.Request, prefix string) {
	orig := r.URL.RequestURI()
	http.Redirect(w, r, prefix+"login?orig="+url.QueryEscape(orig), http.StatusFound)
}

func serveEmbedded(w http.ResponseWriter, r *http.Request, name string) {
	data, err := webFS.ReadFile(name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

// multiFlag implements flag.Value for repeatable string flags.
type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
