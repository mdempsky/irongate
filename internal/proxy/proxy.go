// Package proxy implements the reverse proxy to the backend server.
package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// New creates a reverse proxy targeting the given backend address.
// If backendUser and backendPassword are non-empty, the proxy injects
// HTTP Basic Auth credentials on every proxied request (defense-in-depth).
func New(backendAddr, backendUser, backendPassword string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse("http://" + backendAddr)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Wrap the default director to inject basic auth.
	defaultDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		defaultDirector(req)
		if backendUser != "" && backendPassword != "" {
			creds := base64.StdEncoding.EncodeToString(
				[]byte(backendUser + ":" + backendPassword),
			)
			req.Header.Set("Authorization", "Basic "+creds)
		}
	}

	return proxy, nil
}
