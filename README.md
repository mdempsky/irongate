# Irongate

Passkey-authenticated reverse proxy for single-user web applications.

Many self-hosted web apps implement ad hoc username/password schemes when
they're really meant for a single user anyway. Irongate replaces all of that
with WebAuthn passkeys and a secure bootstrap process. No default credentials,
no passwords — just passkeys.

## How it works

```
Internet → irongate (:443) → your app (:8080 on 127.0.0.1)
```

Irongate sits in front of your web server as a reverse proxy. It:

1. **Spawns your app** as a child process and babysits it like an init process.
2. **Blocks all access** until a passkey is registered.
3. **Authenticates every request** using WebAuthn passkeys — no passwords, ever.
4. **Proxies authenticated traffic** to your app on localhost.

### Secure bootstrap

The process that launches the container generates a random seed, computes
`HASH = sha256(seed)`, and passes `HASH` to the container as an environment
variable. After the container is up, it opens the user's browser to:

```
https://your-host/_ah/enroll#<seed>
```

The enrollment page reads the seed from the URL fragment (which is never sent
to the server in HTTP requests). The JavaScript includes the seed in the
WebAuthn enrollment request body, where the server verifies
`sha256(submitted_seed) == HASH`. This ensures only the person who launched
the container can enroll the first passkey.

After initial enrollment, additional passkeys can be added from the
authenticated management page.

## Quick start

### Install

```bash
go install github.com/mdempsky/irongate@latest
```

### Usage

```
irongate [flags] command [args...]
```

Instead of running your server directly:

```bash
myserver -listen 0.0.0.0:8080
```

Wrap it with irongate:

```bash
HASH=$(printf 'my-secret-seed' | shasum -a 256 | cut -d' ' -f1) \
irongate -listen :443 -tls self-signed -backend 127.0.0.1:8080 \
  -- myserver -listen 127.0.0.1:8080
```

Then open `https://localhost/_ah/enroll#my-secret-seed` to register your passkey.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:443` | Address to listen on |
| `-backend` | `127.0.0.1:8080` | Backend address to proxy to |
| `-tls` | `off` | TLS mode: `off` (upstream terminates TLS) or `self-signed` |
| `-origin` | (auto) | Allowed WebAuthn origin (repeatable, e.g. `https://example.com:8443`) |
| `-credentials` | (in-memory) | Path to JSON file for persistent passkey storage |
| `-session-ttl` | `24h` | Session cookie lifetime |
| `-rpid` | (auto) | WebAuthn Relying Party ID (hostname) |
| `-prefix` | `/_irongate/` | URL prefix for auth endpoints |

### Environment

| Variable | Description |
|----------|-------------|
| `HASH` | Hex-encoded SHA-256 hash of the enrollment seed. Required for first passkey enrollment. |

## Docker example (OpenCode)

Irongate includes a ready-made Docker setup for [OpenCode](https://opencode.ai),
an open-source AI coding agent with a web UI.

### Dockerfile

```dockerfile
FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /irongate .

FROM ghcr.io/anomalyco/opencode:beta
COPY --from=builder /irongate /usr/local/bin/irongate
ENTRYPOINT []
EXPOSE 443
CMD ["irongate", "-listen=:443", "-tls=self-signed", "-backend=127.0.0.1:4096", \
     "-prefix=/_ah/", "--", \
     "opencode", "web", "--port", "4096", "--hostname", "127.0.0.1"]
```

### Launch script

The included `launch.sh` automates the full flow:

```bash
export ANTHROPIC_API_KEY="sk-..."
./launch.sh
```

It generates a random seed, computes the hash, builds the Docker image, starts
the container, waits for it to be ready, and opens the enrollment URL in your
browser.

## Auth endpoints

All auth endpoints live under the configured prefix (default `/_irongate/`):

| Endpoint | Method | Auth required | Description |
|----------|--------|---------------|-------------|
| `<prefix>enroll` | GET | No | Enrollment page |
| `<prefix>enroll/begin` | POST | No | Start WebAuthn registration |
| `<prefix>enroll/finish` | POST | Seed or session | Complete registration |
| `<prefix>login` | GET | No | Login page |
| `<prefix>login/begin` | POST | No | Start WebAuthn authentication |
| `<prefix>login/finish` | POST | No | Complete authentication |
| `<prefix>logout` | POST | No | Clear session |
| `<prefix>manage` | GET | Yes | Passkey management page |
| `<prefix>manage/credentials` | GET | Yes | List enrolled passkeys |
| `<prefix>manage/credentials?id=...` | DELETE | Yes | Remove a passkey |
| `<prefix>health` | GET | No | Health check for load balancers |

## Architecture

```
irongate/
├── main.go                       Entry point, CLI flags, HTTP routing
├── internal/
│   ├── auth/
│   │   ├── store.go              Credential storage (memory + JSON file)
│   │   ├── session.go            HMAC-SHA256 signed cookie sessions
│   │   └── webauthn.go           WebAuthn enrollment/login/manage handlers
│   ├── process/
│   │   └── process.go            Child process lifecycle & signal forwarding
│   ├── proxy/
│   │   └── proxy.go              Reverse proxy with Basic Auth injection
│   └── tls/
│       └── tls.go                Self-signed ECDSA certificate generation
├── web/
│   ├── enroll.html               Passkey registration page
│   ├── login.html                Passkey authentication page
│   └── manage.html               Passkey management page
├── Dockerfile                    Multi-stage build for OpenCode demo
└── launch.sh                     Example launch script
```

## Security properties

- **No default credentials.** The system has zero access until a passkey is enrolled.
- **Seed never stored.** Only `HASH = sha256(seed)` exists in the environment.
  The seed lives in the browser's URL fragment, which is never sent to the
  server in HTTP requests — it's included only in the JS-constructed POST body
  during enrollment.
- **Passkey-only.** No passwords anywhere in the system. Authentication uses
  WebAuthn with platform authenticators (Touch ID, Windows Hello, etc.) or
  security keys.
- **Defense-in-depth.** Irongate generates a random password at startup and
  injects it into the child process's environment (`OPENCODE_SERVER_PASSWORD`).
  Every proxied request includes Basic Auth credentials. Even if the reverse
  proxy has a bug, the backend has its own auth layer.
- **Backend isolation.** The child process listens on `127.0.0.1` and is never
  directly reachable from outside the container.

## License

MIT
