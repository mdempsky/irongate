// Package process manages the child (backend) process lifecycle.
package process

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// Child represents a managed child process.
type Child struct {
	cmd      *exec.Cmd
	done     chan struct{}
	exitCode int

	// BackendPassword is the randomly generated password set as
	// OPENCODE_SERVER_PASSWORD in the child's environment.
	BackendPassword string
}

// Start spawns the child process with the given command and arguments.
// It sets up signal forwarding and monitors the child lifecycle.
// The child's stdout/stderr are inherited from the parent.
func Start(ctx context.Context, command string, args []string) (*Child, error) {
	// Generate a random backend password for defense-in-depth.
	pwBytes := make([]byte, 32)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, fmt.Errorf("generating backend password: %w", err)
	}
	backendPw := base64.RawURLEncoding.EncodeToString(pwBytes)

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "OPENCODE_SERVER_PASSWORD="+backendPw)

	// Don't propagate signals to the child via process group;
	// we forward them ourselves.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting child process %q: %w", command, err)
	}

	c := &Child{
		cmd:             cmd,
		done:            make(chan struct{}),
		BackendPassword: backendPw,
	}

	// Monitor child process in background.
	go func() {
		defer close(c.done)
		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				c.exitCode = exitErr.ExitCode()
			} else {
				c.exitCode = 1
			}
		}
		log.Printf("irongate: child process exited with code %d", c.exitCode)
	}()

	// Forward signals to child.
	go c.forwardSignals()

	return c, nil
}

// forwardSignals forwards SIGTERM and SIGINT to the child process.
func (c *Child) forwardSignals() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	for {
		select {
		case sig := <-sigCh:
			if c.cmd.Process != nil {
				_ = c.cmd.Process.Signal(sig)
			}
		case <-c.done:
			return
		}
	}
}

// Wait blocks until the child process exits and returns its exit code.
func (c *Child) Wait() int {
	<-c.done
	return c.exitCode
}

// Done returns a channel that is closed when the child process exits.
func (c *Child) Done() <-chan struct{} {
	return c.done
}

// ExitCode returns the child's exit code. Only valid after Done() is closed.
func (c *Child) ExitCode() int {
	return c.exitCode
}

// WaitForBackend polls the given address until it accepts TCP connections
// or the context is cancelled. This is used to wait for the backend
// server to be ready before accepting external traffic.
func WaitForBackend(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("backend %s not ready after %v", addr, timeout)
		}

		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
