package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"
)

// freeAddress returns a loopback address with a port that was free a moment ago.
func freeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func get(addr, path string) (int, string, error) {
	resp, err := http.Get("http://" + addr + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

// start runs run in the background; its result arrives on the returned channel.
func start(ctx context.Context, reporterAddress, prometheusAddress string) <-chan error {
	done := make(chan error, 1)
	go func() { done <- run(ctx, zap.NewNop(), reporterAddress, prometheusAddress) }()
	return done
}

func result(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("run did not return")
		return nil
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	reporterAddress, prometheusAddress := freeAddress(t), freeAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := start(ctx, reporterAddress, prometheusAddress)

	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body, err := get(prometheusAddress, "/healthz")
		if err == nil && code == http.StatusOK && body == "ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/healthz = %d %q, %v", code, body, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, body, err := get(prometheusAddress, "/metrics"); err != nil || code != http.StatusOK || len(body) == 0 {
		t.Errorf("/metrics = %d, %d bytes, %v", code, len(body), err)
	}
	if code, _, err := get(reporterAddress, "/"); err != nil || code != http.StatusOK {
		t.Errorf("GET / = %d, %v", code, err)
	}

	cancel()
	if err := result(t, done); err != nil {
		t.Fatalf("run() = %v, want nil after cancel", err)
	}
	for _, addr := range []string{reporterAddress, prometheusAddress} {
		if conn, err := net.Dial("tcp", addr); err == nil {
			_ = conn.Close()
			t.Errorf("%s still accepts connections after run returned", addr)
		}
	}
}

func TestRunFailsWhenAListenerCannotBind(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	for name, addrs := range map[string][2]string{
		"reporter": {taken.Addr().String(), freeAddress(t)},
		"metrics":  {freeAddress(t), taken.Addr().String()},
	} {
		t.Run(name, func(t *testing.T) {
			if err := result(t, start(context.Background(), addrs[0], addrs[1])); err == nil {
				t.Fatal("run() = nil, want the bind error")
			}
		})
	}
}
