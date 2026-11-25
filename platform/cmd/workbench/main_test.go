package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/bootstrap"
)

func TestWorkbenchCommandFlagValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "root missing required config flag",
			args:    nil,
			wantErr: `required flag(s) "config" not set`,
		},
		{
			name:    "root rejects positional args",
			args:    []string{"--config", "c.json", "extra"},
			wantErr: "unknown command",
		},
		{
			name:    "prepare missing required flags",
			args:    []string{"prepare"},
			wantErr: `required flag(s)`,
		},
		{
			name:    "prepare missing output flag",
			args:    []string{"prepare", "--fabric", "/tmp/fabric"},
			wantErr: `required flag(s) "output" not set`,
		},
		{
			name:    "prepare missing fabric flag",
			args:    []string{"prepare", "--output", "/tmp/out"},
			wantErr: `required flag(s) "fabric" not set`,
		},
		{
			name:    "prepare rejects positional args",
			args:    []string{"prepare", "--fabric", "/tmp/f", "--output", "/tmp/o", "extra"},
			wantErr: "unknown command",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out, errOut bytes.Buffer
			cmd := newCommand()
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	t.Run("help lists root and prepare subcommand", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		cmd := newCommand()
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs([]string{"--help"})
		require.NoError(t, cmd.Execute())
		assert.Contains(t, out.String(), "prepare")
		assert.Contains(t, out.String(), "--config")
	})
}

func TestServeWorkbenchMTLSGuards(t *testing.T) {
	t.Parallel()

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name    string
		app     *bootstrap.Workbench
		wantErr string
	}{
		{
			name:    "nil workbench rejected",
			app:     nil,
			wantErr: "browser handler and listener address are required",
		},
		{
			name:    "missing browser handler rejected",
			app:     &bootstrap.Workbench{BrowserAddr: "127.0.0.1:0"},
			wantErr: "browser handler and listener address are required",
		},
		{
			name: "internal listener without handler rejected",
			app: &bootstrap.Workbench{
				Browser:      okHandler,
				BrowserAddr:  "127.0.0.1:0",
				InternalAddr: "127.0.0.1:0",
				InternalTLS:  &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert},
			},
			wantErr: "mutually authenticated TLS",
		},
		{
			name: "internal listener without TLS config rejected",
			app: &bootstrap.Workbench{
				Browser:      okHandler,
				BrowserAddr:  "127.0.0.1:0",
				Internal:     okHandler,
				InternalAddr: "127.0.0.1:0",
			},
			wantErr: "mutually authenticated TLS",
		},
		{
			name: "internal listener without RequireAndVerifyClientCert rejected",
			app: &bootstrap.Workbench{
				Browser:      okHandler,
				BrowserAddr:  "127.0.0.1:0",
				Internal:     okHandler,
				InternalAddr: "127.0.0.1:0",
				InternalTLS:  &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven},
			},
			wantErr: "mutually authenticated TLS",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := serveWorkbench(t.Context(), tc.app)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func newTestMTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now().UTC()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-workbench-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	issueLeaf := func(serial int64, cn string, extUsage x509.ExtKeyUsage) tls.Certificate {
		k, gErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, gErr)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{extUsage},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, cErr := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		require.NoError(t, cErr)
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: k}
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{issueLeaf(2, "workbench-internal", x509.ExtKeyUsageServerAuth)},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	clientTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{issueLeaf(3, "workbench-peer", x509.ExtKeyUsageClientAuth)},
		RootCAs:      pool,
	}
	return serverTLS, clientTLS
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func TestServeWorkbenchGracefulLifecycleWithMTLS(t *testing.T) {
	t.Parallel()

	serverTLS, clientTLS := newTestMTLSConfigs(t)
	browserAddr := reserveLoopbackAddr(t)
	internalAddr := reserveLoopbackAddr(t)

	app := &bootstrap.Workbench{
		BrowserAddr: browserAddr,
		Browser: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("browser-ok"))
		}),
		InternalAddr: internalAddr,
		Internal: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("internal-ok"))
		}),
		InternalTLS: serverTLS,
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- serveWorkbench(ctx, app)
	}()

	httpClient := &http.Client{Timeout: 2 * time.Second}
	mtlsClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}

	require.Eventually(t, func() bool {
		resp, err := httpClient.Get("http://" + browserAddr)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode == http.StatusOK && string(body) == "browser-ok"
	}, 3*time.Second, 25*time.Millisecond)

	require.Eventually(t, func() bool {
		resp, err := mtlsClient.Get("https://" + internalAddr)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode == http.StatusOK && string(body) == "internal-ok"
	}, 3*time.Second, 25*time.Millisecond)

	// Unauthenticated TLS client (without client cert) must be rejected by RequireAndVerifyClientCert.
	unauthClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: clientTLS.RootCAs, MinVersion: tls.VersionTLS13},
		},
	}
	_, err := unauthClient.Get("https://" + internalAddr)
	require.Error(t, err)

	cancel()
	select {
	case serveErr := <-done:
		require.NoError(t, serveErr)
	case <-time.After(5 * time.Second):
		t.Fatal("serveWorkbench did not shut down after context cancellation")
	}
}
