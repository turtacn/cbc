//go:build integration
package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to generate a self-signed certificate
func generateSelfSignedCert(t *testing.T) (string, string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certOut, err := os.CreateTemp("", "cert.pem")
	require.NoError(t, err)
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.CreateTemp("", "key.pem")
	require.NoError(t, err)
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certOut.Name(), keyOut.Name()
}

func TestTLSIntegration(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create a listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{
		Addr:    ln.Addr().String(),
		Handler: handler,
	}

	go func() {
		err := server.ListenAndServeTLS(certFile, keyFile)
		if err != http.ErrServerClosed {
			t.Logf("server error: %v", err)
		}
	}()
	defer server.Close()

	// Wait for the server to start
	time.Sleep(100 * time.Millisecond)

	// Create a client that trusts our self-signed cert
	caCert, err := os.ReadFile(certFile)
	require.NoError(t, err)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	// Make a request
	resp, err := client.Get("https://" + server.Addr)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMTLSIntegration(t *testing.T) {
	// Server cert
	serverCertFile, serverKeyFile := generateSelfSignedCert(t)
	defer os.Remove(serverCertFile)
	defer os.Remove(serverKeyFile)

	// Client cert
	clientCertFile, clientKeyFile := generateSelfSignedCert(t)
	defer os.Remove(clientCertFile)
	defer os.Remove(clientKeyFile)

	// Server setup
	caCert, err := os.ReadFile(clientCertFile)
	require.NoError(t, err)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{
		Addr:      ln.Addr().String(),
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	go func() {
		err := server.ListenAndServeTLS(serverCertFile, serverKeyFile)
		if err != http.ErrServerClosed {
			t.Logf("server error: %v", err)
		}
	}()
	defer server.Close()

	// Wait for the server to start
	time.Sleep(100 * time.Millisecond)

	// Client with certificate
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	require.NoError(t, err)

	serverCaCert, err := os.ReadFile(serverCertFile)
	require.NoError(t, err)
	serverCaCertPool := x509.NewCertPool()
	serverCaCertPool.AppendCertsFromPEM(serverCaCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      serverCaCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	// Make a request with the client cert
	resp, err := client.Get("https://" + server.Addr)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Client without certificate
	badClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: serverCaCertPool,
			},
		},
	}

	// Make a request without the client cert
	_, err = badClient.Get("https://" + server.Addr)
	assert.Error(t, err)
}
