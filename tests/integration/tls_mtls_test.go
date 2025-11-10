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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to generate a self-signed certificate
func generateSelfSignedCert(t *testing.T) (string, string, *x509.Certificate, *rsa.PrivateKey) {
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	certOut, err := os.CreateTemp("", "cert.pem")
	require.NoError(t, err)
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.CreateTemp("", "key.pem")
	require.NoError(t, err)
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certOut.Name(), keyOut.Name(), cert, priv
}

func TestTLSIntegration(t *testing.T) {
	t.Parallel()
	_, _, serverCert, priv := generateSelfSignedCert(t)

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  priv,
				Leaf:        serverCert,
			},
		},
	}
	server.StartTLS()
	defer server.Close()

	// Create a client that trusts our self-signed cert
	client := server.Client()

	// Make a request
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestMTLSIntegration(t *testing.T) {
	t.Parallel()
	// Server cert
	_, _, serverCert, serverPriv := generateSelfSignedCert(t)

	// Client cert
	_, _, clientCert, clientPriv := generateSelfSignedCert(t)

	// Server setup
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(clientCert)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  serverPriv,
				Leaf:        serverCert,
			},
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
	}
	server.StartTLS()
	defer server.Close()

	// Client with certificate
	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{
		{
			Certificate: [][]byte{clientCert.Raw},
			PrivateKey:  clientPriv,
			Leaf:        clientCert,
		},
	}

	// Make a request with the client cert
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Client without certificate
	badClient := server.Client()

	// Make a request without the client cert
	_, err = badClient.Get(server.URL)
	assert.Error(t, err)
}
