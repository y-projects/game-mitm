package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertificateManager manages and caches certificates for domains
type CertificateManager struct {
	ca         *CA
	certCache  map[string]*tls.Certificate
	cacheMutex sync.RWMutex
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(ca *CA) *CertificateManager {
	return &CertificateManager{
		ca:        ca,
		certCache: make(map[string]*tls.Certificate),
	}
}

// GetCertificate returns a certificate for the given domain
// This is used as the GetCertificate callback for tls.Config
func (cm *CertificateManager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if clientHello == nil || clientHello.ServerName == "" {
		return nil, fmt.Errorf("missing server name")
	}
	return cm.GetCertificateForDomain(clientHello.ServerName)
}

// GetCertificateForDomain returns a certificate for the given domain
func (cm *CertificateManager) GetCertificateForDomain(domain string) (*tls.Certificate, error) {
	// Check if we have a cached certificate
	cm.cacheMutex.RLock()
	if cert, ok := cm.certCache[domain]; ok {
		cm.cacheMutex.RUnlock()
		return cert, nil
	}
	cm.cacheMutex.RUnlock()

	// Generate a new certificate
	cert, err := cm.generateCertificateForDomain(domain)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	cm.cacheMutex.Lock()
	cm.certCache[domain] = cert
	cm.cacheMutex.Unlock()

	return cert, nil
}

// generateCertificateForDomain generates a new certificate for the given domain
func (cm *CertificateManager) generateCertificateForDomain(domain string) (*tls.Certificate, error) {
	// Extract host from domain (remove port if present)
	host := domain
	if h, _, err := net.SplitHostPort(domain); err == nil {
		host = h
	}

	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// Create certificate using CA
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		cm.ca.Certificate,
		&priv.PublicKey,
		cm.ca.PrivateKey,
	)
	if err != nil {
		return nil, err
	}

	// Encode certificate and private key
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
