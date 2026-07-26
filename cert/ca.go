package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA represents a Certificate Authority
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPath    string
	KeyPath     string
	DERPath     string
	ProfilePath string
}

// LoadOrCreateCA loads an existing CA certificate or creates a new one if it doesn't exist
func LoadOrCreateCA(caDir string) (*CA, error) {
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	var ca *CA
	var err error

	// Check if the CA certificate and key already exist
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			ca, err = loadCA(certPath, keyPath)
		}
	}

	if ca == nil && err == nil {
		ca, err = createCA(certPath, keyPath)
	}
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(keyPath, 0600); err != nil {
		return nil, fmt.Errorf("failed to secure CA private key: %v", err)
	}
	if err := writeIOSArtifacts(ca, caDir); err != nil {
		return nil, err
	}

	return ca, nil
}

// loadCA loads the CA certificate and private key from files
func loadCA(certPath, keyPath string) (*CA, error) {

	// Read CA certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Read CA private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse CA private key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  key,
		CertPath:    certPath,
		KeyPath:     keyPath,
	}, nil
}

// createCA creates a new CA certificate and private key
func createCA(certPath, keyPath string) (*CA, error) {
	log.Println("Creating new CA certificate......")

	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate serial number: %v", err)
	}

	now := time.Now()

	// Generate certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:    "MITM Proxy CA",
			Organization:  []string{"MITM Proxy"},
			Country:       []string{"CN"},
			Province:      []string{"Anywhere"},
			Locality:      []string{"Anywhere"},
			StreetAddress: []string{"Anywhere"},
			PostalCode:    []string{"000000"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create CA certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// Parse CA certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Save CA certificate to file
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		certOut.Close()
		return nil, fmt.Errorf("failed to write CA certificate: %v", err)
	}
	if err := certOut.Close(); err != nil {
		return nil, fmt.Errorf("failed to close CA certificate file: %v", err)
	}

	// Save CA private key to file
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA private key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		keyOut.Close()
		return nil, fmt.Errorf("failed to write CA private key: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		return nil, fmt.Errorf("failed to close CA private key file: %v", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  key,
		CertPath:    certPath,
		KeyPath:     keyPath,
	}, nil
}

// writeIOSArtifacts creates the DER certificate and configuration profile
// required for reliable manual installation on iPhone and iPad.
func writeIOSArtifacts(ca *CA, caDir string) error {
	derPath := filepath.Join(caDir, "ca.cer")
	profilePath := filepath.Join(caDir, "ca.mobileconfig")

	if err := os.WriteFile(derPath, ca.Certificate.Raw, 0644); err != nil {
		return fmt.Errorf("failed to write iOS CA certificate: %v", err)
	}

	certificateUUID := stableUUID(ca.Certificate.Raw, "certificate")
	profileUUID := stableUUID(ca.Certificate.Raw, "profile")
	certificateData := base64.StdEncoding.EncodeToString(ca.Certificate.Raw)

	profile := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>game-mitm-ca.cer</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDescription</key>
			<string>Installs the game-mitm root certificate.</string>
			<key>PayloadDisplayName</key>
			<string>game-mitm Root CA</string>
			<key>PayloadIdentifier</key>
			<string>com.y-projects.game-mitm.ca</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Allows this device to inspect HTTPS traffic through game-mitm.</string>
	<key>PayloadDisplayName</key>
	<string>game-mitm Root CA</string>
	<key>PayloadIdentifier</key>
	<string>com.y-projects.game-mitm.profile</string>
	<key>PayloadOrganization</key>
	<string>game-mitm</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, certificateData, certificateUUID, profileUUID)

	if err := os.WriteFile(profilePath, []byte(profile), 0644); err != nil {
		return fmt.Errorf("failed to write iOS configuration profile: %v", err)
	}

	ca.DERPath = derPath
	ca.ProfilePath = profilePath
	return nil
}

func stableUUID(certificate []byte, purpose string) string {
	hash := sha256.New()
	hash.Write([]byte(purpose))
	hash.Write(certificate)
	sum := hash.Sum(nil)

	// UUID version 5 layout with a stable SHA-256-derived value.
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80

	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		sum[0:4],
		sum[4:6],
		sum[6:8],
		sum[8:10],
		sum[10:16],
	)
}
