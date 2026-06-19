package cryptopki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// I1 — Rogue CA / Certificate Forgery
type RogueCA struct {
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
}

func NewRogueCA() (*RogueCA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ARES Rogue CA",
			Organization: []string{"ARES Engine"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return &RogueCA{caCert: caCert, caKey: caKey}, nil
}

func (r *RogueCA) SignCert(commonName string, sans []string) (*tls.Certificate, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate cert key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"ARES Rogue"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, r.caCert, &certKey.PublicKey, r.caKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, r.caCert.Raw},
		PrivateKey:  certKey,
	}, nil
}

func (r *RogueCA) GetCACertPEM() []byte {
	return pemEncode("CERTIFICATE", r.caCert.Raw)
}

// I2 — TLS Downgrade
type TLSDowngrader struct{}

func NewTLSDowngrader() *TLSDowngrader {
	return &TLSDowngrader{}
}

func (t *TLSDowngrader) DowngradeToSSLv3() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionSSL30,
		MaxVersion: tls.VersionSSL30,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		InsecureSkipVerify: true,
	}
}

// I3 — Cipher Negotiation Manipulation
type CipherManipulator struct{}

func NewCipherManipulator() *CipherManipulator {
	return &CipherManipulator{}
}

func (c *CipherManipulator) WeakCipherConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		InsecureSkipVerify: true,
	}
}
