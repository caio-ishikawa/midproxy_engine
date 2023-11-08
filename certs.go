package midproxy_engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/patrickmn/go-cache"
)

func (p *Proxy) GenerateTLSConfig(hostname string) *tls.Config {
	tlsConfig := &tls.Config{
		ServerName:             hostname,
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h1"},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := clientHello.ServerName

			if host == "" {
				host = hostname
			}

			return p.getOrCreateTLSCert(host)
		},
		// This makes it so client certificate verification is skipped.
		// Remote certificate verification still has to be done.
		InsecureSkipVerify: true,
	}

	return tlsConfig
}

func loadRootCert() (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(ROOT_CA_CERT_PATH)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)

	rootCACert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return rootCACert, nil
}

func loadRootKey() (*rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(ROOT_CA_KEY_PATH)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)

	rootKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := rootKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Root key is not RSA private key")
	}

	return key, nil
}

// Generates server certificate and key files.
func (p *Proxy) getOrCreateTLSCert(host string) (*tls.Certificate, error) {
	cert, found := p.certCache.Get(host)
	if found {
		p.logDebug("Found cached certificate", nil)
		if c, ok := cert.(*tls.Certificate); ok {
			return c, nil
		} else {
			return nil, fmt.Errorf("Cached item is not a TLS certificate")
		}
	}

	hostname, _, err := net.SplitHostPort(host)
	if err == nil {
		host = hostname
	}

	rootCert := p.config.caCert
	rootKey := p.config.caPrivateKey

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	pkixpub, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}

	h := sha1.New()
	_, err = h.Write(pkixpub)
	if err != nil {
		return nil, err
	}

	keyID := h.Sum(nil)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() / 100000),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          keyID,
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, rootCert, privateKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}

	x509c, err := x509.ParseCertificate(raw)

	c := &tls.Certificate{
		Certificate: [][]byte{raw, rootCert.Raw},
		PrivateKey:  privateKey,
		Leaf:        x509c,
	}

	p.certCache.Set(host, c, cache.DefaultExpiration)

	return c, nil
}
