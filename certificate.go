package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type ObservedCertificate struct {
	Domain      string
	Fingerprint string
	Serial      string
	NotAfter    time.Time
}

type CertificateMaterial struct {
	CertificateID  string
	Domain         string
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Fingerprint    string
	Serial         string
	NotAfter       time.Time
}

func probeTLSCertificate(ctx context.Context, domain string) (*ObservedCertificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no tls certificate")
	}

	return observeX509Certificate(domain, certs[0]), nil
}

func observeX509Certificate(domain string, cert *x509.Certificate) *ObservedCertificate {
	return &ObservedCertificate{
		Domain:      domain,
		Fingerprint: certificateFingerprint(cert),
		Serial:      cert.SerialNumber.String(),
		NotAfter:    cert.NotAfter,
	}
}

func certificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

func parseCertificateMaterial(domain, certificateID string, certPEM, keyPEM []byte) (*CertificateMaterial, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate/key pair: %w", err)
	}

	var leaf *x509.Certificate
	if pair.Leaf != nil {
		leaf = pair.Leaf
	} else if len(pair.Certificate) > 0 {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse leaf certificate: %w", err)
		}
	} else {
		return nil, fmt.Errorf("empty certificate chain")
	}

	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("certificate does not cover domain %s: %w", domain, err)
	}

	return &CertificateMaterial{
		CertificateID:  certificateID,
		Domain:         domain,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    certificateFingerprint(leaf),
		Serial:         leaf.SerialNumber.String(),
		NotAfter:       leaf.NotAfter,
	}, nil
}

func extractCertificateMaterialFromZIP(domain, certificateID string, zipContent []byte) (*CertificateMaterial, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipContent), int64(len(zipContent)))
	if err != nil {
		return nil, fmt.Errorf("open certificate zip: %w", err)
	}

	type fileCandidate struct {
		name string
		data []byte
	}

	var certFiles []fileCandidate
	var keyFiles []fileCandidate

	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open zip entry %s: %w", f.Name, err)
		}
		data, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read zip entry %s: %w", f.Name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close zip entry %s: %w", f.Name, closeErr)
		}

		if containsPEMBlock(data, "PRIVATE KEY") {
			keyFiles = append(keyFiles, fileCandidate{name: f.Name, data: data})
		}
		if containsPEMBlock(data, "CERTIFICATE") {
			certFiles = append(certFiles, fileCandidate{name: f.Name, data: data})
		}
	}

	if len(certFiles) == 0 || len(keyFiles) == 0 {
		return nil, fmt.Errorf("certificate zip does not contain certificate and key")
	}

	type bundleCandidate struct {
		material *CertificateMaterial
		score    int
	}

	var best *bundleCandidate
	for _, certFile := range certFiles {
		for _, keyFile := range keyFiles {
			material, err := parseCertificateMaterial(domain, certificateID, certFile.data, keyFile.data)
			if err != nil {
				continue
			}
			score := scoreCertificateBundle(certFile.name, certFile.data)
			if best == nil || score > best.score || (score == best.score && material.NotAfter.After(best.material.NotAfter)) {
				best = &bundleCandidate{material: material, score: score}
			}
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no valid nginx certificate bundle found for %s", domain)
	}

	return best.material, nil
}

func containsPEMBlock(data []byte, suffix string) bool {
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return false
		}
		if strings.HasSuffix(block.Type, suffix) {
			return true
		}
		rest = remaining
	}
}

func scoreCertificateBundle(name string, data []byte) int {
	score := strings.Count(string(data), "BEGIN CERTIFICATE")
	base := strings.ToLower(filepath.Base(name))
	if strings.Contains(base, "bundle") {
		score += 10
	}
	if strings.HasSuffix(base, ".crt") {
		score += 3
	}
	if strings.HasSuffix(base, ".pem") {
		score += 2
	}
	return score
}

func certFingerprintFromPEM(certPEM []byte) (string, error) {
	cert, err := firstCertificateFromPEM(certPEM)
	if err != nil {
		return "", err
	}
	return certificateFingerprint(cert), nil
}

func firstCertificateFromPEM(certPEM []byte) (*x509.Certificate, error) {
	rest := certPEM
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no certificate found in pem")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return cert, nil
		}
		rest = remaining
	}
}

func verifyExternalDeployment(ctx context.Context, domain, expectedFingerprint string) (*ObservedCertificate, error) {
	var last *ObservedCertificate
	var lastErr error

	for i := 0; i < 5; i++ {
		last, lastErr = probeTLSCertificate(ctx, domain)
		if lastErr == nil && last.Fingerprint == expectedFingerprint {
			return last, nil
		}
		if i < 4 {
			time.Sleep(3 * time.Second)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("probe external certificate: %w", lastErr)
	}

	return nil, fmt.Errorf("external certificate fingerprint mismatch: got=%s want=%s serial=%s notAfter=%s",
		last.Fingerprint, expectedFingerprint, last.Serial, last.NotAfter.Format(time.RFC3339))
}

func domainsFromMetadata(primary *string, sans []*string) []string {
	values := make([]string, 0, len(sans)+1)
	if primary != nil && strings.TrimSpace(*primary) != "" {
		values = append(values, strings.TrimSpace(*primary))
	}
	for _, san := range sans {
		if san == nil {
			continue
		}
		v := strings.TrimSpace(*san)
		if v == "" {
			continue
		}
		values = append(values, v)
	}

	slices.Sort(values)
	return slices.Compact(values)
}
