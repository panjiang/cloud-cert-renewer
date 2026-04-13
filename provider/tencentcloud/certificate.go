package tencentcloud

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	providerpkg "github.com/panjiang/cloud-cert-renewer/provider"
)

var tencentTimeLocation = time.FixedZone("GMT+8", 8*60*60)

func certificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

func parseCertificateMaterial(domain, certificateID string, certPEM, keyPEM []byte) (*providerpkg.CertificateMaterial, error) {
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

	return &providerpkg.CertificateMaterial{
		CertificateID:  certificateID,
		Domain:         domain,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		Fingerprint:    certificateFingerprint(leaf),
		Serial:         leaf.SerialNumber.String(),
		NotAfter:       leaf.NotAfter,
	}, nil
}

func extractCertificateMaterialFromZIP(domain, certificateID string, zipContent []byte) (*providerpkg.CertificateMaterial, error) {
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
		material *providerpkg.CertificateMaterial
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

func metadataCoversDomain(domain string, metadataDomains []string, isWildcard *bool) bool {
	for _, candidate := range metadataDomains {
		if coveredByPattern(candidate, domain) {
			return true
		}
	}
	if isWildcard != nil && *isWildcard {
		for _, candidate := range metadataDomains {
			if strings.HasPrefix(candidate, "*.") && coveredByPattern(candidate, domain) {
				return true
			}
		}
	}
	return false
}

func coveredByPattern(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if pattern == "" || domain == "" {
		return false
	}
	if pattern == domain {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	suffix := strings.TrimPrefix(pattern, "*.")
	if !strings.HasSuffix(domain, "."+suffix) {
		return false
	}

	rest := strings.TrimSuffix(domain, "."+suffix)
	return rest != "" && !strings.Contains(rest, ".")
}

func parseTencentTimestamp(value *string) (time.Time, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}

	layouts := []string{
		"2006-01-02 15:04:05",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if ts, err := time.ParseInLocation(layout, strings.TrimSpace(*value), tencentTimeLocation); err == nil {
			return ts, nil
		}
	}

	return time.Time{}, fmt.Errorf("unsupported timestamp: %s", *value)
}

func parseOptionalTencentTimestamp(value *string) (time.Time, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return time.Time{}, nil
	}
	return parseTencentTimestamp(value)
}
