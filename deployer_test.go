package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalDeployerDeployDomainBacksUpExistingFilesToCertBakDir(t *testing.T) {
	domainName := "doc.example.com"
	oldNotAfter := time.Date(2026, 5, 1, 2, 3, 4, 0, time.UTC)
	oldMaterial := testCertificateMaterial(t, domainName, "old-cert", oldNotAfter)
	newMaterial := testCertificateMaterial(t, domainName, "new-cert", time.Date(2027, 6, 2, 3, 4, 5, 0, time.UTC))

	root := t.TempDir()
	certPath := filepath.Join(root, "ssl", "doc.example.com.crt")
	keyPath := filepath.Join(root, "private", "doc.example.com.key")
	writeTestFile(t, certPath, oldMaterial.CertificatePEM, 0640)
	writeTestFile(t, keyPath, oldMaterial.PrivateKeyPEM, 0600)

	deployer := &LocalDeployer{}
	result, err := deployer.DeployDomain(context.Background(), DomainConfig{
		Domain:   domainName,
		CertPath: certPath,
		KeyPath:  keyPath,
	}, newMaterial)
	if err != nil {
		t.Fatalf("DeployDomain() error = %v", err)
	}
	if !result.FilesChanged {
		t.Fatal("FilesChanged = false, want true")
	}

	expiresAt := oldNotAfter.UTC().Format("20060102T150405Z")
	wantBackupCertPath := filepath.Join(root, "ssl", "bak", "doc.example.com.crt.expires_at_"+expiresAt)
	wantBackupKeyPath := filepath.Join(root, "ssl", "bak", "doc.example.com.key.expires_at_"+expiresAt)
	if result.BackupCertPath != wantBackupCertPath {
		t.Fatalf("BackupCertPath = %q, want %q", result.BackupCertPath, wantBackupCertPath)
	}
	if result.BackupKeyPath != wantBackupKeyPath {
		t.Fatalf("BackupKeyPath = %q, want %q", result.BackupKeyPath, wantBackupKeyPath)
	}

	assertFileContent(t, wantBackupCertPath, oldMaterial.CertificatePEM)
	assertFileContent(t, wantBackupKeyPath, oldMaterial.PrivateKeyPEM)
	assertFileMode(t, wantBackupCertPath, 0640)
	assertFileMode(t, wantBackupKeyPath, 0600)
	assertFileContent(t, certPath, newMaterial.CertificatePEM)
	assertFileContent(t, keyPath, newMaterial.PrivateKeyPEM)
}

func TestLocalDeployerDeployDomainSkipsBackupWhenNoExistingCert(t *testing.T) {
	domainName := "doc.example.com"
	material := testCertificateMaterial(t, domainName, "new-cert", time.Date(2027, 6, 2, 3, 4, 5, 0, time.UTC))

	root := t.TempDir()
	certPath := filepath.Join(root, "ssl", "doc.example.com.crt")
	keyPath := filepath.Join(root, "private", "doc.example.com.key")

	deployer := &LocalDeployer{}
	result, err := deployer.DeployDomain(context.Background(), DomainConfig{
		Domain:   domainName,
		CertPath: certPath,
		KeyPath:  keyPath,
	}, material)
	if err != nil {
		t.Fatalf("DeployDomain() error = %v", err)
	}
	if !result.FilesChanged {
		t.Fatal("FilesChanged = false, want true")
	}
	if result.BackupCertPath != "" {
		t.Fatalf("BackupCertPath = %q, want empty", result.BackupCertPath)
	}
	if result.BackupKeyPath != "" {
		t.Fatalf("BackupKeyPath = %q, want empty", result.BackupKeyPath)
	}
	if _, err := os.Stat(filepath.Join(root, "ssl", "bak")); !os.IsNotExist(err) {
		t.Fatalf("bak dir stat error = %v, want not exist", err)
	}
	assertFileContent(t, certPath, material.CertificatePEM)
	assertFileContent(t, keyPath, material.PrivateKeyPEM)
}

func testCertificateMaterial(t *testing.T, domain, certificateID string, notAfter time.Time) *CertificateMaterial {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("rand.Int() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	material, err := parseCertificateMaterial(domain, certificateID, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertificateMaterial() error = %v", err)
	}
	return material
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
}

func assertFileContent(t *testing.T, path string, want []byte) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadFile(%q) content mismatch", path)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%q) = %v, want %v", path, got, want)
	}
}
