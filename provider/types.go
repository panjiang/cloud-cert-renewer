package provider

import "time"

type ObservedCertificate struct {
	Domain      string
	Fingerprint string
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

type CertificateResolution struct {
	Material *CertificateMaterial
	Pending  *PendingCertificate
}

type ResolveOptions struct {
	Force bool
}

type CleanupOptions struct {
	Force          bool
	ManagedDomains []string
}

const (
	CleanupTypeConfiguredOld = "configured-old"
	CleanupTypeAllExpired    = "all-expired"
)

type CleanupCandidate struct {
	Provider           string
	CleanupType        string
	Domain             string
	CertificateID      string
	CertificateDomains []string
	NotAfter           time.Time
	CurrentNotAfter    time.Time
}

type PendingCertificate struct {
	CertificateID string
	Status        uint64
	StatusName    string
	StatusMsg     string
	VerifyType    string
}

type StageError struct {
	Stage string
	Err   error
}

func (e *StageError) Error() string {
	return e.Err.Error()
}

func (e *StageError) Unwrap() error {
	return e.Err
}
