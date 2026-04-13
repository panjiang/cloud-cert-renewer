package provider

import "context"

type Provider interface {
	ResolveCertificate(ctx context.Context, domain string, current *ObservedCertificate) (*CertificateResolution, error)
}
