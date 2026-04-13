package tencentcloud

import (
	"context"
	"errors"
	"testing"
	"time"

	providerpkg "github.com/panjiang/cloud-cert-renewer/provider"
)

func TestCoveredByPattern(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{pattern: "doc.yourdomain.com", domain: "doc.yourdomain.com", want: true},
		{pattern: "*.yourdomain.com", domain: "doc.yourdomain.com", want: true},
		{pattern: "*.yourdomain.com", domain: "a.b.yourdomain.com", want: false},
		{pattern: "*.yourdomain.com", domain: "yourdomain.com", want: false},
		{pattern: "api.yourdomain.com", domain: "doc.yourdomain.com", want: false},
	}

	for _, tt := range tests {
		if got := coveredByPattern(tt.pattern, tt.domain); got != tt.want {
			t.Fatalf("coveredByPattern(%q, %q) = %v, want %v", tt.pattern, tt.domain, got, tt.want)
		}
	}
}

func TestProviderResolveCertificate(t *testing.T) {
	current := &providerpkg.ObservedCertificate{
		Domain:      "doc.yourdomain.com",
		Fingerprint: "current-fingerprint",
		NotAfter:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	t.Run("uses existing deployable certificate", func(t *testing.T) {
		applied := false
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{
					Enabled:      true,
					PollInterval: time.Minute,
					PollTimeout:  10 * time.Minute,
				},
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				if !deployableOnly {
					t.Fatal("listCertificatesFunc should not query pending certificates when deployable certificate exists")
				}
				return []certificateRecord{
					{
						id:       "deployable-cert",
						notAfter: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   "new-fingerprint",
					NotAfter:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			},
			applyCertificateFunc: func(ctx context.Context, domain string) (string, error) {
				applied = true
				return "", nil
			},
		}

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current)
		if err != nil {
			t.Fatalf("ResolveCertificate() error = %v", err)
		}
		if resolution == nil || resolution.Material == nil {
			t.Fatal("ResolveCertificate() expected deployable material")
		}
		if resolution.Material.CertificateID != "deployable-cert" {
			t.Fatalf("CertificateID = %q, want %q", resolution.Material.CertificateID, "deployable-cert")
		}
		if applied {
			t.Fatal("ApplyCertificate should not be called when deployable certificate exists")
		}
	})

	t.Run("returns pending certificate without apply when existing pending request found", func(t *testing.T) {
		applied := false
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{
					Enabled:      true,
					PollInterval: time.Minute,
					PollTimeout:  10 * time.Minute,
				},
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				if deployableOnly {
					return nil, nil
				}
				return []certificateRecord{
					{
						id:          "pending-cert",
						domains:     []string{domain},
						packageType: "83",
						verifyType:  "DNS_AUTO",
						status:      4,
						statusName:  "自动添加DNS记录",
						statusMsg:   "PENDING-DCV",
					},
				}, nil
			},
			describeCertificateFunc: func(ctx context.Context, certificateID string) (*certificateRecord, error) {
				return &certificateRecord{
					id:         certificateID,
					verifyType: "DNS_AUTO",
					status:     4,
					statusName: "自动添加DNS记录",
					statusMsg:  "PENDING-DCV",
				}, nil
			},
			waitFunc: func(ctx context.Context, d time.Duration) error {
				return context.DeadlineExceeded
			},
			applyCertificateFunc: func(ctx context.Context, domain string) (string, error) {
				applied = true
				return "", nil
			},
		}

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current)
		if err != nil {
			t.Fatalf("ResolveCertificate() error = %v", err)
		}
		if resolution == nil || resolution.Pending == nil {
			t.Fatal("ResolveCertificate() expected pending certificate")
		}
		if resolution.Pending.CertificateID != "pending-cert" {
			t.Fatalf("Pending.CertificateID = %q, want %q", resolution.Pending.CertificateID, "pending-cert")
		}
		if applied {
			t.Fatal("ApplyCertificate should not be called when pending request already exists")
		}
	})

	t.Run("applies certificate when no deployable or pending request exists", func(t *testing.T) {
		applied := false
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{
					Enabled:      true,
					PollInterval: time.Minute,
					PollTimeout:  10 * time.Minute,
				},
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return nil, nil
			},
			applyCertificateFunc: func(ctx context.Context, domain string) (string, error) {
				applied = true
				return "applied-cert", nil
			},
			describeCertificateFunc: func(ctx context.Context, certificateID string) (*certificateRecord, error) {
				return &certificateRecord{
					id:         certificateID,
					verifyType: "DNS_AUTO",
					status:     0,
					statusName: "审核中",
					statusMsg:  "WAIT-ISSUE",
				}, nil
			},
			waitFunc: func(ctx context.Context, d time.Duration) error {
				return context.DeadlineExceeded
			},
		}

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current)
		if err != nil {
			t.Fatalf("ResolveCertificate() error = %v", err)
		}
		if !applied {
			t.Fatal("ApplyCertificate should be called when no deployable or pending certificate exists")
		}
		if resolution == nil || resolution.Pending == nil {
			t.Fatal("ResolveCertificate() expected pending certificate after apply")
		}
		if resolution.Pending.CertificateID != "applied-cert" {
			t.Fatalf("Pending.CertificateID = %q, want %q", resolution.Pending.CertificateID, "applied-cert")
		}
	})

	t.Run("returns issued material after polling", func(t *testing.T) {
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{
					Enabled:      true,
					PollInterval: time.Minute,
					PollTimeout:  10 * time.Minute,
				},
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return nil, nil
			},
			applyCertificateFunc: func(ctx context.Context, domain string) (string, error) {
				return "issued-cert", nil
			},
			describeCertificateFunc: func(ctx context.Context, certificateID string) (*certificateRecord, error) {
				return &certificateRecord{
					id:         certificateID,
					status:     1,
					statusName: "已通过",
					statusMsg:  "WAIT-ISSUE",
					deployable: true,
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   "issued-fingerprint",
					NotAfter:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			},
		}

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current)
		if err != nil {
			t.Fatalf("ResolveCertificate() error = %v", err)
		}
		if resolution == nil || resolution.Material == nil {
			t.Fatal("ResolveCertificate() expected issued material")
		}
		if resolution.Material.CertificateID != "issued-cert" {
			t.Fatalf("Material.CertificateID = %q, want %q", resolution.Material.CertificateID, "issued-cert")
		}
	})

	t.Run("returns stage error on terminal failure", func(t *testing.T) {
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{
					Enabled:      true,
					PollInterval: time.Minute,
					PollTimeout:  10 * time.Minute,
				},
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return nil, nil
			},
			applyCertificateFunc: func(ctx context.Context, domain string) (string, error) {
				return "failed-cert", nil
			},
			describeCertificateFunc: func(ctx context.Context, certificateID string) (*certificateRecord, error) {
				return &certificateRecord{
					id:         certificateID,
					status:     2,
					statusName: "审核失败",
					statusMsg:  "域名验证超时，订单自动关闭，请您重新进行证书申请",
				}, nil
			},
		}

		_, err := provider.ResolveCertificate(context.Background(), current.Domain, current)
		if err == nil {
			t.Fatal("ResolveCertificate() expected error")
		}
		var stageErr *providerpkg.StageError
		if !errors.As(err, &stageErr) {
			t.Fatalf("ResolveCertificate() error = %T, want *StageError", err)
		}
		if stageErr.Stage != "wait_certificate_issue" {
			t.Fatalf("Stage = %q, want %q", stageErr.Stage, "wait_certificate_issue")
		}
	})

	t.Run("wildcard domain does not auto apply", func(t *testing.T) {
		applied := false
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{
					Enabled:      true,
					PollInterval: time.Minute,
					PollTimeout:  10 * time.Minute,
				},
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return nil, nil
			},
			applyCertificateFunc: func(ctx context.Context, domain string) (string, error) {
				applied = true
				return "", nil
			},
		}

		resolution, err := provider.ResolveCertificate(context.Background(), "*.yourdomain.com", &providerpkg.ObservedCertificate{
			Domain:      "*.yourdomain.com",
			Fingerprint: "current-fingerprint",
			NotAfter:    current.NotAfter,
		})
		if err != nil {
			t.Fatalf("ResolveCertificate() error = %v", err)
		}
		if resolution == nil {
			t.Fatal("ResolveCertificate() expected non-nil resolution")
		}
		if resolution.Material != nil || resolution.Pending != nil {
			t.Fatal("ResolveCertificate() expected empty resolution for wildcard domain")
		}
		if applied {
			t.Fatal("ApplyCertificate should not be called for wildcard domain")
		}
	})
}
