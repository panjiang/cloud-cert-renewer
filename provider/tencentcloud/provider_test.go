package tencentcloud

import (
	"context"
	"errors"
	"testing"
	"time"

	providerpkg "github.com/panjiang/cert-renewer/provider"
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

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current, providerpkg.ResolveOptions{})
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

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current, providerpkg.ResolveOptions{})
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

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current, providerpkg.ResolveOptions{})
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

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current, providerpkg.ResolveOptions{})
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

		_, err := provider.ResolveCertificate(context.Background(), current.Domain, current, providerpkg.ResolveOptions{})
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
		}, providerpkg.ResolveOptions{})
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

	t.Run("force mode allows older deployable certificate", func(t *testing.T) {
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
				return []certificateRecord{
					{
						id:       "older-cert",
						notAfter: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   "older-fingerprint",
					NotAfter:      time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			},
			applyCertificateFunc: func(ctx context.Context, domain string) (string, error) {
				applied = true
				return "", nil
			},
		}

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current, providerpkg.ResolveOptions{Force: true})
		if err != nil {
			t.Fatalf("ResolveCertificate() error = %v", err)
		}
		if resolution == nil || resolution.Material == nil {
			t.Fatal("ResolveCertificate() expected deployable material in force mode")
		}
		if resolution.Material.CertificateID != "older-cert" {
			t.Fatalf("CertificateID = %q, want %q", resolution.Material.CertificateID, "older-cert")
		}
		if applied {
			t.Fatal("ApplyCertificate should not be called in force mode when deployable certificate exists")
		}
	})

	t.Run("force mode allows same fingerprint certificate", func(t *testing.T) {
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
				return []certificateRecord{
					{
						id:       "same-fingerprint-cert",
						notAfter: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   current.Fingerprint,
					NotAfter:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			},
			applyCertificateFunc: func(ctx context.Context, domain string) (string, error) {
				applied = true
				return "", nil
			},
		}

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current, providerpkg.ResolveOptions{Force: true})
		if err != nil {
			t.Fatalf("ResolveCertificate() error = %v", err)
		}
		if resolution == nil || resolution.Material == nil {
			t.Fatal("ResolveCertificate() expected material in force mode")
		}
		if resolution.Material.CertificateID != "same-fingerprint-cert" {
			t.Fatalf("CertificateID = %q, want %q", resolution.Material.CertificateID, "same-fingerprint-cert")
		}
		if applied {
			t.Fatal("ApplyCertificate should not be called in force mode when deployable certificate exists")
		}
	})

	t.Run("force mode does not auto apply when no deployable certificate exists", func(t *testing.T) {
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
		}

		resolution, err := provider.ResolveCertificate(context.Background(), current.Domain, current, providerpkg.ResolveOptions{Force: true})
		if err != nil {
			t.Fatalf("ResolveCertificate() error = %v", err)
		}
		if resolution == nil {
			t.Fatal("ResolveCertificate() expected non-nil resolution")
		}
		if resolution.Material != nil || resolution.Pending != nil {
			t.Fatal("ResolveCertificate() expected empty resolution in force mode without deployable certificate")
		}
		if applied {
			t.Fatal("ApplyCertificate should not be called in force mode without deployable certificate")
		}
	})
}

func TestProviderCleanupOldCertificates(t *testing.T) {
	keep := &providerpkg.CertificateMaterial{
		CertificateID: "new-cert",
		Fingerprint:   "new-fingerprint",
		NotAfter:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	live := &providerpkg.ObservedCertificate{
		Domain:      "doc.yourdomain.com",
		Fingerprint: "live-fingerprint",
		NotAfter:    keep.NotAfter,
	}

	t.Run("deletes eligible old certificates", func(t *testing.T) {
		var deleted []string
		provider := &Provider{
			cfg: Config{
				AutoApply:                 AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
				AutoDeleteOldCertificates: true,
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return []certificateRecord{
					{
						id:            "new-cert",
						domains:       []string{domain},
						notAfter:      keep.NotAfter,
						allowDownload: true,
					},
					{
						id:            "old-cert",
						domains:       []string{domain},
						notAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
						allowDownload: true,
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   "old-fingerprint",
					NotAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				deleted = append(deleted, certificateIDs...)
				return []string{"task-1"}, nil
			},
			describeDeleteTaskResultsFunc: func(ctx context.Context, taskIDs []string) ([]deleteTaskResult, error) {
				return []deleteTaskResult{{
					taskID:        "task-1",
					certificateID: "old-cert",
					status:        1,
				}}, nil
			},
		}

		err := provider.CleanupOldCertificates(context.Background(), live.Domain, keep, live, providerpkg.CleanupOptions{
			ManagedDomains: []string{live.Domain},
		})
		if err != nil {
			t.Fatalf("CleanupOldCertificates() error = %v", err)
		}
		if len(deleted) != 1 || deleted[0] != "old-cert" {
			t.Fatalf("deleted = %#v, want %#v", deleted, []string{"old-cert"})
		}
	})

	t.Run("skips shared certificates", func(t *testing.T) {
		deleted := false
		provider := &Provider{
			cfg: Config{
				AutoApply:                 AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
				AutoDeleteOldCertificates: true,
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return []certificateRecord{
					{
						id:            "shared-old-cert",
						domains:       []string{domain, "api.yourdomain.com"},
						notAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
						allowDownload: true,
					},
				}, nil
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				deleted = true
				return nil, nil
			},
		}

		err := provider.CleanupOldCertificates(context.Background(), live.Domain, keep, live, providerpkg.CleanupOptions{
			ManagedDomains: []string{live.Domain, "api.yourdomain.com"},
		})
		if err != nil {
			t.Fatalf("CleanupOldCertificates() error = %v", err)
		}
		if deleted {
			t.Fatal("DeleteCertificates should not be called for shared certificates")
		}
	})

	t.Run("skips certificate matching live fingerprint", func(t *testing.T) {
		deleted := false
		provider := &Provider{
			cfg: Config{
				AutoApply:                 AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
				AutoDeleteOldCertificates: true,
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return []certificateRecord{
					{
						id:            "live-old-cert",
						domains:       []string{domain},
						notAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
						allowDownload: true,
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   live.Fingerprint,
					NotAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				deleted = true
				return nil, nil
			},
		}

		err := provider.CleanupOldCertificates(context.Background(), live.Domain, keep, live, providerpkg.CleanupOptions{
			ManagedDomains: []string{live.Domain},
		})
		if err != nil {
			t.Fatalf("CleanupOldCertificates() error = %v", err)
		}
		if deleted {
			t.Fatal("DeleteCertificates should not be called when candidate matches live fingerprint")
		}
	})

	t.Run("skips certificate when fingerprint verification fails", func(t *testing.T) {
		deleted := false
		provider := &Provider{
			cfg: Config{
				AutoApply:                 AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
				AutoDeleteOldCertificates: true,
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return []certificateRecord{
					{
						id:            "broken-old-cert",
						domains:       []string{domain},
						notAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
						allowDownload: true,
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return nil, errors.New("download failed")
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				deleted = true
				return nil, nil
			},
		}

		err := provider.CleanupOldCertificates(context.Background(), live.Domain, keep, live, providerpkg.CleanupOptions{
			ManagedDomains: []string{live.Domain},
		})
		if err != nil {
			t.Fatalf("CleanupOldCertificates() error = %v", err)
		}
		if deleted {
			t.Fatal("DeleteCertificates should not be called when fingerprint verification fails")
		}
	})

	t.Run("returns error when delete task fails", func(t *testing.T) {
		provider := &Provider{
			cfg: Config{
				AutoApply:                 AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
				AutoDeleteOldCertificates: true,
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return []certificateRecord{
					{
						id:            "old-cert",
						domains:       []string{domain},
						notAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
						allowDownload: true,
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   "old-fingerprint",
					NotAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				return []string{"task-1"}, nil
			},
			describeDeleteTaskResultsFunc: func(ctx context.Context, taskIDs []string) ([]deleteTaskResult, error) {
				return []deleteTaskResult{{
					taskID:        "task-1",
					certificateID: "old-cert",
					status:        4,
					err:           "resource still bound",
				}}, nil
			},
		}

		err := provider.CleanupOldCertificates(context.Background(), live.Domain, keep, live, providerpkg.CleanupOptions{
			ManagedDomains: []string{live.Domain},
		})
		if err == nil {
			t.Fatal("CleanupOldCertificates() expected error")
		}
	})
}

func TestProviderCleanupUnusedOldCertificates(t *testing.T) {
	live := &providerpkg.ObservedCertificate{
		Domain:      "doc.yourdomain.com",
		Fingerprint: "live-fingerprint",
		NotAfter:    time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}

	t.Run("finds keep certificate from live fingerprint and deletes older ones", func(t *testing.T) {
		var deleted []string
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return []certificateRecord{
					{
						id:            "keep-cert",
						domains:       []string{domain},
						notAfter:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
						allowDownload: true,
					},
					{
						id:            "old-cert",
						domains:       []string{domain},
						notAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
						allowDownload: true,
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				fingerprint := "old-fingerprint"
				notAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				if certificateID == "keep-cert" {
					fingerprint = live.Fingerprint
					notAfter = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
				}
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   fingerprint,
					NotAfter:      notAfter,
				}, nil
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				deleted = append(deleted, certificateIDs...)
				return nil, nil
			},
		}

		err := provider.CleanupUnusedOldCertificates(context.Background(), live.Domain, live, providerpkg.CleanupOptions{
			ManagedDomains: []string{live.Domain},
		})
		if err != nil {
			t.Fatalf("CleanupUnusedOldCertificates() error = %v", err)
		}
		if len(deleted) != 1 || deleted[0] != "old-cert" {
			t.Fatalf("deleted = %#v, want %#v", deleted, []string{"old-cert"})
		}
	})

	t.Run("skips cleanup when no provider certificate matches live fingerprint", func(t *testing.T) {
		deleted := false
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
			},
			listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
				return []certificateRecord{
					{
						id:            "other-cert",
						domains:       []string{domain},
						notAfter:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
						allowDownload: true,
					},
				}, nil
			},
			downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
				return &providerpkg.CertificateMaterial{
					CertificateID: certificateID,
					Fingerprint:   "other-fingerprint",
					NotAfter:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				deleted = true
				return nil, nil
			},
		}

		err := provider.CleanupUnusedOldCertificates(context.Background(), live.Domain, live, providerpkg.CleanupOptions{
			ManagedDomains: []string{live.Domain},
		})
		if err != nil {
			t.Fatalf("CleanupUnusedOldCertificates() error = %v", err)
		}
		if deleted {
			t.Fatal("DeleteCertificates should not be called when keep certificate cannot be identified")
		}
	})
}

func TestProviderListUnusedOldCertificateCleanupCandidates(t *testing.T) {
	live := &providerpkg.ObservedCertificate{
		Domain:      "doc.yourdomain.com",
		Fingerprint: "live-fingerprint",
		NotAfter:    time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	deleted := false
	provider := &Provider{
		listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
			return []certificateRecord{
				{
					id:            "keep-cert",
					domain:        domain,
					domains:       []string{domain},
					notAfter:      time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
					allowDownload: true,
				},
				{
					id:            "old-cert",
					domain:        domain,
					domains:       []string{domain, "alt.yourdomain.com"},
					notAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
					allowDownload: true,
				},
			}, nil
		},
		downloadCertificateFunc: func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
			fingerprint := "old-fingerprint"
			notAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			if certificateID == "keep-cert" {
				fingerprint = live.Fingerprint
				notAfter = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
			}
			return &providerpkg.CertificateMaterial{
				CertificateID: certificateID,
				Fingerprint:   fingerprint,
				NotAfter:      notAfter,
			}, nil
		},
		deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
			deleted = true
			return nil, nil
		},
	}

	candidates, err := provider.ListUnusedOldCertificateCleanupCandidates(context.Background(), live.Domain, live, providerpkg.CleanupOptions{
		ManagedDomains: []string{live.Domain},
	})
	if err != nil {
		t.Fatalf("ListUnusedOldCertificateCleanupCandidates() error = %v", err)
	}
	if deleted {
		t.Fatal("DeleteCertificates should not be called while listing candidates")
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v, want 1", candidates)
	}
	candidate := candidates[0]
	if candidate.Provider != "tencentcloud" || candidate.CleanupType != providerpkg.CleanupTypeConfiguredOld || candidate.Domain != live.Domain || candidate.CertificateID != "old-cert" {
		t.Fatalf("candidate = %#v, want configured-old old-cert for %s", candidate, live.Domain)
	}
	if candidate.NotAfter != time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("candidate.NotAfter = %s, want 2026-01-01", candidate.NotAfter)
	}
	if !candidate.CurrentNotAfter.Equal(live.NotAfter) {
		t.Fatalf("candidate.CurrentNotAfter = %s, want %s", candidate.CurrentNotAfter, live.NotAfter)
	}
	if len(candidate.CertificateDomains) != 2 || candidate.CertificateDomains[0] != "alt.yourdomain.com" || candidate.CertificateDomains[1] != live.Domain {
		t.Fatalf("candidate.CertificateDomains = %#v, want sorted metadata domains", candidate.CertificateDomains)
	}
}

func TestProviderCleanupExpiredCertificates(t *testing.T) {
	var deleted []string
	provider := &Provider{
		cfg: Config{
			AutoApply: AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
		},
		listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
			return []certificateRecord{
				{
					id:       "expired-cert-1",
					notAfter: time.Now().Add(-24 * time.Hour),
				},
				{
					id:       "valid-cert",
					notAfter: time.Now().Add(24 * time.Hour),
				},
				{
					id:       "expired-cert-2",
					notAfter: time.Now().Add(-48 * time.Hour),
				},
			}, nil
		},
		deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
			deleted = append(deleted, certificateIDs...)
			return nil, nil
		},
	}

	err := provider.CleanupExpiredCertificates(context.Background())
	if err != nil {
		t.Fatalf("CleanupExpiredCertificates() error = %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted = %#v, want 2 expired certificates", deleted)
	}
}

func TestProviderListExpiredCertificateCleanupCandidates(t *testing.T) {
	expiredAt := time.Now().Add(-24 * time.Hour)
	provider := &Provider{
		listCertificatesFunc: func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
			return []certificateRecord{
				{
					id:       "expired-cert",
					domain:   "doc.yourdomain.com",
					domains:  []string{"doc.yourdomain.com", "alt.yourdomain.com"},
					notAfter: expiredAt,
				},
				{
					id:       "valid-cert",
					domain:   "valid.yourdomain.com",
					notAfter: time.Now().Add(24 * time.Hour),
				},
			}, nil
		},
		deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
			t.Fatal("DeleteCertificates should not be called while listing candidates")
			return nil, nil
		},
	}

	candidates, err := provider.ListExpiredCertificateCleanupCandidates(context.Background())
	if err != nil {
		t.Fatalf("ListExpiredCertificateCleanupCandidates() error = %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v, want 1", candidates)
	}
	candidate := candidates[0]
	if candidate.Provider != "tencentcloud" || candidate.CleanupType != providerpkg.CleanupTypeAllExpired || candidate.Domain != "doc.yourdomain.com" || candidate.CertificateID != "expired-cert" {
		t.Fatalf("candidate = %#v, want expired-cert metadata", candidate)
	}
	if !candidate.NotAfter.Equal(expiredAt) {
		t.Fatalf("candidate.NotAfter = %s, want %s", candidate.NotAfter, expiredAt)
	}
	if !candidate.CurrentNotAfter.IsZero() {
		t.Fatalf("candidate.CurrentNotAfter = %s, want zero", candidate.CurrentNotAfter)
	}
	if len(candidate.CertificateDomains) != 2 || candidate.CertificateDomains[0] != "alt.yourdomain.com" || candidate.CertificateDomains[1] != "doc.yourdomain.com" {
		t.Fatalf("candidate.CertificateDomains = %#v, want sorted metadata domains", candidate.CertificateDomains)
	}
}

func TestProviderDeleteCleanupCandidates(t *testing.T) {
	t.Run("deletes listed candidates", func(t *testing.T) {
		var deleted []string
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				deleted = append(deleted, certificateIDs...)
				return nil, nil
			},
		}

		err := provider.DeleteCleanupCandidates(context.Background(), []providerpkg.CleanupCandidate{
			{Provider: "tencentcloud", CertificateID: "cert-1"},
			{Provider: "tencentcloud", CertificateID: "cert-1"},
			{Provider: "tencentcloud", CertificateID: "cert-2"},
		})
		if err != nil {
			t.Fatalf("DeleteCleanupCandidates() error = %v", err)
		}
		if len(deleted) != 2 || deleted[0] != "cert-1" || deleted[1] != "cert-2" {
			t.Fatalf("deleted = %#v, want unique cert-1/cert-2", deleted)
		}
	})

	t.Run("returns error when delete task fails", func(t *testing.T) {
		provider := &Provider{
			cfg: Config{
				AutoApply: AutoApplyConfig{PollInterval: time.Millisecond, PollTimeout: time.Second},
			},
			deleteCertificatesFunc: func(ctx context.Context, certificateIDs []string) ([]string, error) {
				return []string{"task-1"}, nil
			},
			describeDeleteTaskResultsFunc: func(ctx context.Context, taskIDs []string) ([]deleteTaskResult, error) {
				return []deleteTaskResult{{
					taskID:        "task-1",
					certificateID: "cert-1",
					status:        4,
					err:           "resource still bound",
				}}, nil
			},
		}

		err := provider.DeleteCleanupCandidates(context.Background(), []providerpkg.CleanupCandidate{
			{Provider: "tencentcloud", CertificateID: "cert-1"},
		})
		if err == nil {
			t.Fatal("DeleteCleanupCandidates() expected error")
		}
	})
}
