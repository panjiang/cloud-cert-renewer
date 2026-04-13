package main

import (
	"context"
	"errors"
	"testing"
	"time"

	providerpkg "github.com/panjiang/cert-renewer/provider"
)

func TestFormatSuccessNotification(t *testing.T) {
	originalLocal := time.Local
	time.Local = time.FixedZone("UTC+8", 8*60*60)
	defer func() {
		time.Local = originalLocal
	}()

	notAfter := time.Date(2026, 5, 1, 2, 3, 4, 0, time.UTC)

	got := formatSuccessNotification("example.com", "cert-123", notAfter)
	want := "**Domain**: example.com\n**Expires At**: 2026-05-01T10:03:04+08:00\n**Certificate ID**: cert-123"
	if got != want {
		t.Fatalf("formatSuccessNotification() = %q, want %q", got, want)
	}
}

func TestFormatFailureNotification(t *testing.T) {
	got := formatFailureNotification("example.com", "verify_external", errors.New("fingerprint mismatch"))
	want := "**Domain**: example.com\n**Stage**: verify_external\n**Error**: fingerprint mismatch"
	if got != want {
		t.Fatalf("formatFailureNotification() = %q, want %q", got, want)
	}
}

type fakeUpdaterNotifier struct {
	successes int
	failures  int
}

func (n *fakeUpdaterNotifier) Success(title, content string) {
	n.successes++
}

func (n *fakeUpdaterNotifier) Failure(title, content string) {
	n.failures++
}

type fakeUpdaterProvider struct {
	calls       int
	lastOptions providerpkg.ResolveOptions
	resolution  *providerpkg.CertificateResolution
	err         error
}

func (p *fakeUpdaterProvider) ResolveCertificate(ctx context.Context, domain string, current *providerpkg.ObservedCertificate, options providerpkg.ResolveOptions) (*providerpkg.CertificateResolution, error) {
	p.calls++
	p.lastOptions = options
	if p.err != nil {
		return nil, p.err
	}
	return p.resolution, nil
}

type fakeUpdaterDeployer struct {
	deployCalls int
	globalCalls int
}

func (d *fakeUpdaterDeployer) DeployDomain(ctx context.Context, domain DomainConfig, material *CertificateMaterial) (*DeployResult, error) {
	d.deployCalls++
	return &DeployResult{}, nil
}

func (d *fakeUpdaterDeployer) RunGlobalCommands(ctx context.Context, commands []string) ([]string, error) {
	d.globalCalls++
	return commands, nil
}

func TestUpdaterRunOnceSkipsProviderOutsideRenewalWindow(t *testing.T) {
	provider := &fakeUpdaterProvider{}
	updater := &Updater{
		cfg: &Config{
			Alert: AlertConfig{BeforeExpired: 10 * 24 * time.Hour},
			Domains: []DomainConfig{
				{
					Domain:            "example.com",
					EffectiveProvider: ProviderTencentCloud,
				},
			},
		},
		notifier:  &fakeUpdaterNotifier{},
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		deployer:  &fakeUpdaterDeployer{},
		ctx:       context.Background(),
		probeCertificate: func(ctx context.Context, domain string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: "current-fingerprint",
				NotAfter:    time.Now().Add(30 * 24 * time.Hour),
			}, nil
		},
		verifyDeployment: func(ctx context.Context, domain, expectedFingerprint string) (*ObservedCertificate, error) {
			t.Fatal("verifyDeployment should not be called when provider is skipped")
			return nil, nil
		},
	}

	result := updater.RunOnce(CheckOptions{})
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d, want 0", provider.calls)
	}
	if result.Failures != 0 {
		t.Fatalf("Failures = %d, want 0", result.Failures)
	}
	if result.SuccessfulUpdates != 0 {
		t.Fatalf("SuccessfulUpdates = %d, want 0", result.SuccessfulUpdates)
	}
}

func TestUpdaterRunOnceForceCallsProviderOutsideRenewalWindow(t *testing.T) {
	provider := &fakeUpdaterProvider{
		resolution: &providerpkg.CertificateResolution{},
	}
	updater := &Updater{
		cfg: &Config{
			Alert: AlertConfig{BeforeExpired: 10 * 24 * time.Hour},
			Domains: []DomainConfig{
				{
					Domain:            "example.com",
					EffectiveProvider: ProviderTencentCloud,
				},
			},
		},
		notifier:  &fakeUpdaterNotifier{},
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		deployer:  &fakeUpdaterDeployer{},
		ctx:       context.Background(),
		probeCertificate: func(ctx context.Context, domain string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: "current-fingerprint",
				NotAfter:    time.Now().Add(30 * 24 * time.Hour),
			}, nil
		},
		verifyDeployment: func(ctx context.Context, domain, expectedFingerprint string) (*ObservedCertificate, error) {
			t.Fatal("verifyDeployment should not be called without a deployed certificate")
			return nil, nil
		},
	}

	result := updater.RunOnce(CheckOptions{Force: true})
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}
	if !provider.lastOptions.Force {
		t.Fatal("ResolveOptions.Force = false, want true")
	}
	if result.Failures != 0 {
		t.Fatalf("Failures = %d, want 0", result.Failures)
	}
}

func TestUpdaterRunOnceForceDeploysAndVerifies(t *testing.T) {
	provider := &fakeUpdaterProvider{
		resolution: &providerpkg.CertificateResolution{
			Material: &providerpkg.CertificateMaterial{
				CertificateID: "forced-cert",
				Fingerprint:   "current-fingerprint",
				NotAfter:      time.Now().Add(60 * 24 * time.Hour),
			},
		},
	}
	deployer := &fakeUpdaterDeployer{}
	notifier := &fakeUpdaterNotifier{}
	verifyCalls := 0
	updater := &Updater{
		cfg: &Config{
			Alert: AlertConfig{BeforeExpired: 10 * 24 * time.Hour},
			GlobalPostCommands: []string{
				"nginx -s reload",
			},
			Domains: []DomainConfig{
				{
					Domain:            "example.com",
					EffectiveProvider: ProviderTencentCloud,
				},
			},
		},
		notifier:  notifier,
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		deployer:  deployer,
		ctx:       context.Background(),
		probeCertificate: func(ctx context.Context, domain string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: "current-fingerprint",
				NotAfter:    time.Now().Add(30 * 24 * time.Hour),
			}, nil
		},
		verifyDeployment: func(ctx context.Context, domain, expectedFingerprint string) (*ObservedCertificate, error) {
			verifyCalls++
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: expectedFingerprint,
				NotAfter:    time.Now().Add(60 * 24 * time.Hour),
			}, nil
		},
	}

	result := updater.RunOnce(CheckOptions{Force: true})
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}
	if deployer.deployCalls != 1 {
		t.Fatalf("deploy calls = %d, want 1", deployer.deployCalls)
	}
	if deployer.globalCalls != 1 {
		t.Fatalf("global command calls = %d, want 1", deployer.globalCalls)
	}
	if verifyCalls != 1 {
		t.Fatalf("verify calls = %d, want 1", verifyCalls)
	}
	if result.SuccessfulUpdates != 1 {
		t.Fatalf("SuccessfulUpdates = %d, want 1", result.SuccessfulUpdates)
	}
	if result.Failures != 0 {
		t.Fatalf("Failures = %d, want 0", result.Failures)
	}
	if notifier.successes != 1 {
		t.Fatalf("success notifications = %d, want 1", notifier.successes)
	}
}
