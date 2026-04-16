package main

import (
	"context"
	"errors"
	"sync"
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
	successes   int
	failures    int
	successFunc func(title, content string)
	failureFunc func(title, content string)
}

func (n *fakeUpdaterNotifier) Success(title, content string) {
	n.successes++
	if n.successFunc != nil {
		n.successFunc(title, content)
	}
}

func (n *fakeUpdaterNotifier) Failure(title, content string) {
	n.failures++
	if n.failureFunc != nil {
		n.failureFunc(title, content)
	}
}

type fakeUpdaterProvider struct {
	mu                           sync.Mutex
	calls                        int
	cleanupCalls                 int
	cleanupUnusedCalls           int
	cleanupExpiredCalls          int
	listUnusedCandidatesCalls    int
	listExpiredCandidatesCalls   int
	deleteCleanupCandidatesCalls int
	lastOptions                  providerpkg.ResolveOptions
	lastCleanupOptions           providerpkg.CleanupOptions
	lastCleanupDomain            string
	lastCleanupKeep              *providerpkg.CertificateMaterial
	lastCleanupLive              *providerpkg.ObservedCertificate
	lastCleanupCandidates        []providerpkg.CleanupCandidate
	resolution                   *providerpkg.CertificateResolution
	err                          error
	resolveFunc                  func(ctx context.Context, domain string, current *providerpkg.ObservedCertificate, options providerpkg.ResolveOptions) (*providerpkg.CertificateResolution, error)
	cleanupFunc                  func(ctx context.Context, domain string, keep *providerpkg.CertificateMaterial, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) error
	cleanupUnusedFunc            func(ctx context.Context, domain string, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) error
	cleanupExpiredFunc           func(ctx context.Context) error
	listUnusedCandidatesFunc     func(ctx context.Context, domain string, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) ([]providerpkg.CleanupCandidate, error)
	listExpiredCandidatesFunc    func(ctx context.Context) ([]providerpkg.CleanupCandidate, error)
	deleteCleanupCandidatesFunc  func(ctx context.Context, candidates []providerpkg.CleanupCandidate) error
}

func (p *fakeUpdaterProvider) ResolveCertificate(ctx context.Context, domain string, current *providerpkg.ObservedCertificate, options providerpkg.ResolveOptions) (*providerpkg.CertificateResolution, error) {
	p.mu.Lock()
	p.calls++
	p.lastOptions = options
	resolveFunc := p.resolveFunc
	resolution := p.resolution
	err := p.err
	p.mu.Unlock()

	if resolveFunc != nil {
		return resolveFunc(ctx, domain, current, options)
	}
	if err != nil {
		return nil, err
	}
	return resolution, nil
}

func (p *fakeUpdaterProvider) CleanupOldCertificates(ctx context.Context, domain string, keep *providerpkg.CertificateMaterial, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) error {
	p.mu.Lock()
	p.cleanupCalls++
	p.lastCleanupDomain = domain
	p.lastCleanupKeep = keep
	p.lastCleanupLive = live
	p.lastCleanupOptions = options
	cleanupFunc := p.cleanupFunc
	p.mu.Unlock()

	if cleanupFunc != nil {
		return cleanupFunc(ctx, domain, keep, live, options)
	}
	return nil
}

func (p *fakeUpdaterProvider) CleanupUnusedOldCertificates(ctx context.Context, domain string, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) error {
	p.mu.Lock()
	p.cleanupUnusedCalls++
	p.lastCleanupDomain = domain
	p.lastCleanupLive = live
	p.lastCleanupOptions = options
	cleanupUnusedFunc := p.cleanupUnusedFunc
	p.mu.Unlock()

	if cleanupUnusedFunc != nil {
		return cleanupUnusedFunc(ctx, domain, live, options)
	}
	return nil
}

func (p *fakeUpdaterProvider) CleanupExpiredCertificates(ctx context.Context) error {
	p.mu.Lock()
	p.cleanupExpiredCalls++
	cleanupExpiredFunc := p.cleanupExpiredFunc
	p.mu.Unlock()

	if cleanupExpiredFunc != nil {
		return cleanupExpiredFunc(ctx)
	}
	return nil
}

func (p *fakeUpdaterProvider) ListUnusedOldCertificateCleanupCandidates(ctx context.Context, domain string, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) ([]providerpkg.CleanupCandidate, error) {
	p.mu.Lock()
	p.listUnusedCandidatesCalls++
	p.lastCleanupDomain = domain
	p.lastCleanupLive = live
	p.lastCleanupOptions = options
	listUnusedCandidatesFunc := p.listUnusedCandidatesFunc
	p.mu.Unlock()

	if listUnusedCandidatesFunc != nil {
		return listUnusedCandidatesFunc(ctx, domain, live, options)
	}
	return nil, nil
}

func (p *fakeUpdaterProvider) ListExpiredCertificateCleanupCandidates(ctx context.Context) ([]providerpkg.CleanupCandidate, error) {
	p.mu.Lock()
	p.listExpiredCandidatesCalls++
	listExpiredCandidatesFunc := p.listExpiredCandidatesFunc
	p.mu.Unlock()

	if listExpiredCandidatesFunc != nil {
		return listExpiredCandidatesFunc(ctx)
	}
	return nil, nil
}

func (p *fakeUpdaterProvider) DeleteCleanupCandidates(ctx context.Context, candidates []providerpkg.CleanupCandidate) error {
	p.mu.Lock()
	p.deleteCleanupCandidatesCalls++
	p.lastCleanupCandidates = append([]providerpkg.CleanupCandidate(nil), candidates...)
	deleteCleanupCandidatesFunc := p.deleteCleanupCandidatesFunc
	p.mu.Unlock()

	if deleteCleanupCandidatesFunc != nil {
		return deleteCleanupCandidatesFunc(ctx, candidates)
	}
	return nil
}

type fakeUpdaterDeployer struct {
	deployCalls   int
	globalCalls   int
	deployFunc    func(ctx context.Context, domain DomainConfig, material *CertificateMaterial) (*DeployResult, error)
	runGlobalFunc func(ctx context.Context, commands []string) ([]string, error)
}

func (d *fakeUpdaterDeployer) DeployDomain(ctx context.Context, domain DomainConfig, material *CertificateMaterial) (*DeployResult, error) {
	d.deployCalls++
	if d.deployFunc != nil {
		return d.deployFunc(ctx, domain, material)
	}
	return &DeployResult{}, nil
}

func (d *fakeUpdaterDeployer) RunGlobalCommands(ctx context.Context, commands []string) ([]string, error) {
	d.globalCalls++
	if d.runGlobalFunc != nil {
		return d.runGlobalFunc(ctx, commands)
	}
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
	if provider.cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0 when cleanup disabled", provider.cleanupCalls)
	}
}

func TestUpdaterRunOnceStartsCleanupAfterVerifyWhenEnabled(t *testing.T) {
	cleanupCalled := make(chan struct{}, 1)
	provider := &fakeUpdaterProvider{
		resolution: &providerpkg.CertificateResolution{
			Material: &providerpkg.CertificateMaterial{
				CertificateID: "forced-cert",
				Fingerprint:   "forced-fingerprint",
				NotAfter:      time.Now().Add(60 * 24 * time.Hour),
			},
		},
		cleanupFunc: func(ctx context.Context, domain string, keep *providerpkg.CertificateMaterial, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) error {
			select {
			case cleanupCalled <- struct{}{}:
			default:
			}
			return nil
		},
	}
	notifier := &fakeUpdaterNotifier{}
	updater := &Updater{
		cfg: &Config{
			Alert: AlertConfig{BeforeExpired: 10 * 24 * time.Hour},
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{AutoDeleteOldCertificatesV: true},
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
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: expectedFingerprint,
				NotAfter:    time.Now().Add(60 * 24 * time.Hour),
			}, nil
		},
	}

	result := updater.RunOnce(CheckOptions{Force: true})
	if result.SuccessfulUpdates != 1 || result.Failures != 0 {
		t.Fatalf("RunOnce() = %#v, want one successful update", result)
	}
	select {
	case <-cleanupCalled:
	case <-time.After(time.Second):
		t.Fatal("cleanup was not started")
	}
	if provider.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", provider.cleanupCalls)
	}
	if provider.lastCleanupDomain != "example.com" {
		t.Fatalf("cleanup domain = %q, want %q", provider.lastCleanupDomain, "example.com")
	}
	if !provider.lastCleanupOptions.Force {
		t.Fatal("cleanup Force = false, want true")
	}
	if notifier.successes != 1 {
		t.Fatalf("success notifications = %d, want 1", notifier.successes)
	}
}

func TestUpdaterRunOnceWaitsForNotificationBeforeNextDomain(t *testing.T) {
	successStarted := make(chan struct{}, 1)
	releaseNotification := make(chan struct{})
	secondResolveStarted := make(chan struct{}, 1)

	provider := &fakeUpdaterProvider{
		resolveFunc: func(ctx context.Context, domain string, current *providerpkg.ObservedCertificate, options providerpkg.ResolveOptions) (*providerpkg.CertificateResolution, error) {
			if domain == "api.example.com" {
				select {
				case secondResolveStarted <- struct{}{}:
				default:
				}
			}
			return &providerpkg.CertificateResolution{
				Material: &providerpkg.CertificateMaterial{
					CertificateID: domain + "-cert",
					Fingerprint:   domain + "-fingerprint",
					NotAfter:      time.Now().Add(60 * 24 * time.Hour),
				},
			}, nil
		},
	}
	notifier := &fakeUpdaterNotifier{
		successFunc: func(title, content string) {
			if title == "Certificate Updated" && content != "" {
				select {
				case successStarted <- struct{}{}:
				default:
				}
				<-releaseNotification
			}
		},
	}
	updater := &Updater{
		cfg: &Config{
			Alert: AlertConfig{BeforeExpired: 10 * 24 * time.Hour},
			GlobalPostCommands: []string{
				"nginx -s reload",
			},
			Domains: []DomainConfig{
				{Domain: "doc.example.com", EffectiveProvider: ProviderTencentCloud},
				{Domain: "api.example.com", EffectiveProvider: ProviderTencentCloud},
			},
		},
		notifier:  notifier,
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		deployer:  &fakeUpdaterDeployer{},
		ctx:       context.Background(),
		probeCertificate: func(ctx context.Context, domain string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: "current-" + domain,
				NotAfter:    time.Now().Add(24 * time.Hour),
			}, nil
		},
		verifyDeployment: func(ctx context.Context, domain, expectedFingerprint string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: expectedFingerprint,
				NotAfter:    time.Now().Add(60 * 24 * time.Hour),
			}, nil
		},
	}

	done := make(chan CheckResult, 1)
	go func() {
		done <- updater.RunOnce(CheckOptions{Force: true})
	}()

	select {
	case <-successStarted:
	case <-time.After(time.Second):
		t.Fatal("first success notification did not start")
	}

	select {
	case <-secondResolveStarted:
		t.Fatal("second domain started before first success notification completed")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseNotification)

	select {
	case <-secondResolveStarted:
	case <-time.After(time.Second):
		t.Fatal("second domain did not start after notification completed")
	}

	result := <-done
	if result.SuccessfulUpdates != 2 || result.Failures != 0 {
		t.Fatalf("RunOnce() = %#v, want two successful updates", result)
	}
}

func TestUpdaterRunOnceStopsAfterGlobalCommandFailure(t *testing.T) {
	provider := &fakeUpdaterProvider{
		resolveFunc: func(ctx context.Context, domain string, current *providerpkg.ObservedCertificate, options providerpkg.ResolveOptions) (*providerpkg.CertificateResolution, error) {
			return &providerpkg.CertificateResolution{
				Material: &providerpkg.CertificateMaterial{
					CertificateID: domain + "-cert",
					Fingerprint:   domain + "-fingerprint",
					NotAfter:      time.Now().Add(60 * 24 * time.Hour),
				},
			}, nil
		},
	}
	deployer := &fakeUpdaterDeployer{
		runGlobalFunc: func(ctx context.Context, commands []string) ([]string, error) {
			return nil, errors.New("reload failed")
		},
	}
	notifier := &fakeUpdaterNotifier{}
	verifyCalls := 0
	updater := &Updater{
		cfg: &Config{
			Alert: AlertConfig{BeforeExpired: 10 * 24 * time.Hour},
			GlobalPostCommands: []string{
				"nginx -s reload",
			},
			ProviderConfigs: ProviderConfigs{
				TencentCloud: TencentCloudConfig{AutoDeleteOldCertificatesV: true},
			},
			Domains: []DomainConfig{
				{Domain: "doc.example.com", EffectiveProvider: ProviderTencentCloud},
				{Domain: "api.example.com", EffectiveProvider: ProviderTencentCloud},
			},
		},
		notifier:  notifier,
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		deployer:  deployer,
		ctx:       context.Background(),
		probeCertificate: func(ctx context.Context, domain string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: "current-" + domain,
				NotAfter:    time.Now().Add(24 * time.Hour),
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
	if result.SuccessfulUpdates != 0 {
		t.Fatalf("SuccessfulUpdates = %d, want 0", result.SuccessfulUpdates)
	}
	if result.Failures != 1 {
		t.Fatalf("Failures = %d, want 1", result.Failures)
	}
	if verifyCalls != 0 {
		t.Fatalf("verify calls = %d, want 0", verifyCalls)
	}
	if provider.cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0", provider.cleanupCalls)
	}
	if notifier.failures != 1 {
		t.Fatalf("failure notifications = %d, want 1", notifier.failures)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1 because second domain should not start", provider.calls)
	}
}

func TestUpdaterCleanupUnusedOldCertificates(t *testing.T) {
	provider := &fakeUpdaterProvider{}
	updater := &Updater{
		cfg: &Config{
			Domains: []DomainConfig{
				{Domain: "doc.example.com", EffectiveProvider: ProviderTencentCloud},
				{Domain: "api.example.com", EffectiveProvider: ProviderTencentCloud},
			},
		},
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		ctx:       context.Background(),
		probeCertificate: func(ctx context.Context, domain string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: "live-" + domain,
				NotAfter:    time.Now().Add(24 * time.Hour),
			}, nil
		},
	}

	err := updater.CleanupUnusedOldCertificates()
	if err != nil {
		t.Fatalf("CleanupUnusedOldCertificates() error = %v", err)
	}
	if provider.cleanupUnusedCalls != 2 {
		t.Fatalf("cleanupUnusedCalls = %d, want 2", provider.cleanupUnusedCalls)
	}
	if len(provider.lastCleanupOptions.ManagedDomains) != 2 {
		t.Fatalf("ManagedDomains = %#v, want 2 entries", provider.lastCleanupOptions.ManagedDomains)
	}
}

func TestUpdaterCleanupExpiredCertificates(t *testing.T) {
	provider := &fakeUpdaterProvider{}
	updater := &Updater{
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		ctx:       context.Background(),
	}

	err := updater.CleanupExpiredCertificates()
	if err != nil {
		t.Fatalf("CleanupExpiredCertificates() error = %v", err)
	}
	if provider.cleanupExpiredCalls != 1 {
		t.Fatalf("cleanupExpiredCalls = %d, want 1", provider.cleanupExpiredCalls)
	}
}

func TestUpdaterBuildCleanupPlanConfiguredOld(t *testing.T) {
	provider := &fakeUpdaterProvider{
		listUnusedCandidatesFunc: func(ctx context.Context, domain string, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) ([]providerpkg.CleanupCandidate, error) {
			return []providerpkg.CleanupCandidate{{
				CleanupType:   providerpkg.CleanupTypeConfiguredOld,
				Domain:        domain,
				CertificateID: "old-" + domain,
				NotAfter:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			}}, nil
		},
	}
	updater := &Updater{
		cfg: &Config{
			Domains: []DomainConfig{
				{Domain: "doc.example.com", EffectiveProvider: ProviderTencentCloud},
				{Domain: "api.example.com", EffectiveProvider: ProviderTencentCloud},
			},
		},
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		ctx:       context.Background(),
		probeCertificate: func(ctx context.Context, domain string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: "live-" + domain,
				NotAfter:    time.Now().Add(24 * time.Hour),
			}, nil
		},
	}

	candidates, err := updater.BuildCleanupPlan(true, false)
	if err != nil {
		t.Fatalf("BuildCleanupPlan() error = %v", err)
	}
	if provider.listUnusedCandidatesCalls != 2 {
		t.Fatalf("listUnusedCandidatesCalls = %d, want 2", provider.listUnusedCandidatesCalls)
	}
	if len(provider.lastCleanupOptions.ManagedDomains) != 2 {
		t.Fatalf("ManagedDomains = %#v, want 2 entries", provider.lastCleanupOptions.ManagedDomains)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %#v, want 2", candidates)
	}
	for _, candidate := range candidates {
		if candidate.Provider != ProviderTencentCloud {
			t.Fatalf("candidate.Provider = %q, want %q", candidate.Provider, ProviderTencentCloud)
		}
	}
}

func TestUpdaterBuildCleanupPlanExpired(t *testing.T) {
	provider := &fakeUpdaterProvider{
		listExpiredCandidatesFunc: func(ctx context.Context) ([]providerpkg.CleanupCandidate, error) {
			return []providerpkg.CleanupCandidate{{
				CleanupType:   providerpkg.CleanupTypeAllExpired,
				Domain:        "doc.example.com",
				CertificateID: "expired-cert",
			}}, nil
		},
	}
	updater := &Updater{
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		ctx:       context.Background(),
	}

	candidates, err := updater.BuildCleanupPlan(false, true)
	if err != nil {
		t.Fatalf("BuildCleanupPlan() error = %v", err)
	}
	if provider.listExpiredCandidatesCalls != 1 {
		t.Fatalf("listExpiredCandidatesCalls = %d, want 1", provider.listExpiredCandidatesCalls)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v, want 1", candidates)
	}
	if candidates[0].Provider != ProviderTencentCloud || candidates[0].CertificateID != "expired-cert" {
		t.Fatalf("candidate = %#v, want provider-filled expired-cert", candidates[0])
	}
}

func TestUpdaterBuildCleanupPlanDeduplicatesCandidates(t *testing.T) {
	currentExpiresAt := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	provider := &fakeUpdaterProvider{
		listUnusedCandidatesFunc: func(ctx context.Context, domain string, live *providerpkg.ObservedCertificate, options providerpkg.CleanupOptions) ([]providerpkg.CleanupCandidate, error) {
			return []providerpkg.CleanupCandidate{{
				Provider:           ProviderTencentCloud,
				CleanupType:        providerpkg.CleanupTypeConfiguredOld,
				Domain:             domain,
				CertificateID:      "same-cert",
				CertificateDomains: []string{domain},
				CurrentNotAfter:    live.NotAfter,
			}}, nil
		},
		listExpiredCandidatesFunc: func(ctx context.Context) ([]providerpkg.CleanupCandidate, error) {
			return []providerpkg.CleanupCandidate{{
				Provider:           ProviderTencentCloud,
				CleanupType:        providerpkg.CleanupTypeAllExpired,
				Domain:             "doc.example.com",
				CertificateID:      "same-cert",
				CertificateDomains: []string{"alt.example.com"},
			}}, nil
		},
	}
	updater := &Updater{
		cfg: &Config{
			Domains: []DomainConfig{
				{Domain: "doc.example.com", EffectiveProvider: ProviderTencentCloud},
			},
		},
		providers: map[string]providerpkg.Provider{ProviderTencentCloud: provider},
		ctx:       context.Background(),
		probeCertificate: func(ctx context.Context, domain string) (*ObservedCertificate, error) {
			return &ObservedCertificate{
				Domain:      domain,
				Fingerprint: "live-" + domain,
				NotAfter:    currentExpiresAt,
			}, nil
		},
	}

	candidates, err := updater.BuildCleanupPlan(true, true)
	if err != nil {
		t.Fatalf("BuildCleanupPlan() error = %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v, want 1 deduplicated candidate", candidates)
	}
	candidate := candidates[0]
	if candidate.CleanupType != "configured-old,all-expired" {
		t.Fatalf("CleanupType = %q, want configured-old,all-expired", candidate.CleanupType)
	}
	if len(candidate.CertificateDomains) != 2 || candidate.CertificateDomains[0] != "alt.example.com" || candidate.CertificateDomains[1] != "doc.example.com" {
		t.Fatalf("CertificateDomains = %#v, want merged sorted domains", candidate.CertificateDomains)
	}
	if !candidate.CurrentNotAfter.Equal(currentExpiresAt) {
		t.Fatalf("CurrentNotAfter = %s, want %s", candidate.CurrentNotAfter, currentExpiresAt)
	}
}
