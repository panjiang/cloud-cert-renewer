package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	providerpkg "github.com/panjiang/cert-renewer/provider"
	"go.uber.org/zap"
)

type Updater struct {
	cfg              *Config
	notifier         Notifier
	providers        map[string]providerpkg.Provider
	deployer         domainDeployer
	probeCertificate probeCertificateFunc
	verifyDeployment verifyDeploymentFunc
	ctx              context.Context
}

type CheckOptions struct {
	Force bool
}

type CheckResult struct {
	Domains           int
	SuccessfulUpdates int
	Failures          int
}

type domainDeployer interface {
	DeployDomain(ctx context.Context, domain DomainConfig, material *CertificateMaterial) (*DeployResult, error)
	RunGlobalCommands(ctx context.Context, commands []string) ([]string, error)
}

type probeCertificateFunc func(ctx context.Context, domain string) (*ObservedCertificate, error)
type verifyDeploymentFunc func(ctx context.Context, domain, expectedFingerprint string) (*ObservedCertificate, error)

func NewUpdater(cfg *Config, notifier Notifier) (*Updater, func(), error) {
	ctx, cancel := context.WithCancel(context.Background())

	providers, err := NewProviders(cfg)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	return &Updater{
			cfg:              cfg,
			notifier:         notifier,
			providers:        providers,
			deployer:         NewLocalDeployer(),
			probeCertificate: probeTLSCertificate,
			verifyDeployment: verifyExternalDeployment,
			ctx:              ctx,
		}, func() {
			cancel()
			zap.L().Info("stopped")
		}, nil
}

func (u *Updater) Run() {
	ticker := time.NewTicker(u.cfg.Alert.CheckInterval)
	defer ticker.Stop()

	zap.L().Info("started", zap.Duration("interval", u.cfg.Alert.CheckInterval), zap.Bool("force", false))
	for {
		u.checkOnce(u.ctx, CheckOptions{})
		select {
		case <-ticker.C:
		case <-u.ctx.Done():
			return
		}
	}
}

func (u *Updater) RunOnce(options CheckOptions) CheckResult {
	return u.checkOnce(u.ctx, options)
}

func (u *Updater) checkOnce(ctx context.Context, options CheckOptions) CheckResult {
	result := CheckResult{Domains: len(u.cfg.Domains)}

	zap.L().Info("certificate check round started",
		zap.Int("domains", len(u.cfg.Domains)),
		zap.Bool("force", options.Force))

	for _, domain := range u.cfg.Domains {
		updated, ok := u.handleDomain(ctx, domain, options)
		if !ok {
			result.Failures++
			zap.L().Warn("stopping certificate check round because domain update failed",
				zap.String("domain", domain.Domain),
				zap.String("provider", domain.EffectiveProvider),
				zap.Int("successfulUpdates", result.SuccessfulUpdates),
				zap.Int("failures", result.Failures))
			zap.L().Info("certificate check round finished",
				zap.Int("domains", len(u.cfg.Domains)),
				zap.Int("successfulUpdates", result.SuccessfulUpdates),
				zap.Int("failures", result.Failures),
				zap.Bool("force", options.Force))
			return result
		}
		if updated {
			result.SuccessfulUpdates++
		}
	}

	zap.L().Info("certificate check round finished",
		zap.Int("domains", len(u.cfg.Domains)),
		zap.Int("successfulUpdates", result.SuccessfulUpdates),
		zap.Int("failures", result.Failures),
		zap.Bool("force", options.Force))
	return result
}

func (u *Updater) handleDomain(ctx context.Context, domain DomainConfig, options CheckOptions) (bool, bool) {
	zap.L().Info("processing domain",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.Bool("force", options.Force))

	currentCert, err := u.probeCertificate(ctx, domain.Domain)
	if err != nil {
		zap.L().Error("probe current certificate failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", "probe_current_certificate"),
			zap.String("provider", domain.EffectiveProvider))
		u.notifier.Failure("Certificate Update Failed",
			formatFailureNotification(domain.Domain, "probe_current_certificate", err))
		return false, false
	}

	remaining := time.Until(currentCert.NotAfter)
	zap.L().Info("checked current certificate",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.Int64("daysRemaining", int64(remaining.Hours())/24),
		zap.Time("notAfter", currentCert.NotAfter),
		zap.String("fingerprint", currentCert.Fingerprint))

	if options.Force {
		zap.L().Info("force mode enabled, skipping renewal window check",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider),
			zap.Duration("remaining", remaining),
			zap.Duration("beforeExpired", u.cfg.Alert.BeforeExpired))
	} else if remaining > u.cfg.Alert.BeforeExpired {
		zap.L().Info("certificate is not in renewal window",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider),
			zap.Duration("remaining", remaining),
			zap.Duration("beforeExpired", u.cfg.Alert.BeforeExpired))
		return false, true
	}

	if options.Force {
		zap.L().Info("continuing with forced certificate selection",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider),
			zap.Duration("remaining", remaining),
			zap.Duration("beforeExpired", u.cfg.Alert.BeforeExpired))
	} else {
		zap.L().Info("certificate entered renewal window",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider),
			zap.Duration("remaining", remaining),
			zap.Duration("beforeExpired", u.cfg.Alert.BeforeExpired))
	}

	provider, err := resolveProvider(u.providers, domain)
	if err != nil {
		zap.L().Error("resolve provider failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", "resolve_provider"),
			zap.String("provider", domain.EffectiveProvider))
		u.notifier.Failure("Certificate Update Failed",
			formatFailureNotification(domain.Domain, "resolve_provider", err))
		return false, false
	}

	zap.L().Info("querying provider for certificate",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.Bool("force", options.Force))
	resolution, err := provider.ResolveCertificate(ctx, domain.Domain, toProviderObservedCertificate(currentCert), providerpkg.ResolveOptions{Force: options.Force})
	if err != nil {
		stage := "query_or_download"
		var stageErr *providerpkg.StageError
		if errors.As(err, &stageErr) {
			stage = stageErr.Stage
		}
		zap.L().Error("query or download certificate failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", stage),
			zap.String("provider", domain.EffectiveProvider))
		u.notifier.Failure("Certificate Update Failed",
			formatFailureNotification(domain.Domain, stage, err))
		return false, false
	}
	if resolution == nil || (resolution.Material == nil && resolution.Pending == nil) {
		message := "no newer provider certificate"
		if options.Force {
			message = "no provider certificate available for forced deployment"
		}
		zap.L().Info(message,
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider))
		return false, true
	}
	if resolution.Pending != nil {
		zap.L().Warn("certificate issuance is still pending",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider),
			zap.String("certificateId", resolution.Pending.CertificateID),
			zap.Uint64("status", resolution.Pending.Status),
			zap.String("statusName", resolution.Pending.StatusName),
			zap.String("statusMsg", resolution.Pending.StatusMsg),
			zap.String("verifyType", resolution.Pending.VerifyType))
		return false, true
	}

	nextCert := fromProviderCertificateMaterial(resolution.Material)

	zap.L().Info("deploying selected certificate",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", nextCert.CertificateID),
		zap.Time("notAfter", nextCert.NotAfter),
		zap.String("fingerprint", nextCert.Fingerprint),
		zap.String("certPath", domain.CertPath),
		zap.String("keyPath", domain.KeyPath))
	result, err := u.deployer.DeployDomain(ctx, domain, nextCert)
	if err != nil {
		stage := "deploy_local_files"
		var stageErr *DeployStageError
		if errors.As(err, &stageErr) {
			stage = stageErr.Stage
		}
		zap.L().Error("deploy local files failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", stage),
			zap.String("provider", domain.EffectiveProvider),
			zap.String("certificateId", nextCert.CertificateID),
			zap.String("certPath", domain.CertPath),
			zap.String("keyPath", domain.KeyPath))
		u.notifier.Failure("Certificate Update Failed",
			formatFailureNotification(domain.Domain, stage, err))
		return false, false
	}

	if err := u.runGlobalPostCommands(ctx, domain, nextCert, result); err != nil {
		return false, false
	}

	observed, err := u.verifyDeployedDomain(ctx, domain, nextCert, result)
	if err != nil {
		return false, false
	}

	if u.cfg.ProviderConfigs.TencentCloud.AutoDeleteOldCertificatesV {
		u.startCleanupTask(domain, provider, nextCert, observed, options)
	}

	u.notifier.Success("Certificate Updated",
		formatSuccessNotification(domain.Domain, nextCert.CertificateID, observed.NotAfter))
	return true, true
}

func (u *Updater) runGlobalPostCommands(ctx context.Context, domain DomainConfig, nextCert *CertificateMaterial, result *DeployResult) error {
	if len(u.cfg.GlobalPostCommands) == 0 {
		return nil
	}

	zap.L().Info("running global post commands",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", nextCert.CertificateID),
		zap.Int("commands", len(u.cfg.GlobalPostCommands)))
	globalPostCommands, err := u.deployer.RunGlobalCommands(ctx, u.cfg.GlobalPostCommands)
	if err != nil {
		zap.L().Error("global post commands failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", "global_post_commands"),
			zap.String("provider", domain.EffectiveProvider),
			zap.String("certificateId", nextCert.CertificateID),
			zap.Bool("filesChanged", result.FilesChanged))
		u.notifier.Failure("Certificate Update Failed",
			formatFailureNotification(domain.Domain, "global_post_commands", err))
		return err
	}
	zap.L().Info("global post commands completed",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", nextCert.CertificateID),
		zap.Int("commands", len(globalPostCommands)))
	return nil
}

func (u *Updater) verifyDeployedDomain(ctx context.Context, domain DomainConfig, nextCert *CertificateMaterial, result *DeployResult) (*ObservedCertificate, error) {
	zap.L().Info("verifying external deployment",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", nextCert.CertificateID),
		zap.String("expectedFingerprint", nextCert.Fingerprint))
	observed, err := u.verifyDeployment(ctx, domain.Domain, nextCert.Fingerprint)
	if err != nil {
		zap.L().Error("verify external deployment failed",
			zap.Error(err),
			zap.String("domain", domain.Domain),
			zap.String("stage", "verify_external"),
			zap.String("provider", domain.EffectiveProvider),
			zap.String("certificateId", nextCert.CertificateID),
			zap.String("certPath", domain.CertPath),
			zap.String("keyPath", domain.KeyPath),
			zap.Bool("filesChanged", result.FilesChanged))
		u.notifier.Failure("Certificate Update Failed",
			formatFailureNotification(domain.Domain, "verify_external", err))
		return nil, err
	}
	zap.L().Info("external deployment verified",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", nextCert.CertificateID),
		zap.String("fingerprint", observed.Fingerprint),
		zap.String("serial", observed.Serial),
		zap.Time("notAfter", observed.NotAfter),
		zap.Bool("filesChanged", result.FilesChanged))

	return observed, nil
}

func (u *Updater) startCleanupTask(domain DomainConfig, provider providerpkg.Provider, keep *CertificateMaterial, observed *ObservedCertificate, options CheckOptions) {
	ctx := u.ctx
	managedDomains := u.managedDomains()

	zap.L().Info("starting old certificate cleanup task",
		zap.String("domain", domain.Domain),
		zap.String("provider", domain.EffectiveProvider),
		zap.String("certificateId", keep.CertificateID),
		zap.Bool("force", options.Force),
		zap.Int("managedDomains", len(managedDomains)))

	go func() {
		if err := provider.CleanupOldCertificates(ctx, domain.Domain, toProviderCertificateMaterial(keep), toProviderObservedCertificate(observed), providerpkg.CleanupOptions{
			Force:          options.Force,
			ManagedDomains: managedDomains,
		}); err != nil {
			zap.L().Warn("old certificate cleanup task failed",
				zap.Error(err),
				zap.String("domain", domain.Domain),
				zap.String("provider", domain.EffectiveProvider),
				zap.String("certificateId", keep.CertificateID),
				zap.Bool("force", options.Force))
			return
		}
		zap.L().Info("old certificate cleanup task finished",
			zap.String("domain", domain.Domain),
			zap.String("provider", domain.EffectiveProvider),
			zap.String("certificateId", keep.CertificateID),
			zap.Bool("force", options.Force))
	}()
}

func (u *Updater) managedDomains() []string {
	domains := make([]string, 0, len(u.cfg.Domains))
	for _, item := range u.cfg.Domains {
		domains = append(domains, item.Domain)
	}
	return domains
}

func formatSuccessNotification(domain, certificateID string, notAfter time.Time) string {
	return fmt.Sprintf("**Domain**: %s\n**Expires At**: %s\n**Certificate ID**: %s",
		domain,
		notAfter.In(time.Local).Format(time.RFC3339),
		certificateID)
}

func formatFailureNotification(domain, stage string, err error) string {
	return fmt.Sprintf("**Domain**: %s\n**Stage**: %s\n**Error**: %v", domain, stage, err)
}
