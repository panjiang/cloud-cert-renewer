package tencentcloud

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	providerpkg "github.com/panjiang/cloud-cert-renewer/provider"
	sslcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	sslapi "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
	"go.uber.org/zap"
)

type Provider struct {
	client     *sslapi.Client
	httpClient *http.Client
	cfg        Config

	listCertificatesFunc    func(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error)
	describeCertificateFunc func(ctx context.Context, certificateID string) (*certificateRecord, error)
	applyCertificateFunc    func(ctx context.Context, domain string) (string, error)
	downloadCertificateFunc func(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error)
	waitFunc                func(ctx context.Context, d time.Duration) error
}

type certificateRecord struct {
	id            string
	domain        string
	domains       []string
	notAfter      time.Time
	insertTime    time.Time
	packageType   string
	verifyType    string
	status        uint64
	statusName    string
	statusMsg     string
	deployable    bool
	allowDownload bool
	isWildcard    bool
}

func New(cfg Config) (*Provider, error) {
	cred := sslcommon.NewCredential(cfg.SecretID, cfg.SecretKey)
	prof := profile.NewClientProfile()
	prof.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, err := sslapi.NewClient(cred, "", prof)
	if err != nil {
		return nil, err
	}
	zap.L().Info("initialized tencent cloud provider")

	return &Provider{
		client: client,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		cfg: cfg,
	}, nil
}

func (c *Provider) ResolveCertificate(ctx context.Context, domain string, current *providerpkg.ObservedCertificate) (*providerpkg.CertificateResolution, error) {
	material, err := c.findLatestDeployableCertificate(ctx, domain, current)
	if err != nil {
		return nil, err
	}
	if material != nil {
		return &providerpkg.CertificateResolution{Material: material}, nil
	}

	if !c.cfg.AutoApply.Enabled {
		zap.L().Info("auto apply disabled after no deployable certificate found",
			zap.String("provider", "tencentcloud"),
			zap.String("domain", domain))
		return &providerpkg.CertificateResolution{}, nil
	}

	if isWildcardDomain(domain) {
		zap.L().Warn("automatic certificate application is not supported for wildcard domains",
			zap.String("provider", "tencentcloud"),
			zap.String("domain", domain))
		return &providerpkg.CertificateResolution{}, nil
	}

	pending, err := c.findPendingCertificate(ctx, domain)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		certificateID, err := c.applyCertificate(ctx, domain)
		if err != nil {
			return nil, &providerpkg.StageError{
				Stage: "apply_certificate",
				Err:   fmt.Errorf("apply certificate: %w", err),
			}
		}
		pending = &providerpkg.PendingCertificate{
			CertificateID: certificateID,
			VerifyType:    "DNS_AUTO",
			StatusMsg:     "PENDING-DCV",
		}
		zap.L().Info("automatic certificate application submitted",
			zap.String("provider", "tencentcloud"),
			zap.String("domain", domain),
			zap.String("certificateId", certificateID))
	}

	return c.waitForIssuedCertificate(ctx, domain, pending.CertificateID)
}

func (c *Provider) findLatestDeployableCertificate(ctx context.Context, domain string, current *providerpkg.ObservedCertificate) (*providerpkg.CertificateMaterial, error) {
	candidates, err := c.listCertificates(ctx, domain, true)
	if err != nil {
		return nil, err
	}
	zap.L().Info("provider candidate query completed",
		zap.String("provider", "tencentcloud"),
		zap.String("domain", domain),
		zap.Int("candidates", len(candidates)))

	for _, candidate := range candidates {
		if candidate.notAfter.Before(current.NotAfter) {
			zap.L().Debug("skipping candidate older than current certificate",
				zap.String("provider", "tencentcloud"),
				zap.String("domain", domain),
				zap.String("certificateId", candidate.id),
				zap.Time("candidateNotAfter", candidate.notAfter),
				zap.Time("currentNotAfter", current.NotAfter))
			continue
		}

		zap.L().Info("downloading candidate certificate",
			zap.String("provider", "tencentcloud"),
			zap.String("domain", domain),
			zap.String("certificateId", candidate.id))
		material, err := c.downloadCertificate(ctx, domain, candidate.id)
		if err != nil {
			return nil, fmt.Errorf("download candidate %s: %w", candidate.id, err)
		}
		if material.Fingerprint == current.Fingerprint {
			zap.L().Debug("skipping candidate with same fingerprint",
				zap.String("provider", "tencentcloud"),
				zap.String("domain", domain),
				zap.String("certificateId", candidate.id),
				zap.String("fingerprint", material.Fingerprint))
			continue
		}
		if material.NotAfter.Before(current.NotAfter) {
			zap.L().Debug("skipping downloaded candidate older than current certificate",
				zap.String("provider", "tencentcloud"),
				zap.String("domain", domain),
				zap.String("certificateId", candidate.id),
				zap.Time("candidateNotAfter", material.NotAfter),
				zap.Time("currentNotAfter", current.NotAfter))
			continue
		}
		zap.L().Info("selected deployable certificate",
			zap.String("provider", "tencentcloud"),
			zap.String("domain", domain),
			zap.String("certificateId", material.CertificateID),
			zap.Time("notAfter", material.NotAfter),
			zap.String("fingerprint", material.Fingerprint))
		return material, nil
	}

	zap.L().Info("no deployable provider certificate found",
		zap.String("provider", "tencentcloud"),
		zap.String("domain", domain))
	return nil, nil
}

func (c *Provider) findPendingCertificate(ctx context.Context, domain string) (*providerpkg.PendingCertificate, error) {
	records, err := c.listCertificates(ctx, domain, false)
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if !isExactDomainMatch(record, domain) || !isAutoApplyFreeDVRecord(record) || !isPendingCertificateRecord(record) {
			continue
		}
		pending := pendingCertificateFromRecord(record)
		zap.L().Info("found existing pending certificate application",
			zap.String("provider", "tencentcloud"),
			zap.String("domain", domain),
			zap.String("certificateId", pending.CertificateID),
			zap.Uint64("status", pending.Status),
			zap.String("statusName", pending.StatusName),
			zap.String("statusMsg", pending.StatusMsg),
			zap.String("verifyType", pending.VerifyType))
		return pending, nil
	}

	return nil, nil
}

func (c *Provider) waitForIssuedCertificate(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateResolution, error) {
	pollCtx, cancel := context.WithTimeout(ctx, c.cfg.AutoApply.PollTimeout)
	defer cancel()

	lastPending := &providerpkg.PendingCertificate{
		CertificateID: certificateID,
		VerifyType:    "DNS_AUTO",
	}

	for {
		record, err := c.describeCertificate(pollCtx, certificateID)
		if err != nil {
			if errors.Is(pollCtx.Err(), context.DeadlineExceeded) {
				zap.L().Warn("certificate issuance poll timed out",
					zap.String("provider", "tencentcloud"),
					zap.String("domain", domain),
					zap.String("certificateId", certificateID),
					zap.Duration("pollTimeout", c.cfg.AutoApply.PollTimeout))
				return &providerpkg.CertificateResolution{Pending: lastPending}, nil
			}
			return nil, fmt.Errorf("describe certificate %s: %w", certificateID, err)
		}

		if isIssuedCertificateRecord(*record) {
			zap.L().Info("certificate issuance completed",
				zap.String("provider", "tencentcloud"),
				zap.String("domain", domain),
				zap.String("certificateId", certificateID),
				zap.Uint64("status", record.status),
				zap.String("statusName", record.statusName),
				zap.String("statusMsg", record.statusMsg))
			material, err := c.downloadCertificate(ctx, domain, certificateID)
			if err != nil {
				return nil, fmt.Errorf("download issued certificate %s: %w", certificateID, err)
			}
			return &providerpkg.CertificateResolution{Material: material}, nil
		}

		if isTerminalFailureCertificateRecord(*record) {
			return nil, &providerpkg.StageError{
				Stage: "wait_certificate_issue",
				Err: fmt.Errorf("certificate %s terminal failure: status=%d statusName=%s statusMsg=%s",
					certificateID, record.status, record.statusName, record.statusMsg),
			}
		}

		lastPending = pendingCertificateFromRecord(*record)
		zap.L().Info("certificate issuance still pending",
			zap.String("provider", "tencentcloud"),
			zap.String("domain", domain),
			zap.String("certificateId", lastPending.CertificateID),
			zap.Uint64("status", lastPending.Status),
			zap.String("statusName", lastPending.StatusName),
			zap.String("statusMsg", lastPending.StatusMsg),
			zap.String("verifyType", lastPending.VerifyType))

		if err := c.wait(pollCtx, c.cfg.AutoApply.PollInterval); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				zap.L().Warn("certificate issuance poll timed out",
					zap.String("provider", "tencentcloud"),
					zap.String("domain", domain),
					zap.String("certificateId", certificateID),
					zap.Duration("pollTimeout", c.cfg.AutoApply.PollTimeout))
				return &providerpkg.CertificateResolution{Pending: lastPending}, nil
			}
			return nil, err
		}
	}
}

func (c *Provider) listCertificates(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
	if c.listCertificatesFunc != nil {
		return c.listCertificatesFunc(ctx, domain, deployableOnly)
	}
	return c.listCertificateRecords(ctx, domain, deployableOnly)
}

func (c *Provider) listCertificateRecords(ctx context.Context, domain string, deployableOnly bool) ([]certificateRecord, error) {
	var records []certificateRecord
	var offset uint64
	const limit uint64 = 100

	zap.L().Info("listing provider certificates",
		zap.String("provider", "tencentcloud"),
		zap.String("domain", domain),
		zap.Bool("deployableOnly", deployableOnly))

	for {
		req := sslapi.NewDescribeCertificatesRequest()
		req.Offset = sslcommon.Uint64Ptr(offset)
		req.Limit = sslcommon.Uint64Ptr(limit)
		req.SearchKey = sslcommon.StringPtr(domain)
		req.CertificateType = sslcommon.StringPtr("SVR")
		req.ExpirationSort = sslcommon.StringPtr("DESC")
		if deployableOnly {
			req.Deployable = sslcommon.Uint64Ptr(1)
			req.CertificateStatus = []*uint64{sslcommon.Uint64Ptr(1)}
		}

		resp, err := c.client.DescribeCertificatesWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("describe certificates: %w", err)
		}
		zap.L().Debug("received provider certificate page",
			zap.String("provider", "tencentcloud"),
			zap.String("domain", domain),
			zap.Uint64("offset", offset),
			zap.Uint64("limit", limit),
			zap.Bool("deployableOnly", deployableOnly))

		for _, item := range resp.Response.Certificates {
			record, ok, err := certificateRecordFromListItem(item)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if deployableOnly {
				if !record.allowDownload || !metadataCoversDomain(domain, record.domains, &record.isWildcard) {
					continue
				}
			} else if !metadataCoversDomain(domain, record.domains, &record.isWildcard) {
				continue
			}
			records = append(records, record)
		}

		if resp.Response.TotalCount == nil || offset+limit >= *resp.Response.TotalCount {
			break
		}
		offset += limit
	}

	slices.SortFunc(records, func(a, b certificateRecord) int {
		if diff := b.notAfter.Compare(a.notAfter); diff != 0 {
			return diff
		}
		return b.insertTime.Compare(a.insertTime)
	})

	zap.L().Info("listed provider certificates",
		zap.String("provider", "tencentcloud"),
		zap.String("domain", domain),
		zap.Bool("deployableOnly", deployableOnly),
		zap.Int("certificates", len(records)))
	return records, nil
}

func certificateRecordFromListItem(item *sslapi.Certificates) (certificateRecord, bool, error) {
	if item == nil || item.CertificateId == nil {
		return certificateRecord{}, false, nil
	}

	record := certificateRecord{
		id:          strings.TrimSpace(*item.CertificateId),
		domains:     domainsFromMetadata(item.Domain, item.SubjectAltName),
		packageType: stringValue(item.PackageType),
		verifyType:  stringValue(item.VerifyType),
		status:      uint64Value(item.Status),
		statusName:  stringValue(item.StatusName),
		statusMsg:   stringValue(item.StatusMsg),
		deployable:  boolValue(item.Deployable),
		isWildcard:  boolValue(item.IsWildcard),
	}
	if item.AllowDownload != nil {
		record.allowDownload = *item.AllowDownload
	}
	if item.Domain != nil {
		record.domain = strings.TrimSpace(*item.Domain)
	}

	notAfter, err := parseOptionalTencentTimestamp(item.CertEndTime)
	if err != nil {
		return certificateRecord{}, false, fmt.Errorf("parse candidate %s expire time: %w", record.id, err)
	}
	record.notAfter = notAfter

	insertTime, err := parseOptionalTencentTimestamp(item.InsertTime)
	if err == nil {
		record.insertTime = insertTime
	}

	return record, true, nil
}

func (c *Provider) describeCertificate(ctx context.Context, certificateID string) (*certificateRecord, error) {
	if c.describeCertificateFunc != nil {
		return c.describeCertificateFunc(ctx, certificateID)
	}

	req := sslapi.NewDescribeCertificateRequest()
	req.CertificateId = sslcommon.StringPtr(certificateID)

	resp, err := c.client.DescribeCertificateWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe certificate detail: %w", err)
	}

	record := &certificateRecord{
		id:          strings.TrimSpace(stringValue(resp.Response.CertificateId)),
		domain:      strings.TrimSpace(stringValue(resp.Response.Domain)),
		domains:     domainsFromMetadata(resp.Response.Domain, resp.Response.SubjectAltName),
		packageType: stringValue(resp.Response.PackageType),
		verifyType:  stringValue(resp.Response.VerifyType),
		status:      uint64Value(resp.Response.Status),
		statusName:  stringValue(resp.Response.StatusName),
		statusMsg:   stringValue(resp.Response.StatusMsg),
		deployable:  boolValue(resp.Response.Deployable),
		isWildcard:  boolValue(resp.Response.IsWildcard),
	}

	notAfter, err := parseOptionalTencentTimestamp(resp.Response.CertEndTime)
	if err == nil {
		record.notAfter = notAfter
	}
	insertTime, err := parseOptionalTencentTimestamp(resp.Response.InsertTime)
	if err == nil {
		record.insertTime = insertTime
	}

	return record, nil
}

func (c *Provider) applyCertificate(ctx context.Context, domain string) (string, error) {
	if c.applyCertificateFunc != nil {
		return c.applyCertificateFunc(ctx, domain)
	}

	zap.L().Info("applying free dv certificate",
		zap.String("provider", "tencentcloud"),
		zap.String("domain", domain),
		zap.Bool("deleteDnsAutoRecord", c.cfg.AutoApply.DeleteDNSAutoRecord))

	req := sslapi.NewApplyCertificateRequest()
	req.DvAuthMethod = sslcommon.StringPtr("DNS_AUTO")
	req.DomainName = sslcommon.StringPtr(domain)
	req.PackageType = sslcommon.StringPtr("83")
	req.DeleteDnsAutoRecord = sslcommon.BoolPtr(c.cfg.AutoApply.DeleteDNSAutoRecord)

	resp, err := c.client.ApplyCertificateWithContext(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Response.CertificateId == nil || strings.TrimSpace(*resp.Response.CertificateId) == "" {
		return "", fmt.Errorf("empty certificate id from apply response")
	}
	return strings.TrimSpace(*resp.Response.CertificateId), nil
}

func (c *Provider) downloadCertificate(ctx context.Context, domain, certificateID string) (*providerpkg.CertificateMaterial, error) {
	if c.downloadCertificateFunc != nil {
		return c.downloadCertificateFunc(ctx, domain, certificateID)
	}

	zap.L().Debug("requesting certificate download url",
		zap.String("provider", "tencentcloud"),
		zap.String("domain", domain),
		zap.String("certificateId", certificateID))
	req := sslapi.NewDescribeDownloadCertificateUrlRequest()
	req.CertificateId = sslcommon.StringPtr(certificateID)
	req.ServiceType = sslcommon.StringPtr("nginx")

	resp, err := c.client.DescribeDownloadCertificateUrlWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe download url: %w", err)
	}
	if resp.Response.DownloadCertificateUrl == nil || *resp.Response.DownloadCertificateUrl == "" {
		return nil, fmt.Errorf("empty download url")
	}
	zap.L().Debug("downloading certificate archive",
		zap.String("provider", "tencentcloud"),
		zap.String("domain", domain),
		zap.String("certificateId", certificateID))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, *resp.Response.DownloadCertificateUrl, nil)
	if err != nil {
		return nil, err
	}
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		return nil, fmt.Errorf("download url returned %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("downloaded certificate archive",
		zap.String("provider", "tencentcloud"),
		zap.String("domain", domain),
		zap.String("certificateId", certificateID),
		zap.Int("bytes", len(body)))
	return extractCertificateMaterialFromZIP(domain, certificateID, body)
}

func (c *Provider) wait(ctx context.Context, d time.Duration) error {
	if c.waitFunc != nil {
		return c.waitFunc(ctx, d)
	}
	return waitWithContext(ctx, d)
}

func waitWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func pendingCertificateFromRecord(record certificateRecord) *providerpkg.PendingCertificate {
	return &providerpkg.PendingCertificate{
		CertificateID: record.id,
		Status:        record.status,
		StatusName:    record.statusName,
		StatusMsg:     record.statusMsg,
		VerifyType:    record.verifyType,
	}
}

func isExactDomainMatch(record certificateRecord, domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	for _, value := range record.domains {
		if strings.TrimSpace(strings.ToLower(value)) == domain {
			return true
		}
	}
	return false
}

func isWildcardDomain(domain string) bool {
	return strings.HasPrefix(strings.TrimSpace(domain), "*.")
}

func isAutoApplyFreeDVRecord(record certificateRecord) bool {
	return record.packageType == "83" && record.verifyType == "DNS_AUTO"
}

func isIssuedCertificateRecord(record certificateRecord) bool {
	return record.status == 1 && record.deployable
}

func isPendingCertificateRecord(record certificateRecord) bool {
	if record.status == 0 || record.status == 4 {
		return true
	}
	switch record.statusMsg {
	case "PENDING-DCV", "WAIT-ISSUE", "PRE-REVIEWING", "CA-REVIEWING":
		return true
	default:
		return false
	}
}

func isTerminalFailureCertificateRecord(record certificateRecord) bool {
	switch record.status {
	case 2, 7, 10, 14:
		return true
	default:
		return false
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func uint64Value(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func boolValue(value *bool) bool {
	return value != nil && *value
}
