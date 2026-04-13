# cert-renewer

Update Tencent Cloud SSL certificates directly on the certificate host.

Run this program on the machine that already serves the certificates.

For each configured domain, it:

- checks the current public TLS certificate
- downloads a newer Tencent Cloud certificate when the domain enters the `beforeExpired` window
- replaces local certificate files atomically
- runs domain-level `postCommands`
- runs one round of `globalPostCommands` if every updated domain succeeded
- verifies the external certificate after deployment

Use `-force` to run one validation round for a fresh installation or troubleshooting.

## Config

```yaml
alert:
  # Renewal window. Must be between 3d and 30d.
  beforeExpired: 10d
  # Check interval. Default is 12h. Minimum is 1m.
  checkInterval: 12h
  # Optional. Leave empty to log only.
  notifyUrl: https://open.feishu.cn/open-apis/bot/v2/hook/xxxx

log:
  # debug, info, warn, or error. Default is info.
  level: info

# Default provider. Currently only tencentcloud is supported.
defaultProvider: tencentcloud

providerConfigs:
  tencentcloud:
    # Required.
    secretId: xxx
    # Required.
    secretKey: xxx
    autoApply:
      # Auto-apply a free DV certificate when no deployable certificate exists.
      # Wildcard domains are not auto-applied.
      enabled: true
      # Poll interval for issuance status. Must be greater than 0.
      pollInterval: 1m
      # Max wait time in one round. Must be >= pollInterval.
      pollTimeout: 10m
      # Delete the DNS_AUTO validation record after verification.
      deleteDnsAutoRecord: true

# Optional. Run once after all updated domains succeed.
globalPostCommands:
  - nginx -t
  - nginx -s reload

domains:
  - domain: doc.yourdomain.com
    # Required certificate file path.
    certPath: /etc/nginx/ssl/doc.yourdomain.com.crt
    # Required private key file path.
    keyPath: /etc/nginx/ssl/doc.yourdomain.com.key
    # Optional. Run after this domain is deployed.
    postCommands:
      - consul kv put certs/doc.yourdomain.com.crt @{{.CertPath}}
      - consul kv put certs/doc.yourdomain.com.key @{{.KeyPath}}
```

Config notes:

- Durations use Go-style units plus day and week units: `ms`, `s`, `m`, `h`, `d`, and `w`.
- Example durations: `12h`, `10d`, `1w`.
- Command entries are executed with `sh -lc`.
- Domain-level `postCommands` receive `{{.Domain}}`, `{{.CertPath}}`, `{{.KeyPath}}`, `{{.BackupCertPath}}`, and `{{.BackupKeyPath}}`.
- Top-level `globalPostCommands` do not receive domain-specific values.

## Run

```sh
go run . -config=config.yaml
```

Run one forced update check round and exit:

```sh
go run . -config=config.yaml -force
```

`-force` skips the `beforeExpired` window and exits after one round.

Use it for installation validation or troubleshooting.

Do not add `-force` to the systemd service command.
Do not run it in parallel with the running service instance.

## Install

Install the latest Linux release:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo sh
```

Optional: install a specific version instead of the latest release:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo env VERSION=v0.1.0 sh
```

Edit the runtime config:

The installer creates this file with `0600` permissions if it does not already exist.

```sh
sudo vi /etc/cert-renewer/config.yaml
```

Optional: validate the configuration with one forced update check before starting the service:

```sh
sudo /usr/local/bin/cert-renewer -config=/etc/cert-renewer/config.yaml -force
```

This command runs the forced update path.
Make sure the `cert-renewer` service is not already running when you execute it.

Start the service after the config is ready:

```sh
sudo systemctl enable --now cert-renewer
sudo systemctl status cert-renewer
```

View service logs:

```sh
sudo journalctl -u cert-renewer -n 100 --no-pager
sudo journalctl -u cert-renewer -f
```

## China Proxy

If direct access to GitHub is slow or blocked, use a mirrored script URL, set `GITHUB_PROXY`, and install an explicit release tag.

Use a specific version instead of relying on the default `latest` resolution.

Install or upgrade through `ghproxy.net`:

```sh
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo env GITHUB_PROXY=https://ghproxy.net VERSION=<release-tag> sh
```

If the script is already downloaded locally:

```sh
sudo env GITHUB_PROXY=https://ghproxy.net VERSION=<release-tag> sh install.sh
```

`GITHUB_PROXY` is applied to the script's GitHub release asset downloads.

## Upgrade

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo sh
sudo systemctl restart cert-renewer
```

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/uninstall.sh | sudo sh
```

Keep the runtime config during uninstall:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/uninstall.sh | sudo env KEEP_CONFIG=1 sh
```
