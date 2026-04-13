# cert-renewer

Update Tencent Cloud SSL certificates directly on the certificate host.

The program runs on the machine that already serves the certificates. It checks the current public TLS certificate for each configured domain, downloads a newer Tencent Cloud certificate when the domain enters the `beforeExpired` window, replaces local certificate files atomically, runs domain-level `postCommands`, runs one round of `globalPostCommands` if every updated domain succeeded, and then verifies the external certificate. You can also run a one-off forced check with `-force` to validate a fresh installation.

## Config

```yaml
alert:
  beforeExpired: 10d
  checkInterval: 12h
  notifyUrl: https://open.feishu.cn/open-apis/bot/v2/hook/xxxx

log:
  level: info

defaultProvider: tencentcloud

providerConfigs:
  tencentcloud:
    secretId: xxx
    secretKey: xxx
    autoApply:
      enabled: true
      pollInterval: 1m
      pollTimeout: 10m
      deleteDnsAutoRecord: true

globalPostCommands:
  - nginx -t
  - nginx -s reload

domains:
  - domain: doc.yourdomain.com
    certPath: /etc/nginx/ssl/doc.yourdomain.com.crt
    keyPath: /etc/nginx/ssl/doc.yourdomain.com.key
    postCommands:
      - consul kv put certs/doc.yourdomain.com.crt @{{.CertPath}}
      - consul kv put certs/doc.yourdomain.com.key @{{.KeyPath}}
```

Durations use Go-style units plus day and week units: `ms`, `s`, `m`, `h`, `d`, and `w`. For example, `12h`, `10d`, and `1w`.

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `alert.beforeExpired` | Yes | None | Renewal window. A domain is renewed only when its public TLS certificate expires within this duration. Must be between `3d` and `30d`. |
| `alert.checkInterval` | No | `12h` | How often each domain is checked. Must be at least `1m`. This controls the polling interval, not the renewal window. |
| `alert.notifyUrl` | No | Empty | Feishu custom bot webhook URL. When empty, notifications are written to logs only. |
| `log.level` | No | `info` | Log level. Supported values are `debug`, `info`, `warn`, and `error`. |
| `defaultProvider` | Yes | None | Default certificate provider for domains that do not set `provider`. Currently only `tencentcloud` is supported. |
| `providerConfigs.tencentcloud.autoApply.enabled` | No | `true` | When no deployable newer certificate exists in Tencent Cloud, automatically apply for a free DV certificate with DNS auto validation. Wildcard domains are not auto-applied. |
| `providerConfigs.tencentcloud.autoApply.pollInterval` | No | `1m` | How often to poll Tencent Cloud after submitting or finding a pending auto-apply certificate. Must be greater than `0`. |
| `providerConfigs.tencentcloud.autoApply.pollTimeout` | No | `10m` | Maximum time to wait in one check round for an auto-applied certificate to be issued. Must be greater than or equal to `pollInterval`. |
| `providerConfigs.tencentcloud.autoApply.deleteDnsAutoRecord` | No | `true` | Passed to Tencent Cloud when applying with `DNS_AUTO`; controls whether the validation DNS record should be deleted after verification. |
| `globalPostCommands` | No | Empty | Shell commands run once after all updated domains finish local deployment successfully. Use this for shared reload steps such as `nginx -t` and `nginx -s reload`. The legacy top-level key `postCommands` is accepted as an alias, but do not set both top-level keys together. |
| `domains[].domain` | Yes | None | Domain name to check through public TLS on port 443. Domain names must be unique in the config. |
| `domains[].provider` | No | `defaultProvider` | Provider override for this domain. Currently only `tencentcloud` is supported. |
| `domains[].certPath` | Yes | None | Local certificate file path to replace when a newer certificate is selected. Missing parent directories are created. Existing files are backed up as `*.bak.<timestamp>`. |
| `domains[].keyPath` | Yes | None | Local private key file path to replace. Missing parent directories are created. Existing files are backed up as `*.bak.<timestamp>`. |
| `domains[].postCommands` | No | Empty | Shell commands run after this domain's certificate and key files are deployed. Use this for per-domain sync steps such as writing the files to Consul. |

Command entries are executed with `sh -lc`. They can use Go template variables. Domain-level `postCommands` receive `{{.Domain}}`, `{{.CertPath}}`, `{{.KeyPath}}`, `{{.BackupCertPath}}`, and `{{.BackupKeyPath}}`. Top-level `globalPostCommands` are global reload hooks and do not receive domain-specific values.

## Run

```sh
go run . -config=config.yaml
```

Run one forced update check round and exit:

```sh
go run . -config=config.yaml -force
```

`-force` skips the `beforeExpired` window, performs a forced update check, and exits after one round. Use it for installation validation or troubleshooting. This is a forced update path, so do not add `-force` to the systemd service command and do not run it in parallel with the running service instance.

## Install

Install the latest Linux release:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo sh
```

Install a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo env VERSION=v0.1.0 sh
```

Edit the runtime config. The installer creates this file with `0600` permissions if it does not already exist:

```sh
sudo vi /etc/cert-renewer/config.yaml
```

Validate the configuration with one forced update check before starting the service:

```sh
sudo /usr/local/bin/cert-renewer -config=/etc/cert-renewer/config.yaml -force
```

This command runs the forced update path. Make sure the `cert-renewer` service is not already running when you execute it.

Start the service after the config is ready:

```sh
sudo systemctl enable --now cert-renewer
sudo systemctl status cert-renewer
```

Upgrade to the latest release:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/install.sh | sudo sh
sudo systemctl restart cert-renewer
```

Uninstall:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/uninstall.sh | sudo sh
```

Keep the runtime config during uninstall:

```sh
curl -fsSL https://raw.githubusercontent.com/panjiang/cert-renewer/main/scripts/uninstall.sh | sudo env KEEP_CONFIG=1 sh
```
