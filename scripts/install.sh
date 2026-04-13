#!/bin/sh
set -eu

REPO="${REPO:-panjiang/cert-renewer}"
VERSION="${VERSION:-latest}"
BINARY_NAME="${BINARY_NAME:-cert-renewer}"
SERVICE_NAME="${SERVICE_NAME:-cert-renewer}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/cert-renewer}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/${SERVICE_NAME}.service}"
GITHUB_PROXY="${GITHUB_PROXY:-}"

require_command() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required command: $1" >&2
		exit 1
	}
}

if [ "$(id -u)" -ne 0 ]; then
	echo "run this installer as root, for example: curl -fsSL https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh | sudo sh" >&2
	exit 1
fi

require_command curl
require_command install
require_command awk
require_command chmod
require_command chown
require_command mktemp
require_command sha256sum
require_command systemctl
require_command tar
require_command uname

github_url() {
	url="$1"
	if [ -n "$GITHUB_PROXY" ]; then
		printf '%s/%s\n' "${GITHUB_PROXY%/}" "$url"
		return 0
	fi

	printf '%s\n' "$url"
}

detect_installed_version() {
	if version_output="$("$1" -version 2>/dev/null)"; then
		version_output="$(printf '%s' "$version_output" | tr -d '\r' | head -n 1)"
		if [ -n "$version_output" ]; then
			printf '%s\n' "$version_output"
			return 0
		fi
	fi

	return 1
}

os="$(uname -s)"
if [ "$os" != "Linux" ]; then
	echo "unsupported OS: $os" >&2
	exit 1
fi

case "$(uname -m)" in
	x86_64 | amd64)
		arch="amd64"
		;;
	aarch64 | arm64)
		arch="arm64"
		;;
	*)
		echo "unsupported architecture: $(uname -m)" >&2
		exit 1
		;;
esac

asset="${BINARY_NAME}_linux_${arch}.tar.gz"
if [ "$VERSION" = "latest" ]; then
	base_url="https://github.com/${REPO}/releases/latest/download"
	display_version="latest"
else
	base_url="https://github.com/${REPO}/releases/download/${VERSION}"
	display_version="$VERSION"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

echo "Downloading ${asset} from ${REPO} ${display_version}..."
curl -fsSL "$(github_url "${base_url}/${asset}")" -o "${tmp_dir}/${asset}"
curl -fsSL "$(github_url "${base_url}/SHA256SUMS")" -o "${tmp_dir}/SHA256SUMS"

awk -v file="$asset" '$2 == file { print; found = 1 } END { exit found ? 0 : 1 }' \
	"${tmp_dir}/SHA256SUMS" >"${tmp_dir}/SHA256SUMS.selected" || {
	echo "checksum for ${asset} not found in SHA256SUMS" >&2
	exit 1
}

(cd "$tmp_dir" && sha256sum -c SHA256SUMS.selected)

tar -xzf "${tmp_dir}/${asset}" -C "$tmp_dir"
if [ ! -f "${tmp_dir}/${BINARY_NAME}" ]; then
	echo "archive did not contain ${BINARY_NAME}" >&2
	exit 1
fi

install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "${tmp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

install -d -m 0755 "$CONFIG_DIR"
cat >"${CONFIG_DIR}/config.yaml.example" <<'EOF'
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
EOF

if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
	install -m 0600 "${CONFIG_DIR}/config.yaml.example" "${CONFIG_DIR}/config.yaml"
else
	chown root:root "${CONFIG_DIR}/config.yaml"
	chmod 0600 "${CONFIG_DIR}/config.yaml"
fi

cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Cert Renewer
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -config=${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=30s
WorkingDirectory=${CONFIG_DIR}
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

installed_version="$display_version"
if detected_version="$(detect_installed_version "${INSTALL_DIR}/${BINARY_NAME}")"; then
	installed_version="$detected_version"
fi

echo "Installed ${BINARY_NAME} ${installed_version} to ${INSTALL_DIR}/${BINARY_NAME}"
echo "Installed systemd service to ${SERVICE_FILE}"
echo "Configuration example: ${CONFIG_DIR}/config.yaml.example"
echo "Runtime config: ${CONFIG_DIR}/config.yaml"
echo "Edit config before starting:"
echo "  sudo vi ${CONFIG_DIR}/config.yaml"
echo "Validate config with one forced update check before starting the service:"
echo "  sudo ${INSTALL_DIR}/${BINARY_NAME} -config=${CONFIG_DIR}/config.yaml -force"
echo "  Note: -force runs the forced update path. Do not run it while the service is already running."
echo "Start the service after the config is ready:"
echo "  sudo systemctl enable --now ${SERVICE_NAME}"
echo "  sudo systemctl status ${SERVICE_NAME}"
