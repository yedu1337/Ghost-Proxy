#!/usr/bin/env bash
# Ghost Proxy gateway installer for Linux servers.
#
# Run this from the extracted Linux server package:
#   sudo ./install.sh
#
# The installer obtains a free Let's Encrypt certificate for either a public
# IP address (no domain required) or a domain name, installs the gateway as a
# systemd service, enables automatic certificate renewal, and prints the text
# to send to users.
set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ghost-proxy"
CONFIG_DIR="/etc/ghost-proxy"
SERVICE_NAME="ghost-proxy.service"
CERTBOT_DIR="/opt/certbot"
LE_ROOT="/etc/letsencrypt"
RELEASE_URL="https://github.com/yedukrishna012/Ghost-Proxy/releases/latest"

HOST=""
EMAIL=""
PORT=443
PORT_SET=0
CERT_FILE=""
KEY_FILE=""
SELF_SIGNED=0
DRY_RUN=0
NON_INTERACTIVE=0
INTERACTIVE=0
NEW_PSK=0
CERT_MODE=""
CERT_NAME=""
LE_LIVE=""
PKG_MANAGER=""

usage() {
	cat <<'EOF'
Ghost Proxy gateway installer

Usage:
  sudo ./install.sh [options]

The installer asks for a public IP address or domain name. A public IP
address needs no domain: Let's Encrypt issues a free trusted certificate for
it and the installer renews it automatically.

Options:
  --host HOST          Public IP address or domain name (skips the prompt)
  --email EMAIL        Email for Let's Encrypt expiry notices (optional)
  --port PORT          Public TCP port for the gateway (default: 443)
  --cert-file PATH     Use an existing certificate chain instead of Let's Encrypt
  --key-file PATH      Private key for --cert-file
  --self-signed        Generate a self-signed certificate (testing only)
  --new-psk            Rotate the shared PSK instead of keeping the current one
  --non-interactive    Never prompt; requires --host
  --dry-run            Show what would be done without changing the system
  -h, --help           Show this help

Examples:
  sudo ./install.sh
  sudo ./install.sh --host 203.0.113.10 --email you@example.com
  sudo ./install.sh --host proxy.example.com --email you@example.com
  sudo ./install.sh --host 203.0.113.10 --self-signed

Before running, open inbound TCP 80 and 443 in your cloud firewall/security
group (or your chosen --port). Port 80 is used for Let's Encrypt certificate
issuance and renewal; the gateway itself listens on TCP 443 by default.

Re-running the installer upgrades the gateway and keeps the PSK, port,
fallback, and destination settings. Use --new-psk to rotate the key.
EOF
}

log() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() { printf 'Warning: %s\n' "$*" >&2; }
fail() { printf '\nError: %s\n' "$*" >&2; exit 1; }

run() {
	if ((DRY_RUN)); then
		printf '  [dry-run]'
		printf ' %q' "$@"
		printf '\n'
	else
		"$@"
	fi
}

have() { command -v "$1" >/dev/null 2>&1; }

is_ipv4() {
	local value="$1" a b c d extra
	[[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
	IFS=. read -r a b c d extra <<<"$value"
	((${#extra} == 0)) || return 1
	((a <= 255 && b <= 255 && c <= 255 && d <= 255)) || return 1
}

is_ipv6() {
	local value="${1,,}"
	[[ "$value" == *:* && "$value" =~ ^[0-9a-f:.]+$ ]]
}

is_ip() { is_ipv4 "$1" || is_ipv6 "$1"; }

is_domain() {
	local value="${1,,}"
	[[ "$value" == *.* ]] || return 1
	[[ "$value" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

is_private_host() {
	local value="${1,,}" a b c d extra
	if [[ "$value" == "localhost" || "$value" == "localhost.localdomain" ]]; then
		return 0
	fi
	if is_ipv6 "$value"; then
		case "$value" in
		::1 | fc* | fd* | fe80*) return 0 ;;
		esac
	fi
	if is_ipv4 "$value"; then
		IFS=. read -r a b c d extra <<<"$value"
		((a == 0 || a == 10 || a == 127)) && return 0
		((a == 169 && b == 254)) && return 0
		((a == 172 && b >= 16 && b <= 31)) && return 0
		((a == 192 && b == 168)) && return 0
		((a == 100 && b >= 64 && b <= 127)) && return 0
	fi
	return 1
}

normalize_host() {
	local value="$1"
	value="${value#http://}"
	value="${value#https://}"
	value="${value%%/*}"
	value="${value#[}"
	value="${value%]}"
	printf '%s' "${value,,}"
}

detect_public_ip() {
	local value url
	have curl || return 1
	for url in https://api.ipify.org https://ifconfig.me/ip; do
		value="$(curl -4 -fsS --max-time 6 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
		if is_ipv4 "$value"; then
			printf '%s' "$value"
			return 0
		fi
	done
	return 1
}

cert_covers_host() {
	local cert="$1" host="$2"
	[[ -s "$cert" ]] || return 1
	have openssl || return 1
	if is_ip "$host"; then
		openssl x509 -checkip "$host" -noout -in "$cert" >/dev/null 2>&1
	else
		openssl x509 -checkhost "$host" -noout -in "$cert" >/dev/null 2>&1
	fi
}

cert_valid_for() {
	local seconds="$1" cert="$2"
	[[ -s "$cert" ]] && have openssl || return 1
	openssl x509 -checkend "$seconds" -noout -in "$cert" >/dev/null 2>&1
}

version_ge() {
	local current="$1" required="$2"
	[[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n1)" == "$required" ]]
}

compatible_python() {
	local candidate
	for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
		have "$candidate" || continue
		if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
			printf '%s' "$candidate"
			return 0
		fi
	done
	return 1
}

port_in_use() {
	local port="$1"
	if have ss; then
		ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"
	elif have netstat; then
		netstat -ltn 2>/dev/null | awk 'NR > 2 {print $4}' | grep -qE "[:.]${port}$"
	else
		return 1
	fi
}

service_active() {
	systemctl is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1
}

read_config_value() {
	local key="$1"
	awk -v key="$key" '
		$0 ~ "^" key ":" {
			value = $0
			sub("^" key ":[[:space:]]*", "", value)
			sub(/[[:space:]]*$/, "", value)
			gsub(/^"|"$/, "", value)
			print value
			exit
		}
	' "$CONFIG_DIR/server.yaml" 2>/dev/null || true
}

while (($#)); do
	case "$1" in
	--host)
		[[ $# -ge 2 ]] || fail "--host requires a value"
		HOST="$2"
		shift 2
		;;
	--email)
		[[ $# -ge 2 ]] || fail "--email requires a value"
		EMAIL="$2"
		shift 2
		;;
	--port)
		[[ $# -ge 2 ]] || fail "--port requires a value"
		PORT="$2"
		PORT_SET=1
		shift 2
		;;
	--cert-file)
		[[ $# -ge 2 ]] || fail "--cert-file requires a value"
		CERT_FILE="$2"
		shift 2
		;;
	--key-file)
		[[ $# -ge 2 ]] || fail "--key-file requires a value"
		KEY_FILE="$2"
		shift 2
		;;
	--self-signed)
		SELF_SIGNED=1
		shift
		;;
	--new-psk)
		NEW_PSK=1
		shift
		;;
	--non-interactive)
		NON_INTERACTIVE=1
		shift
		;;
	--dry-run)
		DRY_RUN=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		fail "Unknown option: $1 (use --help)"
		;;
	esac
done

if ((DRY_RUN)); then
	log "Ghost Proxy installer (dry run; no changes will be made)"
else
	((EUID == 0)) || fail "Run the installer with sudo: sudo ./install.sh"
fi

[[ "$(uname -s)" == "Linux" ]] || fail "This installer is for Linux servers."
have systemctl || fail "systemd is required. Use the manual systemd instructions in the README instead."

for required in \
	ghost-proxy-server \
	ghost-proxy.service \
	certbot-deploy-hook.sh \
	ghost-proxy-certbot-renew.service \
	ghost-proxy-certbot-renew.timer; do
	[[ -f "$SCRIPT_DIR/$required" ]] || fail "Missing $required next to install.sh. Extract the complete Linux server package."
done

if have apt-get; then
	PKG_MANAGER=apt
elif have dnf; then
	PKG_MANAGER=dnf
elif have yum; then
	PKG_MANAGER=yum
elif ((DRY_RUN)); then
	PKG_MANAGER=unknown
else
	fail "Unsupported Linux distribution: install ca-certificates, curl, and openssl, then rerun."
fi

if [[ -n "$CERT_FILE" || -n "$KEY_FILE" ]]; then
	[[ -n "$CERT_FILE" && -n "$KEY_FILE" ]] || fail "--cert-file and --key-file must be provided together"
	[[ -r "$CERT_FILE" ]] || fail "Cannot read certificate: $CERT_FILE"
	[[ -r "$KEY_FILE" ]] || fail "Cannot read private key: $KEY_FILE"
fi

existing_public_host=""
if [[ -r "$CONFIG_DIR/server.yaml" ]]; then
	existing_public_host="$(read_config_value public_host)"
fi

if [[ -z "$HOST" ]]; then
	if ((NON_INTERACTIVE)) || [[ ! -t 0 ]]; then
		fail "--host is required when running without prompts"
	fi
	default_host="$existing_public_host"
	if [[ -z "$default_host" ]] && have curl; then
		default_host="$(detect_public_ip || true)"
	fi
	if [[ -n "$default_host" ]]; then
		printf 'Public IP address or domain name [%s]: ' "$default_host"
	else
		printf 'Public IP address or domain name: '
	fi
	read -r HOST || fail "No public address provided."
	HOST="${HOST:-$default_host}"
fi

HOST="$(normalize_host "$HOST")"
[[ -n "$HOST" ]] || fail "A public IP address or domain name is required."
if [[ "$HOST" == *" "* || "$HOST" == *$'\t'* ]]; then
	fail "The public address cannot contain spaces."
fi
if is_ip "$HOST" || [[ "$HOST" == "localhost" ]]; then
	:
elif is_domain "$HOST"; then
	:
else
	fail "Enter a public IPv4/IPv6 address or a domain name such as proxy.example.com (without https:// or a port)."
fi

default_port=443
existing_fallback=""
if [[ -r "$CONFIG_DIR/server.yaml" ]]; then
	existing_listen="$(read_config_value listen_address)"
	if [[ "$existing_listen" =~ :([0-9]+)$ ]]; then
		default_port="${BASH_REMATCH[1]}"
	fi
	existing_fallback="$(read_config_value fallback_address)"
fi
if ((PORT_SET == 0)); then
	PORT="$default_port"
fi
if ((PORT_SET == 0)) && ((NON_INTERACTIVE == 0)) && [[ -t 0 ]]; then
	printf 'Public port [%s]: ' "$PORT"
	read -r port_input || true
	PORT="${port_input:-$PORT}"
fi
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "Port must be a number between 1 and 65535."
((PORT >= 1 && PORT <= 65535)) || fail "Port must be between 1 and 65535."

INTERACTIVE=0
if ((NON_INTERACTIVE == 0)) && [[ -t 0 ]]; then
	INTERACTIVE=1
fi

existing_cert=""
existing_key=""
if [[ -r "$CONFIG_DIR/server.yaml" ]]; then
	existing_cert="$(read_config_value cert_file)"
	existing_key="$(read_config_value key_file)"
	if [[ -n "$existing_cert" && "$existing_cert" != /* ]]; then
		existing_cert="$CONFIG_DIR/$existing_cert"
	fi
	if [[ -n "$existing_key" && "$existing_key" != /* ]]; then
		existing_key="$CONFIG_DIR/$existing_key"
	fi
fi

existing_cert_name=""
if [[ -r "$CONFIG_DIR/renewal-cert-name" ]]; then
	existing_cert_name="$(tr -d '[:space:]' <"$CONFIG_DIR/renewal-cert-name")"
	if [[ ! "$existing_cert_name" =~ ^[A-Za-z0-9._-]+$ ]]; then
		warn "Ignoring an invalid renewal certificate name in $CONFIG_DIR/renewal-cert-name."
		existing_cert_name=""
	fi
fi

CERT_NAME="${HOST//:/-}"
LE_LIVE="$LE_ROOT/live/$CERT_NAME"

set_letsencrypt_mode() {
	CERT_MODE=letsencrypt
	CERT_NAME="$1"
	LE_LIVE="$LE_ROOT/live/$CERT_NAME"
	CERT_FILE="$LE_LIVE/fullchain.pem"
	KEY_FILE="$LE_LIVE/privkey.pem"
}

if [[ "$SELF_SIGNED" == 1 ]]; then
	CERT_MODE=self-signed
elif [[ -n "$CERT_FILE" ]]; then
	CERT_MODE=existing
elif [[ -n "$existing_cert_name" ]]; then
	# A previous installer run managed this gateway with Let's Encrypt.
	# Renewal must stay enabled even though the live certificate is copied
	# into /etc/ghost-proxy.
	if [[ -s "$LE_ROOT/live/$existing_cert_name/fullchain.pem" && -s "$LE_ROOT/live/$existing_cert_name/privkey.pem" ]] &&
		cert_covers_host "$LE_ROOT/live/$existing_cert_name/fullchain.pem" "$HOST"; then
		set_letsencrypt_mode "$existing_cert_name"
	elif [[ -s "$LE_LIVE/fullchain.pem" && -s "$LE_LIVE/privkey.pem" ]] &&
		cert_covers_host "$LE_LIVE/fullchain.pem" "$HOST"; then
		set_letsencrypt_mode "$CERT_NAME"
	elif is_private_host "$HOST"; then
		fail "Let's Encrypt cannot issue a certificate for the private or local address $HOST. Use --self-signed for local testing, or use this server's public IP address."
	else
		if [[ -s "$LE_ROOT/live/$existing_cert_name/fullchain.pem" ]]; then
			warn "The existing certificate $existing_cert_name does not cover $HOST. A new certificate will be requested."
		else
			warn "The previous Let's Encrypt certificate ($existing_cert_name) was not found. A new certificate will be requested."
		fi
		set_letsencrypt_mode "$CERT_NAME"
	fi
elif [[ -s "$LE_LIVE/fullchain.pem" && -s "$LE_LIVE/privkey.pem" ]] &&
	cert_covers_host "$LE_LIVE/fullchain.pem" "$HOST"; then
	set_letsencrypt_mode "$CERT_NAME"
elif [[ -n "$existing_cert" && "$existing_cert" == "$LE_ROOT/live/"* && -r "$existing_cert" && -r "$existing_key" ]] &&
	cert_covers_host "$existing_cert" "$HOST"; then
	CERT_NAME="${existing_cert#"$LE_ROOT/live/"}"
	CERT_NAME="${CERT_NAME%%/*}"
	set_letsencrypt_mode "$CERT_NAME"
elif [[ -n "$existing_cert" && -n "$existing_key" && -r "$existing_cert" && -r "$existing_key" ]] &&
	cert_covers_host "$existing_cert" "$HOST"; then
	CERT_MODE=existing
	CERT_FILE="$existing_cert"
	KEY_FILE="$existing_key"
elif is_private_host "$HOST"; then
	fail "Let's Encrypt cannot issue a certificate for the private or local address $HOST. Use --self-signed for local testing, or use this server's public IP address."
else
	set_letsencrypt_mode "$CERT_NAME"
fi

if [[ "$CERT_MODE" == letsencrypt ]] && ((PORT == 80)); then
	fail "The gateway cannot use port 80 when Let's Encrypt needs port 80 for validation. Choose another --port."
fi

if [[ "$CERT_MODE" == letsencrypt && -z "$EMAIL" && "$INTERACTIVE" == 1 ]]; then
	printf 'Email for Let'"'"'s Encrypt expiry notices (optional): '
	read -r EMAIL || true
fi
if [[ -n "$EMAIL" && "$EMAIL" != *@*.* ]]; then
	fail "The email address looks invalid: $EMAIL"
fi

detected_ip=""
if have curl && ! is_private_host "$HOST"; then
	detected_ip="$(detect_public_ip || true)"
fi

if [[ "$CERT_MODE" == letsencrypt ]]; then
	if is_ip "$HOST"; then
		cert_description="Let's Encrypt public IP certificate (free, trusted, auto-renewed)"
	else
		cert_description="Let's Encrypt domain certificate (free, trusted, auto-renewed)"
	fi
elif [[ "$CERT_MODE" == self-signed ]]; then
	cert_description="self-signed certificate (testing only; users must install the CA file)"
else
	cert_description="existing certificate $CERT_FILE"
fi

step "Installation plan"
printf '  Public address: %s:%s\n' "$HOST" "$PORT"
printf '  Certificate:    %s\n' "$cert_description"
printf '  Service:        %s (systemd)\n' "$SERVICE_NAME"
printf '  Config:         %s/server.yaml\n' "$CONFIG_DIR"
printf '  Invite:         %s/invite.txt\n' "$CONFIG_DIR"

if [[ -n "$detected_ip" && "$CERT_MODE" == letsencrypt ]]; then
	if is_ipv4 "$HOST" && [[ "$detected_ip" != "$HOST" ]]; then
		warn "This machine's detected public IP is $detected_ip, but the certificate will be requested for $HOST."
		warn "Make sure $HOST is assigned to this server, or the validation will fail."
	elif is_domain "$HOST" && have getent; then
		resolved="$(getent ahostsv4 "$HOST" 2>/dev/null | awk 'NR == 1 {print $1}' || true)"
		if [[ -n "$resolved" && "$resolved" != "$detected_ip" ]]; then
			warn "$HOST currently resolves to $resolved, but this server's public IP appears to be $detected_ip."
			warn "Point the DNS record at this server before requesting the certificate."
		fi
	fi
fi

if ((INTERACTIVE)); then
	printf '\nContinue? [Y/n]: '
	read -r answer || true
	case "${answer,,}" in
	y | yes | "") : ;;
	*) fail "Installation cancelled." ;;
	esac
fi

install_packages() {
	step "Installing required packages"
	case "$PKG_MANAGER" in
	apt)
		local -a packages=(ca-certificates curl openssl iproute2)
		[[ "$CERT_MODE" == letsencrypt ]] && packages+=(python3 python3-venv)
		run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
		run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${packages[@]}"
		;;
	dnf)
		local -a packages=(ca-certificates curl openssl iproute)
		[[ "$CERT_MODE" == letsencrypt ]] && packages+=(python3)
		run dnf install -y -q "${packages[@]}"
		;;
	yum)
		local -a packages=(ca-certificates curl openssl iproute)
		[[ "$CERT_MODE" == letsencrypt ]] && packages+=(python3)
		run yum install -y -q "${packages[@]}"
		;;
	unknown)
		log "  [dry-run] install curl and openssl"
		[[ "$CERT_MODE" == letsencrypt ]] && log "  [dry-run] install python3 and python3-venv"
		;;
	esac
}

if ((DRY_RUN == 0)); then
	install_packages
else
	step "Required packages"
	case "$PKG_MANAGER" in
	apt)
		log "  [dry-run] apt-get install ca-certificates curl openssl iproute2"
		[[ "$CERT_MODE" == letsencrypt ]] && log "  [dry-run] apt-get install python3 python3-venv"
		;;
	dnf | yum)
		log "  [dry-run] $PKG_MANAGER install ca-certificates curl openssl iproute"
		[[ "$CERT_MODE" == letsencrypt ]] && log "  [dry-run] $PKG_MANAGER install python3"
		;;
	unknown)
		log "  [dry-run] install ca-certificates, curl, openssl, and iproute2"
		[[ "$CERT_MODE" == letsencrypt ]] && log "  [dry-run] install python3 and python3-venv"
		;;
	esac
fi

if ((DRY_RUN == 0)); then
	if [[ "$CERT_MODE" == letsencrypt ]] && port_in_use 80; then
		fail "TCP port 80 is already in use. Stop the service using it (for example nginx or apache2), rerun the installer, then start that service again. Let's Encrypt needs port 80 for validation and renewal."
	fi
	if port_in_use "$PORT" && ! service_active; then
		fail "TCP port $PORT is already in use by another service. Stop it or choose another --port."
	fi
fi

certbot_ready() {
	[[ -x "$CERTBOT_DIR/bin/certbot" ]] || return 1
	local current
	current="$("$CERTBOT_DIR/bin/certbot" --version 2>/dev/null | awk '{print $2}' || true)"
	[[ -n "$current" ]] && version_ge "$current" "5.4"
}

setup_certbot() {
	step "Setting up Certbot"
	if certbot_ready; then
		log "Certbot is already installed."
		return
	fi

	local py
	if ! py="$(compatible_python)"; then
		if [[ "$PKG_MANAGER" == dnf || "$PKG_MANAGER" == yum ]]; then
			run "$PKG_MANAGER" install -y -q python3.11 python3.11-pip ||
				run "$PKG_MANAGER" install -y -q python3.11 || true
		fi
		py="$(compatible_python || true)"
	fi
	if [[ -z "$py" ]]; then
		fail "Certbot requires Python 3.10 or newer. Install python3.11 (or newer) and rerun the installer."
	fi

	if ! run "$py" -m venv "$CERTBOT_DIR"; then
		fail "Could not create the Certbot environment with $py. Install the venv module (python3-venv on Debian/Ubuntu) and rerun."
	fi
	run "$CERTBOT_DIR/bin/python" -m pip install --quiet --upgrade pip
	run "$CERTBOT_DIR/bin/pip" install --quiet --upgrade 'certbot>=5.4'
}

obtain_certificate() {
	if cert_valid_for 86400 "$LE_LIVE/fullchain.pem" &&
		cert_covers_host "$LE_LIVE/fullchain.pem" "$HOST"; then
		step "Using the existing Let's Encrypt certificate"
		log "Certificate: $LE_LIVE/fullchain.pem"
		return
	fi

	step "Requesting a Let's Encrypt certificate for $HOST"
	local -a args=(certonly --standalone --non-interactive --agree-tos --cert-name "$CERT_NAME")
	if [[ -n "$EMAIL" ]]; then
		args+=(-m "$EMAIL")
	else
		args+=(--register-unsafely-without-email)
		warn "No email address was provided. Certificate expiry notices cannot be sent to you."
	fi
	if is_ip "$HOST"; then
		args+=(--preferred-profile shortlived --ip-address "$HOST")
	else
		args+=(-d "$HOST")
	fi

	log "This may take a minute. Port 80 must be reachable from the internet."
	if ! run "$CERTBOT_DIR/bin/certbot" "${args[@]}"; then
		cat >&2 <<EOF

Certificate request failed. Check these items and rerun the installer:
  - TCP port 80 is open in the cloud security group and the host firewall.
  - For a domain, its DNS A/AAAA record points to this server.
  - No other service (nginx, apache2, Caddy) is listening on port 80.

EOF
		exit 1
	fi
}

if [[ "$CERT_MODE" == letsencrypt ]]; then
	if ((DRY_RUN == 0)); then
		setup_certbot
	fi
	obtain_certificate
fi

step "Installing Ghost Proxy"
if ! getent group ghost-proxy >/dev/null 2>&1; then
	run groupadd --system ghost-proxy
fi
if ! id -u ghost-proxy >/dev/null 2>&1; then
	run useradd --system --gid ghost-proxy --home-dir /var/lib/ghost-proxy --create-home --shell /usr/sbin/nologin ghost-proxy
fi
run install -d -m 0750 -o root -g ghost-proxy "$CONFIG_DIR"
run install -d -m 0755 -o root -g root "$INSTALL_DIR"
run install -m 0755 "$SCRIPT_DIR/ghost-proxy-server" "$INSTALL_DIR/ghost-proxy-server"

setup_args=(
	--setup-only
	--config "$CONFIG_DIR/server.yaml"
	--env-file "$CONFIG_DIR/environment"
	--public-host "$HOST"
	--public-port "$PORT"
	--fallback-address "${existing_fallback:-none}"
	--non-interactive
	--invite-file "$CONFIG_DIR/invite.txt"
)
((NEW_PSK)) && setup_args+=(--force-psk)
case "$CERT_MODE" in
letsencrypt)
	setup_args+=(--cert-file "$LE_LIVE/fullchain.pem" --key-file "$LE_LIVE/privkey.pem" --force)
	;;
existing)
	setup_args+=(--cert-file "$CERT_FILE" --key-file "$KEY_FILE" --force)
	;;
self-signed)
	setup_args+=(--self-signed)
	;;
esac
run "$INSTALL_DIR/ghost-proxy-server" "${setup_args[@]}"

# The service runs as the unprivileged ghost-proxy user, so it needs group
# read access to the key, config, and environment file. The invite contains
# the PSK and stays root-only.
run chown root:ghost-proxy "$CONFIG_DIR/server.key" "$CONFIG_DIR/server.crt" "$CONFIG_DIR/server.yaml" "$CONFIG_DIR/environment"
run chmod 0640 "$CONFIG_DIR/server.key" "$CONFIG_DIR/server.yaml" "$CONFIG_DIR/environment"
run chmod 0644 "$CONFIG_DIR/server.crt"
run chown root:root "$CONFIG_DIR/invite.txt"
run chmod 0600 "$CONFIG_DIR/invite.txt"

run install -m 0644 "$SCRIPT_DIR/ghost-proxy.service" "/etc/systemd/system/$SERVICE_NAME"

if [[ "$CERT_MODE" == letsencrypt ]]; then
	run install -d -m 0755 "$LE_ROOT/renewal-hooks/deploy"
	run install -m 0755 "$SCRIPT_DIR/certbot-deploy-hook.sh" "$LE_ROOT/renewal-hooks/deploy/ghost-proxy.sh"
	run install -m 0644 "$SCRIPT_DIR/ghost-proxy-certbot-renew.service" "/etc/systemd/system/ghost-proxy-certbot-renew.service"
	run install -m 0644 "$SCRIPT_DIR/ghost-proxy-certbot-renew.timer" "/etc/systemd/system/ghost-proxy-certbot-renew.timer"
	if ((DRY_RUN)); then
		log "  [dry-run] write $CONFIG_DIR/renewal-cert-name ($CERT_NAME)"
	else
		printf '%s\n' "$CERT_NAME" >"$CONFIG_DIR/renewal-cert-name"
		chown root:root "$CONFIG_DIR/renewal-cert-name"
		chmod 0644 "$CONFIG_DIR/renewal-cert-name"
	fi
else
	if [[ -f "$LE_ROOT/renewal-hooks/deploy/ghost-proxy.sh" ]]; then
		run rm -f "$LE_ROOT/renewal-hooks/deploy/ghost-proxy.sh"
	fi
	if [[ -f "/etc/systemd/system/ghost-proxy-certbot-renew.timer" ]]; then
		run systemctl disable --now ghost-proxy-certbot-renew.timer || true
	fi
	run rm -f "$CONFIG_DIR/renewal-cert-name"
fi

if ((DRY_RUN)); then
	step "Dry run complete"
	log "Would install the gateway and write:"
	log "  /etc/systemd/system/$SERVICE_NAME"
	log "  $CONFIG_DIR/server.yaml"
	log "  $CONFIG_DIR/environment"
	log "  $CONFIG_DIR/invite.txt"
	if [[ "$CERT_MODE" == letsencrypt ]]; then
		log "Would install Certbot in $CERTBOT_DIR and request a certificate."
	fi
	log "Would run: systemctl daemon-reload && systemctl enable --now $SERVICE_NAME"
	if [[ "$CERT_MODE" == letsencrypt ]]; then
		log "Would enable ghost-proxy-certbot-renew.timer for automatic renewal."
	fi
	log "No files or services were changed."
	log "Rerun without --dry-run to install the gateway."
	exit 0
fi

run systemctl daemon-reload
run systemctl enable "$SERVICE_NAME"
run systemctl restart "$SERVICE_NAME"
if [[ "$CERT_MODE" == letsencrypt ]]; then
	run systemctl enable --now ghost-proxy-certbot-renew.timer
fi

for _ in {1..20}; do
	service_active && break
	sleep 0.5
done
if ! service_active; then
	systemctl status --no-pager -l "$SERVICE_NAME" || true
	journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
	fail "The gateway did not start. See the service log above."
fi

"$INSTALL_DIR/ghost-proxy-server" --check \
	--config "$CONFIG_DIR/server.yaml" \
	--env-file "$CONFIG_DIR/environment"

step "Firewall"
if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
	log "UFW is active. Allow inbound traffic with:"
	if [[ "$CERT_MODE" == letsencrypt ]]; then
		log "  ufw allow 80/tcp"
	fi
	log "  ufw allow $PORT/tcp"
elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then
	log "firewalld is active. Allow inbound traffic with:"
	if [[ "$CERT_MODE" == letsencrypt ]]; then
		log "  firewall-cmd --permanent --add-port=80/tcp"
	fi
	log "  firewall-cmd --permanent --add-port=$PORT/tcp"
	log "  firewall-cmd --reload"
else
	if [[ "$CERT_MODE" == letsencrypt ]]; then
		log "No active host firewall was detected. If you use one, allow TCP 80 and $PORT."
	else
		log "No active host firewall was detected. If you use one, allow TCP $PORT."
	fi
fi
if [[ "$CERT_MODE" == letsencrypt ]]; then
	log "Also allow inbound TCP 80 and $PORT in your cloud provider's security group"
else
	log "Also allow inbound TCP $PORT in your cloud provider's security group"
fi
log "(for example, the AWS EC2 security group attached to this instance)."

printf '\n'
log "=========================================================================="
log "Ghost Proxy is installed and the service is running."
log "=========================================================================="
printf '\n'
cat "$CONFIG_DIR/invite.txt"
printf '\n'
log "Service status:  sudo systemctl status ghost-proxy"
log "Settings:        sudo nano $CONFIG_DIR/server.yaml"
log "Invite file:     sudo cat $CONFIG_DIR/invite.txt"
log "Client download: $RELEASE_URL"
log "User check:      run the client with --check"
printf '\n'
if [[ "$CERT_MODE" == letsencrypt ]]; then
	log "The certificate renews automatically. Port 80 must stay open for renewal."
else
	log "Certificate renewal is not managed by the installer."
fi
