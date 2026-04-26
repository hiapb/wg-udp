#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# WG + AnyTLS/AnyGo 多入口一出口转发隧道
# JSON 状态版 + UID路由规避 + DoH安全解析
# ==========================================================

WG_IF="wg0"
WG_DIR="/etc/wireguard"
ANY_DIR="/etc/anygo"
ANY_BIN="/usr/local/bin/anygo"
ANY_CONFIG="${ANY_DIR}/config.yml"
STATE_FILE="${ANY_DIR}/state.json"

ANY_USER="anygo"
ANY_GROUP="anygo"

WG_SAFE_MTU=1320
WG_SERVER_PORT_DEFAULT=51820
ANY_SERVER_PORT_DEFAULT=443
ANY_LOCAL_UDP_PORT_DEFAULT=51820
ROUTE_TABLE_ID=51820

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}❌ 请用 root 运行${NC}"
  exit 1
fi

print_block() {
  echo
  echo "=================================================="
  echo "$1"
  echo "=================================================="
}

print_ok() {
  echo -e "${GREEN}✅ $1${NC}"
}

print_warn() {
  echo -e "${YELLOW}⚠️  $1${NC}"
}

print_err() {
  echo -e "${RED}❌ $1${NC}"
}

print_step() {
  echo -e "${CYAN}[$1] $2${NC}"
}

ensure_anygo_user() {
  if ! id "$ANY_USER" >/dev/null 2>&1; then
    useradd -r -M -s /usr/sbin/nologin "$ANY_USER" 2>/dev/null || true
  fi
}

ensure_dirs() {
  mkdir -p "$WG_DIR" "$ANY_DIR"
  chmod 700 "$WG_DIR" 2>/dev/null || true
  chmod 750 "$ANY_DIR" 2>/dev/null || true
}

install_base_packages() {
  print_step "1/3" "安装基础依赖..."
  export DEBIAN_FRONTEND=noninteractive
  apt update -y >/dev/null 2>&1 || true
  apt install -y curl ca-certificates iproute2 iptables openssl lsb-release wireguard wireguard-tools certbot jq >/dev/null 2>&1
  ensure_anygo_user
  print_ok "基础依赖安装完成"
}

ensure_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt update -y >/dev/null 2>&1 || true
    apt install -y jq >/dev/null 2>&1
  fi
}

init_state() {
  ensure_dirs
  ensure_jq
  ensure_anygo_user

  if [[ ! -f "$STATE_FILE" ]]; then
    cat > "$STATE_FILE" <<EOF
{
  "role": "unknown",
  "mode": "split",
  "ports": [],
  "wg": {
    "interface": "${WG_IF}",
    "exit_wg_ip": "",
    "entry_wg_ip": "",
    "exit_public_key": "",
    "entry_public_key": "",
    "safe_mtu": ${WG_SAFE_MTU}
  },
  "anytls": {
    "domain": "",
    "remote_host": "",
    "remote_ip": "",
    "remote_port": ${ANY_SERVER_PORT_DEFAULT},
    "listen_port": ${ANY_SERVER_PORT_DEFAULT},
    "local_udp_port": ${ANY_LOCAL_UDP_PORT_DEFAULT},
    "remote_wg_port": ${WG_SERVER_PORT_DEFAULT},
    "password": "",
    "sni": "",
    "verify_tls": "Y",
    "padding_mode": "fast"
  }
}
EOF
  fi

  chmod 640 "$STATE_FILE" 2>/dev/null || true
  chown root:"$ANY_GROUP" "$STATE_FILE" 2>/dev/null || true
}

fix_anygo_permissions() {
  ensure_anygo_user
  chown -R root:"$ANY_GROUP" "$ANY_DIR" 2>/dev/null || true
  chmod 750 "$ANY_DIR" 2>/dev/null || true
  chmod 640 "$ANY_CONFIG" "$STATE_FILE" 2>/dev/null || true
}

state_get() {
  local path="$1"
  init_state
  jq -r "$path // empty" "$STATE_FILE"
}

state_set() {
  local path="$1"
  local value="$2"
  init_state

  local tmp
  tmp="$(mktemp)"

  jq --arg v "$value" "$path = \$v" "$STATE_FILE" > "$tmp"
  mv "$tmp" "$STATE_FILE"
  chmod 640 "$STATE_FILE" 2>/dev/null || true
  chown root:"$ANY_GROUP" "$STATE_FILE" 2>/dev/null || true
}

state_set_json() {
  local path="$1"
  local json="$2"
  init_state

  local tmp
  tmp="$(mktemp)"

  jq --argjson v "$json" "$path = \$v" "$STATE_FILE" > "$tmp"
  mv "$tmp" "$STATE_FILE"
  chmod 640 "$STATE_FILE" 2>/dev/null || true
  chown root:"$ANY_GROUP" "$STATE_FILE" 2>/dev/null || true
}

state_add_port() {
  local port="$1"
  init_state

  local tmp
  tmp="$(mktemp)"

  jq --argjson p "$port" '.ports = ((.ports + [$p]) | unique | sort)' "$STATE_FILE" > "$tmp"
  mv "$tmp" "$STATE_FILE"
  chmod 640 "$STATE_FILE" 2>/dev/null || true
  chown root:"$ANY_GROUP" "$STATE_FILE" 2>/dev/null || true
}

state_remove_port() {
  local port="$1"
  init_state

  local tmp
  tmp="$(mktemp)"

  jq --argjson p "$port" '.ports = (.ports | map(select(. != $p)))' "$STATE_FILE" > "$tmp"
  mv "$tmp" "$STATE_FILE"
  chmod 640 "$STATE_FILE" 2>/dev/null || true
  chown root:"$ANY_GROUP" "$STATE_FILE" 2>/dev/null || true
}

get_role() {
  state_get '.role'
}

set_role() {
  state_set '.role' "$1"
}

get_current_mode() {
  local mode
  mode="$(state_get '.mode')"
  echo "${mode:-split}"
}

set_mode_flag() {
  state_set '.mode' "$1"
}

rand_pass() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18 || true
}

get_wan_if() {
  local wan
  wan=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)
  echo "${wan:-eth0}"
}

get_main_gateway() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' || true
}

resolve_ipv4() {
  local host="$1"

  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$host"
    return 0
  fi

  local ip=""

  if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    ip="$(curl -4 -fsSL --max-time 5 \
      --resolve cloudflare-dns.com:443:1.1.1.1 \
      -H "accept: application/dns-json" \
      "https://cloudflare-dns.com/dns-query?name=${host}&type=A" \
      | jq -r '.Answer[]? | select(.type==1) | .data' \
      | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
      | head -n 1 || true)"
  fi

  if [[ -z "$ip" ]]; then
    ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}' || true)"
  fi

  echo "$ip"
}

enable_ip_forward_global() {
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null || true
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
}

check_anygo_bin() {
  if [[ ! -x "$ANY_BIN" ]]; then
    print_err "未找到 AnyGo/AnyTLS 主程序: ${ANY_BIN}"
    echo
    echo "请先把你的 anygo/anytls 二进制放到："
    echo "  ${ANY_BIN}"
    echo
    echo "然后执行："
    echo "  chmod +x ${ANY_BIN}"
    echo
    exit 1
  fi

  print_ok "检测到 AnyGo/AnyTLS: ${ANY_BIN}"
}

ensure_anygo_uid_bypass() {
  local uid
  uid="$(id -u "$ANY_USER" 2>/dev/null || true)"
  [[ -n "$uid" ]] || return 0

  iptables -t mangle -C OUTPUT -m owner --uid-owner "$uid" -j RETURN 2>/dev/null || \
    iptables -t mangle -I OUTPUT 1 -m owner --uid-owner "$uid" -j RETURN
}

get_padding_fast() {
  cat <<'EOF'
stop=3
0=80-180
1=120-300
2=120-300
3=120-300
EOF
}

get_padding_strong() {
  cat <<'EOF'
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
EOF
}

write_padding_yaml() {
  local mode="$1"
  if [[ "$mode" == "strong" ]]; then
    get_padding_strong | sed 's/^/  /'
  else
    get_padding_fast | sed 's/^/  /'
  fi
}

issue_cert_standalone() {
  local domain="$1"

  print_block "申请 Let's Encrypt 证书"
  print_warn "当前使用 HTTP-01 standalone，会临时占用 80 端口，请确保域名已解析到本机"

  systemctl stop nginx 2>/dev/null || true
  systemctl stop apache2 2>/dev/null || true

  if certbot certonly --standalone -d "$domain" --non-interactive --agree-tos -m "admin@${domain}"; then
    print_ok "证书申请成功: ${domain}"
  else
    print_err "证书申请失败，请检查 DNS / 80端口 / 防火墙"
    exit 1
  fi
}

calc_wg_cidr24() {
  local wg_addr="$1"
  local ip="${wg_addr%%/*}"
  awk -F. '{print $1"."$2"."$3".0/24"}' <<< "$ip"
}

setup_exit_anytls_service() {
  local listen_port="$1"
  local wg_udp_port="$2"
  local domain="$3"
  local password="$4"
  local sni="$5"
  local padding_mode="$6"

  ensure_dirs
  init_state

  cat > "$ANY_CONFIG" <<EOF
log_level: "info"

idle_session_check_interval: "30s"
idle_session_timeout: "60s"
min_idle_session: 2

padding_scheme: |
$(write_padding_yaml "$padding_mode")

tunnels:
  - listen: "[::]:${listen_port}"
    remote: "127.0.0.1:${wg_udp_port}"
    sni: "${sni}"
    password: "${password}"
    cert: "/etc/letsencrypt/live/${domain}/fullchain.pem"
    key: "/etc/letsencrypt/live/${domain}/privkey.pem"
    max_conns: 0
EOF

  cat > /etc/systemd/system/anygo-exit.service <<EOF
[Unit]
Description=AnyTLS Exit Server
After=network-online.target wg-quick@${WG_IF}.service
Requires=wg-quick@${WG_IF}.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${ANY_BIN} -c ${ANY_CONFIG}
Restart=always
RestartSec=2
User=root
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  fix_anygo_permissions

  systemctl daemon-reload
  systemctl enable anygo-exit.service >/dev/null 2>&1 || true
  systemctl restart anygo-exit.service

  state_set '.anytls.domain' "$domain"
  state_set '.anytls.listen_port' "$listen_port"
  state_set '.anytls.remote_wg_port' "$wg_udp_port"
  state_set '.anytls.password' "$password"
  state_set '.anytls.sni' "$sni"
  state_set '.anytls.padding_mode' "$padding_mode"
}

setup_entry_anytls_service() {
  local remote_host="$1"
  local remote_port="$2"
  local local_udp_port="$3"
  local remote_wg_port="$4"
  local password="$5"
  local sni="$6"
  local verify_tls="$7"
  local padding_mode="$8"

  ensure_dirs
  init_state
  ensure_anygo_user

  local connect_host remote_ip
  remote_ip="$(resolve_ipv4 "$remote_host")"

  if [[ -n "$remote_ip" ]]; then
    connect_host="$remote_ip"
  else
    connect_host="$remote_host"
  fi

  local insecure_line=""
  if [[ "$verify_tls" =~ ^[Nn]$ ]]; then
    insecure_line='    insecure: true'
  else
    insecure_line='    insecure: false'
  fi

  cat > "$ANY_CONFIG" <<EOF
log_level: "info"

idle_session_check_interval: "30s"
idle_session_timeout: "60s"
min_idle_session: 2

padding_scheme: |
$(write_padding_yaml "$padding_mode")

tunnels:
  - listen: "127.0.0.1:${local_udp_port}"
    remote: "${connect_host}:${remote_port}"
    sni: "${sni}"
    password: "${password}"
${insecure_line}
    max_conns: 0
EOF

  cat > /etc/systemd/system/anygo-entry.service <<EOF
[Unit]
Description=AnyTLS Entry Client
After=network-online.target
Before=wg-quick@${WG_IF}.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${ANY_BIN} -c ${ANY_CONFIG}
Restart=always
RestartSec=2
User=${ANY_USER}
Group=${ANY_GROUP}
LimitNOFILE=1048576
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  fix_anygo_permissions

  systemctl daemon-reload
  systemctl enable anygo-entry.service >/dev/null 2>&1 || true
  systemctl restart anygo-entry.service

  state_set '.anytls.remote_host' "$remote_host"
  state_set '.anytls.remote_ip' "$remote_ip"
  state_set '.anytls.remote_port' "$remote_port"
  state_set '.anytls.local_udp_port' "$local_udp_port"
  state_set '.anytls.remote_wg_port' "$remote_wg_port"
  state_set '.anytls.password' "$password"
  state_set '.anytls.sni' "$sni"
  state_set '.anytls.verify_tls' "$verify_tls"
  state_set '.anytls.padding_mode' "$padding_mode"

  ensure_anygo_uid_bypass
}

configure_exit_wg() {
  local wg_addr="$1"
  local out_if="$2"
  local wg_udp_port="$3"
  local exit_private_key
  local cidr24

  ensure_dirs
  cd "$WG_DIR"

  if [[ ! -f exit_private.key ]]; then
    umask 077
    wg genkey | tee exit_private.key | wg pubkey > exit_public.key
  fi

  exit_private_key="$(cat exit_private.key)"
  cidr24="$(calc_wg_cidr24 "$wg_addr")"

  cat > "${WG_DIR}/${WG_IF}.conf" <<EOF
[Interface]
Address = ${wg_addr}
ListenPort = ${wg_udp_port}
PrivateKey = ${exit_private_key}
MTU = ${WG_SAFE_MTU}
PostUp = iptables -A FORWARD -i ${WG_IF} -o ${out_if} -j ACCEPT; iptables -A FORWARD -i ${out_if} -o ${WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -A POSTROUTING -s ${cidr24} -o ${out_if} -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i ${WG_IF} -o ${out_if} -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i ${out_if} -o ${WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables -t nat -D POSTROUTING -s ${cidr24} -o ${out_if} -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

EOF

  chmod 600 "${WG_DIR}/${WG_IF}.conf"
  enable_ip_forward_global

  systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
  wg-quick down "${WG_IF}" 2>/dev/null || true
  wg-quick up "${WG_IF}"

  local exit_public_key
  exit_public_key="$(cat "${WG_DIR}/exit_public.key" 2>/dev/null || true)"

  state_set '.wg.exit_public_key' "$exit_public_key"
}

configure_entry_wg() {
  local wg_addr="$1"
  local exit_wg_ip="$2"
  local exit_public_key="$3"
  local local_udp_port="$4"
  local entry_private_key
  local exit_wg_ip_no_mask="${exit_wg_ip%%/*}"

  ensure_dirs
  cd "$WG_DIR"

  if [[ ! -f entry_private.key ]]; then
    umask 077
    wg genkey | tee entry_private.key | wg pubkey > entry_public.key
  fi

  entry_private_key="$(cat entry_private.key)"

  cat > "${WG_DIR}/${WG_IF}.conf" <<EOF
[Interface]
Address = ${wg_addr}
PrivateKey = ${entry_private_key}
Table = off
MTU = ${WG_SAFE_MTU}
PostUp = ip rule show | grep -q "fwmark 0x1 lookup ${ROUTE_TABLE_ID}" || ip rule add fwmark 0x1 lookup ${ROUTE_TABLE_ID}; ip route replace default dev ${WG_IF} table ${ROUTE_TABLE_ID}; ip route replace ${exit_wg_ip_no_mask}/32 dev ${WG_IF}; iptables -t nat -C POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${WG_IF} -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip rule del fwmark 0x1 lookup ${ROUTE_TABLE_ID} 2>/dev/null || true; ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true; ip route del ${exit_wg_ip_no_mask}/32 dev ${WG_IF} 2>/dev/null || true; iptables -t nat -D POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${exit_public_key}
Endpoint = 127.0.0.1:${local_udp_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 20
EOF

  chmod 600 "${WG_DIR}/${WG_IF}.conf"

  local entry_public_key
  entry_public_key="$(cat "${WG_DIR}/entry_public.key" 2>/dev/null || true)"

  state_set '.wg.exit_wg_ip' "$exit_wg_ip_no_mask"
  state_set '.wg.entry_wg_ip' "$wg_addr"
  state_set '.wg.entry_public_key' "$entry_public_key"

  systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
  wg-quick down "${WG_IF}" 2>/dev/null || true
  wg-quick up "${WG_IF}"
}

ensure_server_bypass_route() {
  local remote_host remote_ip wan_if gateway

  remote_ip="$(state_get '.anytls.remote_ip')"

  if [[ -z "${remote_ip:-}" ]]; then
    remote_host="$(state_get '.anytls.remote_host')"
    [[ -n "$remote_host" ]] || return 0
    remote_ip="$(resolve_ipv4 "$remote_host")"
    [[ -n "$remote_ip" ]] || remote_ip="$remote_host"
  fi

  [[ -n "${remote_ip:-}" ]] || return 0

  wan_if="$(get_wan_if)"
  gateway="$(get_main_gateway)"
  [[ -n "$gateway" ]] || return 0

  ip route replace "${remote_ip}/32" via "$gateway" dev "$wan_if" 2>/dev/null || true
}

clear_mark_rules() {
  for chain in OUTPUT PREROUTING; do
    iptables -t mangle -S "$chain" 2>/dev/null | grep " MARK " | sed 's/^-A /-D /' | while read -r line; do
      [[ -n "$line" ]] && iptables -t mangle $line 2>/dev/null || true
    done || true
  done
}

ensure_policy_routing() {
  ip link show "$WG_IF" >/dev/null 2>&1 || return 0

  if ! ip rule show | grep -q "fwmark 0x1 lookup ${ROUTE_TABLE_ID}"; then
    ip rule add fwmark 0x1 lookup ${ROUTE_TABLE_ID} 2>/dev/null || true
  fi

  ip route replace default dev "$WG_IF" table ${ROUTE_TABLE_ID} 2>/dev/null || true
  ensure_server_bypass_route
  ensure_anygo_uid_bypass
}

remove_port_iptables_rules() {
  local port="$1"
  iptables -t mangle -D OUTPUT -p tcp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p udp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D PREROUTING -p tcp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D PREROUTING -p udp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
}

apply_port_rules_from_state() {
  clear_mark_rules
  ensure_anygo_uid_bypass

  local ports
  ports="$(jq -r '.ports[]?' "$STATE_FILE" 2>/dev/null || true)"

  while read -r p; do
    [[ -z "$p" ]] && continue

    iptables -t mangle -C OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1

    iptables -t mangle -C PREROUTING -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A PREROUTING -p tcp --dport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C PREROUTING -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A PREROUTING -p udp --dport "$p" -j MARK --set-mark 0x1
  done <<< "$ports"
}

add_forward_port_mapping() {
  local port="$1"
  local exit_ip wan_if

  exit_ip="$(state_get '.wg.exit_wg_ip')"
  [[ -n "$exit_ip" ]] || return 0

  wan_if="$(get_wan_if)"
  enable_ip_forward_global

  ip route replace "${exit_ip}/32" dev "$WG_IF" 2>/dev/null || true

  iptables -t nat -C PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || iptables -t nat -A PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}"
  iptables -t nat -C PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || iptables -t nat -A PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}"

  iptables -C FORWARD -i "$wan_if" -o "$WG_IF" -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  iptables -C FORWARD -i "$WG_IF" -o "$wan_if" -p tcp --sport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -p tcp --sport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  iptables -C FORWARD -i "$wan_if" -o "$WG_IF" -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -p udp --dport "$port" -j ACCEPT
  iptables -C FORWARD -i "$WG_IF" -o "$wan_if" -p udp --sport "$port" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -p udp --sport "$port" -j ACCEPT

  iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE
}

remove_forward_port_mapping() {
  local port="$1"
  local exit_ip wan_if

  exit_ip="$(state_get '.wg.exit_wg_ip')"
  [[ -n "$exit_ip" ]] || return 0

  wan_if="$(get_wan_if)"

  iptables -t nat -D PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true

  iptables -D FORWARD -i "$wan_if" -o "$WG_IF" -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WG_IF" -o "$wan_if" -p tcp --sport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

  iptables -D FORWARD -i "$wan_if" -o "$WG_IF" -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WG_IF" -o "$wan_if" -p udp --sport "$port" -j ACCEPT 2>/dev/null || true
}

enable_split_mode() {
  local exit_ip="" wan_if
  wan_if="$(get_wan_if)"
  exit_ip="$(state_get '.wg.exit_wg_ip')"

  if [[ -n "$exit_ip" ]]; then
    iptables -t nat -D PREROUTING -i "$wan_if" -p tcp ! --dport 22 -j DNAT --to-destination "$exit_ip" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "$wan_if" -p udp ! --dport 22 -j DNAT --to-destination "$exit_ip" 2>/dev/null || true
  fi

  ensure_policy_routing
  clear_mark_rules
  ensure_anygo_uid_bypass
  apply_port_rules_from_state

  local ports
  ports="$(jq -r '.ports[]?' "$STATE_FILE" 2>/dev/null || true)"

  while read -r p; do
    [[ -z "$p" ]] && continue
    add_forward_port_mapping "$p"
  done <<< "$ports"

  ip link set dev "$WG_IF" mtu "$WG_SAFE_MTU" 2>/dev/null || true
  set_mode_flag "split"
}

enable_global_mode() {
  local wan_if exit_ip=""

  ensure_policy_routing
  clear_mark_rules
  ensure_anygo_uid_bypass

  wan_if="$(get_wan_if)"
  exit_ip="$(state_get '.wg.exit_wg_ip')"

  enable_ip_forward_global
  ensure_server_bypass_route

  if [[ -n "$exit_ip" ]]; then
    ip route replace "${exit_ip}/32" dev "$WG_IF" 2>/dev/null || true

    iptables -t nat -C PREROUTING -i "$wan_if" -p tcp ! --dport 22 -j DNAT --to-destination "$exit_ip" 2>/dev/null || iptables -t nat -A PREROUTING -i "$wan_if" -p tcp ! --dport 22 -j DNAT --to-destination "$exit_ip"
    iptables -t nat -C PREROUTING -i "$wan_if" -p udp ! --dport 22 -j DNAT --to-destination "$exit_ip" 2>/dev/null || iptables -t nat -A PREROUTING -i "$wan_if" -p udp ! --dport 22 -j DNAT --to-destination "$exit_ip"

    iptables -C FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -C FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE
  fi

  iptables -t mangle -C OUTPUT -o lo -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -o lo -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --sport 22 -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --dport 22 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport 22 -j RETURN

  iptables -t mangle -C OUTPUT -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A OUTPUT -j MARK --set-mark 0x1
  iptables -t mangle -C PREROUTING -i "$wan_if" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A PREROUTING -i "$wan_if" -j MARK --set-mark 0x1

  ip link set dev "$WG_IF" mtu "$WG_SAFE_MTU" 2>/dev/null || true
  set_mode_flag "global"
}

suggest_next_peer_ip() {
  local conf="${WG_DIR}/${WG_IF}.conf"
  local base="10.66.0"
  local used=""

  if [[ -f "$conf" ]]; then
    used="$(grep -E "^AllowedIPs" "$conf" 2>/dev/null | awk '{print $3}' | cut -d/ -f1 | awk -F. '{print $4}' | sort -n || true)"
  fi

  for i in $(seq 2 254); do
    if ! echo "$used" | grep -qx "$i"; then
      echo "${base}.${i}/32"
      return
    fi
  done

  echo "10.66.0.2/32"
}

add_exit_peer() {
  [[ "$(get_role)" == "exit" ]] || {
    print_err "当前机器不是出口服务器"
    return 1
  }

  local peer_name peer_ip peer_pub suggested_ip

  print_block "添加入口 Peer 到出口 WG"

  read -rp "入口名称备注，例如 hk01 / jp01: " peer_name
  peer_name="${peer_name:-entry}"

  suggested_ip="$(suggest_next_peer_ip)"

  while true; do
    read -rp "入口 WireGuard IP，默认 ${suggested_ip}: " peer_ip
    peer_ip="${peer_ip:-$suggested_ip}"
    [[ -n "$peer_ip" ]] && break
    print_err "IP 不能为空"
  done

  while true; do
    read -rp "入口服务器公钥: " peer_pub
    [[ -n "$peer_pub" ]] && break
    print_err "公钥不能为空"
  done

  if grep -q "$peer_pub" "${WG_DIR}/${WG_IF}.conf" 2>/dev/null; then
    print_warn "该入口公钥已存在，跳过重复添加"
    return 0
  fi

  cat >> "${WG_DIR}/${WG_IF}.conf" <<EOF

# ${peer_name}
[Peer]
PublicKey = ${peer_pub}
AllowedIPs = ${peer_ip}
EOF

  wg syncconf "$WG_IF" <(wg-quick strip "$WG_IF") 2>/dev/null || systemctl restart "wg-quick@${WG_IF}.service"

  print_ok "已添加入口 Peer: ${peer_name} ${peer_ip}"
}

configure_exit() {
  set_role "exit"
  ensure_dirs
  init_state

  print_block "配置出口服务器"

  install_base_packages
  check_anygo_bin

  cd "$WG_DIR"

  if [[ ! -f exit_private.key ]]; then
    umask 077
    wg genkey | tee exit_private.key | wg pubkey > exit_public.key
  fi

  local exit_public_key
  exit_public_key="$(cat exit_public.key)"

  print_block "本机出口 WireGuard 公钥"
  echo "$exit_public_key"

  local domain listen_port wg_addr wg_udp_port out_if password sni padding_mode cert_choice padding_choice

  while true; do
    read -rp "出口域名，必须解析到本机: " domain
    [[ -n "$domain" ]] && break
    print_err "域名不能为空"
  done

  read -rp "AnyTLS 对外监听端口，默认 ${ANY_SERVER_PORT_DEFAULT}: " listen_port
  listen_port="${listen_port:-$ANY_SERVER_PORT_DEFAULT}"

  read -rp "出口 WG 内网 IP，默认 10.66.0.1/24: " wg_addr
  wg_addr="${wg_addr:-10.66.0.1/24}"

  read -rp "出口 WG UDP 端口，默认 ${WG_SERVER_PORT_DEFAULT}: " wg_udp_port
  wg_udp_port="${wg_udp_port:-$WG_SERVER_PORT_DEFAULT}"

  local default_if
  default_if="$(get_wan_if)"
  read -rp "出口公网网卡，默认 ${default_if}: " out_if
  out_if="${out_if:-$default_if}"

  local default_pass
  default_pass="$(rand_pass)"
  read -rp "AnyTLS 密码，默认随机 ${default_pass}: " password
  password="${password:-$default_pass}"

  read -rp "SNI，默认使用出口真实域名 ${domain}: " sni
  sni="${sni:-$domain}"

  echo
  echo "Padding 模式："
  echo "1) fast   速度优先"
  echo "2) strong 抗识别优先，流量更大"
  read -rp "请选择，默认 1: " padding_choice
  if [[ "${padding_choice:-1}" == "2" ]]; then
    padding_mode="strong"
  else
    padding_mode="fast"
  fi

  read -rp "是否现在申请 Let's Encrypt 证书? (Y/n): " cert_choice
  cert_choice="${cert_choice:-Y}"

  if [[ "$cert_choice" =~ ^[Yy]$ ]]; then
    issue_cert_standalone "$domain"
  else
    print_warn "跳过证书申请，请确保已有："
    echo "/etc/letsencrypt/live/${domain}/fullchain.pem"
    echo "/etc/letsencrypt/live/${domain}/privkey.pem"
  fi

  configure_exit_wg "$wg_addr" "$out_if" "$wg_udp_port"
  setup_exit_anytls_service "$listen_port" "$wg_udp_port" "$domain" "$password" "$sni" "$padding_mode"

  state_set '.role' "exit"
  state_set '.wg.exit_public_key' "$exit_public_key"

  print_block "出口配置完成"
  echo "出口域名: ${domain}"
  echo "AnyTLS 端口: ${listen_port}"
  echo "WG 地址: ${wg_addr}"
  echo "WG UDP: ${wg_udp_port}"
  echo "AnyTLS 密码: ${password}"
  echo "SNI: ${sni}"
  echo "Padding: ${padding_mode}"
  echo
  echo "把下面这个出口公钥复制给入口机："
  echo "${exit_public_key}"
  echo
  print_warn "下一步：去入口机配置入口，然后回出口机菜单选择 12 添加入口 Peer"
}

configure_entry() {
  set_role "entry"
  ensure_dirs
  init_state

  print_block "配置入口服务器"

  install_base_packages
  check_anygo_bin

  cd "$WG_DIR"

  if [[ ! -f entry_private.key ]]; then
    umask 077
    wg genkey | tee entry_private.key | wg pubkey > entry_public.key
  fi

  local entry_public_key
  entry_public_key="$(cat entry_public.key)"

  print_block "本机入口 WireGuard 公钥"
  echo "$entry_public_key"

  local wg_addr exit_wg_ip exit_public_key remote_host remote_port local_udp_port remote_wg_port password sni verify_tls padding_mode padding_choice

  read -rp "入口 WG 内网 IP，例如 10.66.0.2/24: " wg_addr
  wg_addr="${wg_addr:-10.66.0.2/24}"

  read -rp "出口 WG 内网 IP，默认 10.66.0.1/32: " exit_wg_ip
  exit_wg_ip="${exit_wg_ip:-10.66.0.1/32}"

  while true; do
    read -rp "出口域名/IP: " remote_host
    [[ -n "$remote_host" ]] && break
    print_err "出口地址不能为空"
  done

  read -rp "出口 AnyTLS 端口，默认 ${ANY_SERVER_PORT_DEFAULT}: " remote_port
  remote_port="${remote_port:-$ANY_SERVER_PORT_DEFAULT}"

  read -rp "入口本地 AnyTLS UDP 监听端口，默认 ${ANY_LOCAL_UDP_PORT_DEFAULT}: " local_udp_port
  local_udp_port="${local_udp_port:-$ANY_LOCAL_UDP_PORT_DEFAULT}"

  read -rp "远端出口 WG UDP 端口，默认 ${WG_SERVER_PORT_DEFAULT}: " remote_wg_port
  remote_wg_port="${remote_wg_port:-$WG_SERVER_PORT_DEFAULT}"

  while true; do
    read -rp "AnyTLS 密码，必须和出口一致: " password
    [[ -n "$password" ]] && break
    print_err "密码不能为空"
  done

  read -rp "SNI，默认使用出口域名 ${remote_host}: " sni
  sni="${sni:-$remote_host}"

  read -rp "是否严格校验证书? (Y/n): " verify_tls
  verify_tls="${verify_tls:-Y}"

  echo
  echo "Padding 模式必须和出口一致："
  echo "1) fast"
  echo "2) strong"
  read -rp "请选择，默认 1: " padding_choice
  if [[ "${padding_choice:-1}" == "2" ]]; then
    padding_mode="strong"
  else
    padding_mode="fast"
  fi

  while true; do
    read -rp "出口 WireGuard 公钥: " exit_public_key
    [[ -n "$exit_public_key" ]] && break
    print_err "出口公钥不能为空"
  done

  setup_entry_anytls_service "$remote_host" "$remote_port" "$local_udp_port" "$remote_wg_port" "$password" "$sni" "$verify_tls" "$padding_mode"
  configure_entry_wg "$wg_addr" "$exit_wg_ip" "$exit_public_key" "$local_udp_port"

  ensure_server_bypass_route
  ensure_anygo_uid_bypass
  set_mode_flag "split"
  enable_split_mode

  state_set '.role' "entry"
  state_set '.wg.entry_public_key' "$entry_public_key"

  print_block "入口配置完成"
  echo "入口 WG 地址: ${wg_addr}"
  echo "出口地址: ${remote_host}:${remote_port}"
  echo "AnyTLS 实际连接 IP: $(state_get '.anytls.remote_ip')"
  echo "WG Endpoint: 127.0.0.1:${local_udp_port}"
  echo
  echo "把下面这个入口公钥复制到出口机，菜单 12 添加入口 Peer："
  echo "${entry_public_key}"
}

update_entry_remote() {
  [[ "$(get_role)" == "entry" ]] || {
    print_err "当前机器不是入口服务器"
    return 1
  }

  local saved_host saved_port saved_pass saved_verify saved_local saved_remote_wg
  saved_host="$(state_get '.anytls.remote_host')"
  saved_port="$(state_get '.anytls.remote_port')"
  saved_pass="$(state_get '.anytls.password')"
  saved_verify="$(state_get '.anytls.verify_tls')"
  saved_local="$(state_get '.anytls.local_udp_port')"
  saved_remote_wg="$(state_get '.anytls.remote_wg_port')"

  local remote_host remote_port password sni verify_tls local_udp remote_wg padding_mode padding_choice

  read -rp "新出口域名/IP，默认 ${saved_host}: " remote_host
  remote_host="${remote_host:-$saved_host}"

  read -rp "新出口 AnyTLS 端口，默认 ${saved_port:-443}: " remote_port
  remote_port="${remote_port:-${saved_port:-443}}"

  read -rp "AnyTLS 密码，默认使用旧密码: " password
  password="${password:-$saved_pass}"

  read -rp "SNI，默认 ${remote_host}: " sni
  sni="${sni:-$remote_host}"

  read -rp "是否严格校验证书，默认 ${saved_verify:-Y}: " verify_tls
  verify_tls="${verify_tls:-${saved_verify:-Y}}"

  local_udp="${saved_local:-$ANY_LOCAL_UDP_PORT_DEFAULT}"
  remote_wg="${saved_remote_wg:-$WG_SERVER_PORT_DEFAULT}"

  echo
  echo "Padding 模式："
  echo "1) fast"
  echo "2) strong"
  read -rp "请选择，默认 1: " padding_choice
  if [[ "${padding_choice:-1}" == "2" ]]; then
    padding_mode="strong"
  else
    padding_mode="fast"
  fi

  setup_entry_anytls_service "$remote_host" "$remote_port" "$local_udp" "$remote_wg" "$password" "$sni" "$verify_tls" "$padding_mode"
  ensure_server_bypass_route
  ensure_anygo_uid_bypass

  print_ok "入口远端已更新: ${remote_host}:${remote_port}"
  echo "AnyTLS 实际连接 IP: $(state_get '.anytls.remote_ip')"
}

refresh_remote_ip() {
  [[ "$(get_role)" == "entry" ]] || {
    print_err "该功能仅入口服务器使用"
    return 1
  }

  local host ip
  host="$(state_get '.anytls.remote_host')"

  if [[ -z "$host" ]]; then
    print_err "未找到出口域名"
    return 1
  fi

  ip="$(resolve_ipv4 "$host")"

  if [[ -z "$ip" ]]; then
    print_err "解析失败: $host"
    return 1
  fi

  state_set '.anytls.remote_ip' "$ip"
  ensure_server_bypass_route
  ensure_anygo_uid_bypass

  local remote_port local_udp remote_wg password sni verify padding
  remote_port="$(state_get '.anytls.remote_port')"
  local_udp="$(state_get '.anytls.local_udp_port')"
  remote_wg="$(state_get '.anytls.remote_wg_port')"
  password="$(state_get '.anytls.password')"
  sni="$(state_get '.anytls.sni')"
  verify="$(state_get '.anytls.verify_tls')"
  padding="$(state_get '.anytls.padding_mode')"

  setup_entry_anytls_service "$host" "$remote_port" "$local_udp" "$remote_wg" "$password" "$sni" "$verify" "$padding"

  print_ok "已重新解析并更新出口 IP: ${host} -> ${ip}"
}

manage_entry_ports() {
  [[ "$(get_role)" == "entry" ]] || {
    print_err "当前机器不是入口服务器"
    return 1
  }

  ensure_policy_routing

  while true; do
    print_block "入口端口分流管理"
    echo "1) 查看当前分流端口"
    echo "2) 添加分流端口"
    echo "3) 删除分流端口"
    echo "0) 返回"
    read -rp "请选择: " sub

    case "$sub" in
      1)
        local ports
        ports="$(jq -r '.ports[]?' "$STATE_FILE" 2>/dev/null || true)"
        if [[ -n "$ports" ]]; then
          echo "$ports"
        else
          print_warn "当前没有分流端口"
        fi
        ;;
      2)
        local p
        read -rp "端口: " p
        if [[ "$p" =~ ^[0-9]+$ ]] && [[ "$p" -ge 1 ]] && [[ "$p" -le 65535 ]] && [[ "$p" -ne 22 ]]; then
          state_add_port "$p"
          apply_port_rules_from_state
          add_forward_port_mapping "$p"
          print_ok "已添加端口: $p"
        else
          print_err "端口不合法，且不能是 22"
        fi
        ;;
      3)
        local p
        read -rp "要删除的端口: " p
        if [[ "$p" =~ ^[0-9]+$ ]]; then
          state_remove_port "$p"
          remove_port_iptables_rules "$p"
          remove_forward_port_mapping "$p"
          print_ok "已删除端口: $p"
        else
          print_err "端口不合法"
        fi
        ;;
      0) break ;;
      *) print_err "无效选择" ;;
    esac
  done
}

manage_entry_mode() {
  [[ "$(get_role)" == "entry" ]] || {
    print_err "当前机器不是入口服务器"
    return 1
  }

  while true; do
    print_block "入口模式管理"
    echo "当前模式: $(get_current_mode)"
    echo "1) 切换为全局模式"
    echo "2) 切换为分流模式"
    echo "0) 返回"
    read -rp "请选择: " sub

    case "$sub" in
      1)
        enable_global_mode
        print_ok "已切换为全局模式"
        ;;
      2)
        enable_split_mode
        print_ok "已切换为分流模式"
        ;;
      0) break ;;
      *) print_err "无效选择" ;;
    esac
  done
}

show_status() {
  local role mode
  role="$(get_role)"
  mode="$(get_current_mode)"

  print_block "当前状态"

  echo "角色: ${role}"
  echo "模式: ${mode}"
  echo

  if [[ "$role" == "exit" ]]; then
    echo "================ 出口可复制信息 ================"
    echo "出口域名: $(state_get '.anytls.domain')"
    echo "AnyTLS端口: $(state_get '.anytls.listen_port')"
    echo "AnyTLS密码: $(state_get '.anytls.password')"
    echo "SNI: $(state_get '.anytls.sni')"
    [[ -f "${WG_DIR}/exit_public.key" ]] && echo "出口WG公钥: $(cat "${WG_DIR}/exit_public.key" 2>/dev/null || true)"
    [[ -f "${WG_DIR}/exit_private.key" ]] && echo "出口WG私钥: 已存在，不显示"
    echo

    echo "入口机配置时需要填："
    echo "出口域名 / AnyTLS端口 / AnyTLS密码 / SNI / 出口WG公钥"
    echo

    echo "出口当前已添加的入口 Peer："
    if [[ -f "${WG_DIR}/${WG_IF}.conf" ]]; then
      grep -nE "^# |^\[Peer\]|^PublicKey|^AllowedIPs" "${WG_DIR}/${WG_IF}.conf" 2>/dev/null || true
    else
      print_warn "未找到 ${WG_DIR}/${WG_IF}.conf"
    fi

  elif [[ "$role" == "entry" ]]; then
    echo "================ 入口可复制信息 ================"
    [[ -f "${WG_DIR}/entry_public.key" ]] && echo "入口WG公钥: $(cat "${WG_DIR}/entry_public.key" 2>/dev/null || true)"
    [[ -f "${WG_DIR}/entry_private.key" ]] && echo "入口WG私钥: 已存在，不显示"
    echo "出口域名/IP: $(state_get '.anytls.remote_host')"
    echo "AnyTLS实际连接IP: $(state_get '.anytls.remote_ip')"
    echo "出口AnyTLS端口: $(state_get '.anytls.remote_port')"
    echo "AnyTLS密码: $(state_get '.anytls.password')"
    echo "SNI: $(state_get '.anytls.sni')"
    echo "本地AnyTLS UDP监听: $(state_get '.anytls.local_udp_port')"
    echo "出口WG内网IP: $(state_get '.wg.exit_wg_ip')"
    echo

    echo "回出口机菜单 12 添加 Peer 时需要填："
    echo "入口WG公钥 + 入口WG内网IP，例如 10.66.0.2/32"
    echo

    echo "当前入口分流端口："
    jq -r '.ports[]?' "$STATE_FILE" 2>/dev/null || true

  else
    print_warn "当前还没有配置角色"
  fi

  echo
  echo "================ WireGuard 状态 ================"
  wg show || true

  echo
  echo "================ systemd 状态 ================"
  systemctl --no-pager --full status anygo-exit.service 2>/dev/null | sed -n '1,12p' || true
  systemctl --no-pager --full status anygo-entry.service 2>/dev/null | sed -n '1,12p' || true

  echo
  echo "================ 监听端口 ================"
  ss -lntup | grep -E 'anygo|wg|51820|443' || true

  echo
  echo "================ UID免检规则 ================"
  iptables -t mangle -S OUTPUT 2>/dev/null | grep -E "uid-owner|MARK|RETURN" || true

  echo
  echo "================ WG 配置关键信息 ================"
  grep -nE "^Endpoint|^Address|^AllowedIPs|^ListenPort" "${WG_DIR}/${WG_IF}.conf" 2>/dev/null || true
}

start_all() {
  local role
  role="$(get_role)"

  print_block "启动服务"

  if [[ "$role" == "exit" ]]; then
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    wg-quick up "$WG_IF" 2>/dev/null || true
    systemctl restart anygo-exit.service 2>/dev/null || true
    print_ok "出口服务已启动"
  elif [[ "$role" == "entry" ]]; then
    systemctl restart anygo-entry.service 2>/dev/null || true
    sleep 1
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    wg-quick up "$WG_IF" 2>/dev/null || true
    ensure_server_bypass_route
    ensure_anygo_uid_bypass

    if [[ "$(get_current_mode)" == "global" ]]; then
      enable_global_mode
    else
      enable_split_mode
    fi

    print_ok "入口服务已启动"
  else
    print_err "还没有配置角色"
  fi
}

stop_all() {
  local role
  role="$(get_role)"

  print_block "停止服务"

  if [[ "$role" == "exit" ]]; then
    systemctl stop anygo-exit.service 2>/dev/null || true
  elif [[ "$role" == "entry" ]]; then
    systemctl stop anygo-entry.service 2>/dev/null || true
  fi

  wg-quick down "$WG_IF" 2>/dev/null || true
  ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true
  ip rule del fwmark 0x1 lookup ${ROUTE_TABLE_ID} 2>/dev/null || true
  clear_mark_rules

  print_ok "已停止"
}

restart_all() {
  stop_all
  start_all
}

uninstall_all() {
  print_block "卸载并清理"

  set +e

  systemctl stop anygo-exit.service 2>/dev/null || true
  systemctl stop anygo-entry.service 2>/dev/null || true
  systemctl disable anygo-exit.service 2>/dev/null || true
  systemctl disable anygo-entry.service 2>/dev/null || true
  rm -f /etc/systemd/system/anygo-exit.service /etc/systemd/system/anygo-entry.service
  systemctl daemon-reload 2>/dev/null || true

  systemctl stop "wg-quick@${WG_IF}.service" 2>/dev/null || true
  systemctl disable "wg-quick@${WG_IF}.service" 2>/dev/null || true
  wg-quick down "$WG_IF" 2>/dev/null || true

  ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true
  ip rule del fwmark 0x1 lookup ${ROUTE_TABLE_ID} 2>/dev/null || true
  clear_mark_rules

  local ports
  ports="$(jq -r '.ports[]?' "$STATE_FILE" 2>/dev/null || true)"
  while read -r p; do
    [[ -z "$p" ]] && continue
    remove_forward_port_mapping "$p"
    remove_port_iptables_rules "$p"
  done <<< "$ports"

  iptables -t nat -S PREROUTING 2>/dev/null | grep -E "DNAT|${WG_IF}" | sed 's/^-A /-D /' | while read -r line; do
    iptables -t nat $line 2>/dev/null || true
  done

  iptables -t nat -S POSTROUTING 2>/dev/null | grep -E "${WG_IF}|MASQUERADE" | sed 's/^-A /-D /' | while read -r line; do
    iptables -t nat $line 2>/dev/null || true
  done

  iptables -S FORWARD 2>/dev/null | grep -E "${WG_IF}" | sed 's/^-A /-D /' | while read -r line; do
    iptables $line 2>/dev/null || true
  done

  rm -rf "$ANY_DIR"
  rm -rf "$WG_DIR"

  sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null || true
  sysctl -p >/dev/null 2>&1 || true

  print_ok "配置和服务已清理"
  print_warn "没有删除 ${ANY_BIN}，如需删除请手动执行：rm -f ${ANY_BIN}"

  set -e
}

test_wrap_status() {
  print_block "检测 WG 是否被 AnyTLS 包住"

  echo "入口正确状态应该是："
  echo "1) WG Endpoint = 127.0.0.1:51820"
  echo "2) AnyGo 进程 UID 被 OUTPUT 免检"
  echo "3) 公网只看到入口 -> 出口:AnyTLS端口"
  echo "4) 不应该看到入口 -> 出口:51820 UDP"
  echo

  echo "当前 wg 配置 Endpoint："
  grep -n "Endpoint" "${WG_DIR}/${WG_IF}.conf" 2>/dev/null || true
  echo

  echo "当前 AnyTLS 配置："
  sed -n '1,120p' "$ANY_CONFIG" 2>/dev/null || true
  echo

  echo "当前 UID 免检规则："
  iptables -t mangle -S OUTPUT 2>/dev/null | grep uid-owner || true
  echo

  echo "入口机检测命令："
  echo "  tcpdump -ni any udp port 51820"
  echo
  echo "公网连接检测命令："
  echo "  tcpdump -ni any port $(state_get '.anytls.remote_port')"
}

export_node_info() {
  print_block "导出当前节点信息"

  init_state

  local role
  role="$(get_role)"

  if [[ "$role" == "exit" ]]; then
    jq -r '
      "角色: exit",
      "出口域名: \(.anytls.domain)",
      "AnyTLS端口: \(.anytls.listen_port)",
      "AnyTLS密码: \(.anytls.password)",
      "SNI: \(.anytls.sni)",
      "出口WG公钥: \(.wg.exit_public_key)"
    ' "$STATE_FILE"
  elif [[ "$role" == "entry" ]]; then
    jq -r '
      "角色: entry",
      "入口WG公钥: \(.wg.entry_public_key)",
      "入口WG IP: \(.wg.entry_wg_ip)",
      "出口域名: \(.anytls.remote_host)",
      "出口IP: \(.anytls.remote_ip)",
      "出口AnyTLS端口: \(.anytls.remote_port)",
      "SNI: \(.anytls.sni)"
    ' "$STATE_FILE"
  else
    print_warn "当前未配置角色"
  fi
}

show_json_state() {
  print_block "JSON 状态"
  init_state
  jq . "$STATE_FILE"
}

while true; do
  init_state

  echo
  echo "================ WG + AnyTLS/AnyGo JSON + UID版 ================"
  echo "1) 配置为出口服务器"
  echo "2) 配置为入口服务器"
  echo "3) 查看状态"
  echo "4) 启动"
  echo "5) 停止"
  echo "6) 重启"
  echo "7) 卸载并清理"
  echo "8) 入口端口分流管理"
  echo "9) 入口模式管理，全局 / 分流"
  echo "10) 修改入口连接的出口域名/IP"
  echo "11) 检测 WG 是否被 AnyTLS 包住"
  echo "12) 出口添加入口 Peer"
  echo "13) 导出当前节点信息"
  echo "14) 重新解析出口 IP，仅入口"
  echo "15) 查看 JSON 状态"
  echo "0) 退出"
  echo "==============================================================="
  read -rp "请选择: " choice

  case "$choice" in
    1) configure_exit ;;
    2) configure_entry ;;
    3) show_status ;;
    4) start_all ;;
    5) stop_all ;;
    6) restart_all ;;
    7) uninstall_all ;;
    8) manage_entry_ports ;;
    9) manage_entry_mode ;;
    10) update_entry_remote ;;
    11) test_wrap_status ;;
    12) add_exit_peer ;;
    13) export_node_info ;;
    14) refresh_remote_ip ;;
    15) show_json_state ;;
    0) exit 0 ;;
    *) print_err "无效选择" ;;
  esac
done
