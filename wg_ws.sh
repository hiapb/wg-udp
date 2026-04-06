#!/usr/bin/env bash
set -euo pipefail

WG_IF="wg0"
WG_DIR="/etc/wireguard"
PORT_LIST_FILE="${WG_DIR}/.wg_ports"
MODE_FILE="${WG_DIR}/.wg_mode"
EXIT_WG_IP_FILE="${WG_DIR}/.exit_wg_ip"
ROLE_FILE="${WG_DIR}/.wg_role"

WST_DIR="/etc/wstunnel"
WSTUNNEL_BIN="/usr/local/bin/wstunnel"
WSTUNNEL_VERSION="10.5.2"
WST_REMOTE_HOST_FILE="${WST_DIR}/remote_host"
WST_REMOTE_PORT_FILE="${WST_DIR}/remote_port"
WST_PATH_FILE="${WST_DIR}/path_prefix"
WST_VERIFY_FILE="${WST_DIR}/verify_tls"
WST_DOMAIN_FILE="${WST_DIR}/domain"
WST_NGINX_SITE_FILE="${WST_DIR}/nginx_site"
WST_WG_UDP_PORT_FILE="${WST_DIR}/wg_udp_port"
WST_LOCAL_UDP_PORT_FILE="${WST_DIR}/local_udp_port"

NGINX_SITE_DIR="/etc/nginx/sites-available"
NGINX_SITE_ENABLED_DIR="/etc/nginx/sites-enabled"
WEB_ROOT_BASE="/var/www"

WG_SAFE_MTU=1320
WG_SERVER_PORT_DEFAULT=51820
WST_LOCAL_UDP_PORT_DEFAULT=51820
ROUTE_TABLE_ID=51820

if [[ $EUID -ne 0 ]]; then
  echo "❌ 请用 root 运行"
  exit 1
fi

print_block() {
  local title="$1"
  echo
  echo "=================================================="
  echo "$title"
  echo "=================================================="
}

print_step() {
  local step="$1"
  local text="$2"
  echo "[$step] $text"
}

print_ok() {
  echo "✅ $1"
}

print_warn() {
  echo "⚠️  $1"
}

print_err() {
  echo "❌ $1"
}

get_role() {
  if [[ -f "$ROLE_FILE" ]]; then
    cat "$ROLE_FILE" 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

set_role() {
  mkdir -p "$(dirname "$ROLE_FILE")"
  echo "$1" > "$ROLE_FILE"
}

rand_hex16() {
  tr -dc 'a-f0-9' </dev/urandom 2>/dev/null | head -c 16 || true
}

normalize_path_prefix() {
  local p="${1:-}"
  p="${p#/}"
  p="${p%/}"
  echo "$p"
}

resolve_ipv4() {
  local host="$1"
  getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}' || true
}

ensure_dirs() {
  mkdir -p "$WG_DIR" "$WST_DIR"
  chmod 700 "$WG_DIR" "$WST_DIR" 2>/dev/null || true
}

get_wan_if() {
  local wan
  wan=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)
  echo "${wan:-eth0}"
}

get_main_gateway() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="via"){print $(i+1); exit}}}' || true
}

enable_ip_forward_global() {
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null || true
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
}

save_wst_params() {
  local host="$1" port="$2" path="$3" verify="$4"
  path="$(normalize_path_prefix "$path")"
  echo "$host" > "$WST_REMOTE_HOST_FILE"
  echo "$port" > "$WST_REMOTE_PORT_FILE"
  echo "$path" > "$WST_PATH_FILE"
  echo "$verify" > "$WST_VERIFY_FILE"
}

ensure_server_bypass_route() {
  local remote_host remote_ip wan_if gateway
  [[ -f "$WST_REMOTE_HOST_FILE" ]] || return 0
  remote_host="$(cat "$WST_REMOTE_HOST_FILE" 2>/dev/null || true)"
  [[ -n "$remote_host" ]] || return 0
  remote_ip="$(resolve_ipv4 "$remote_host")"
  [[ -n "$remote_ip" ]] || remote_ip="$remote_host"
  wan_if="$(get_wan_if)"
  gateway="$(get_main_gateway)"
  [[ -n "$gateway" ]] || return 0
  ip route replace "${remote_ip}/32" via "$gateway" dev "$wan_if" 2>/dev/null || true
}

install_base_packages() {
  print_step "1/3" "安装基础依赖..."
  export DEBIAN_FRONTEND=noninteractive
  apt update -y >/dev/null 2>&1 || true
  apt install -y curl tar ca-certificates iproute2 iptables openssl lsb-release nginx certbot python3-certbot-nginx >/dev/null 2>&1
  print_ok "基础依赖安装完成"
}

install_wireguard() {
  print_step "2/3" "安装 WireGuard..."
  export DEBIAN_FRONTEND=noninteractive
  apt update -y >/dev/null 2>&1 || true
  apt install -y wireguard wireguard-tools >/dev/null 2>&1
  print_ok "WireGuard 安装完成"
}

install_wstunnel() {
  print_step "3/3" "检查并安装 wstunnel..."
  if [[ -x "$WSTUNNEL_BIN" ]]; then
    local cur_ver
    cur_ver=$("$WSTUNNEL_BIN" --version 2>/dev/null || true)
    if [[ -n "$cur_ver" ]]; then
      print_ok "wstunnel 已存在，无需重复安装"
      return 0
    fi
  fi

  mkdir -p "$WST_DIR"
  local arch file url_base url_bin url_sum tmpdir bin_name
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) file="wstunnel_${WSTUNNEL_VERSION}_linux_amd64.tar.gz" ;;
    aarch64|arm64) file="wstunnel_${WSTUNNEL_VERSION}_linux_arm64.tar.gz" ;;
    armv7l|armv6l) file="wstunnel_${WSTUNNEL_VERSION}_linux_armv6.tar.gz" ;;
    *) print_err "不支持架构: $arch"; exit 1 ;;
  esac

  url_base="https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}"
  url_bin="${url_base}/${file}"
  url_sum="${url_base}/checksums.txt"
  tmpdir="$(mktemp -d)"

  echo "⏳ 正在下载并安装 wstunnel ..."
  (
    cd "$tmpdir"
    curl -fsSL "$url_sum" -o checksums.txt
    curl -fL "$url_bin" -o "$file"
    grep "$file" checksums.txt | sha256sum -c - >/dev/null
    tar -xzf "$file"
    bin_name="$(find . -maxdepth 1 -type f \( -name 'wstunnel' -o -name 'wstunnel-cli' \) | head -n1)"
    install -m 0755 "$bin_name" "$WSTUNNEL_BIN"
  )
  rm -rf "$tmpdir"
  print_ok "wstunnel 安装完成"
}

write_nginx_http_site_for_acme() {
  local domain="$1"
  local site_file="${NGINX_SITE_DIR}/${domain}.conf"
  local web_root="${WEB_ROOT_BASE}/${domain}"

  mkdir -p "$web_root"

  cat > "$site_file" <<EOF
server {
    listen 80;
    server_name ${domain};
    root ${web_root};

    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        try_files \$uri =404;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF

  ln -sf "$site_file" "${NGINX_SITE_ENABLED_DIR}/${domain}.conf"
  nginx -t >/dev/null
  systemctl restart nginx
  echo "$site_file" > "$WST_NGINX_SITE_FILE"
}

issue_letsencrypt_cert() {
  local domain="$1"
  print_step "证书" "正在申请 HTTPS 证书: ${domain}"
  certbot --nginx -d "$domain" --non-interactive --agree-tos -m "admin@${domain}" --redirect >/dev/null 2>&1
  print_ok "HTTPS 证书申请完成: ${domain}"
}

write_nginx_https_wstunnel_site() {
  local domain="$1"
  local backend_port="$2"
  local path_prefix="$3"
  local https_port="$4"

  local site_file="${NGINX_SITE_DIR}/${domain}.conf"
  local web_root="${WEB_ROOT_BASE}/${domain}"
  local https_redirect_target

  path_prefix="$(normalize_path_prefix "$path_prefix")"
  mkdir -p "$web_root"

  if [[ "$https_port" == "443" ]]; then
    https_redirect_target="https://\$host\$request_uri"
  else
    https_redirect_target="https://\$host:${https_port}\$request_uri"
  fi

  cat > "$web_root/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Global Network Speed Test</title>
<style>
    :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9; --text-muted: #8b949e; --primary: #58a6ff; --success: #238636; --success-hover: #2ea043; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg); color: var(--text); display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 40px; width: 100%; max-width: 480px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); text-align: center; }
    h1 { font-size: 24px; font-weight: 600; margin-bottom: 8px; color: #fff; }
    p.desc { font-size: 14px; color: var(--text-muted); margin-bottom: 32px; }
    .progress-track { width: 100%; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin-bottom: 32px; display: none; }
    .progress-fill { width: 0%; height: 100%; background: var(--primary); transition: width 0.1s linear; }
    .metrics-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 32px; }
    .metric-box { background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 8px; padding: 16px 8px; }
    .metric-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); display: block; margin-bottom: 8px; }
    .metric-value { font-size: 20px; font-weight: 600; color: #fff; font-variant-numeric: tabular-nums; }
    .metric-unit { font-size: 12px; font-weight: 400; color: var(--text-muted); }
    .btn { background: var(--success); color: #fff; border: none; width: 100%; padding: 14px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
    .btn:hover { background: var(--success-hover); }
    .btn:disabled { background: var(--border); color: var(--text-muted); cursor: not-allowed; }
</style>
</head>
<body>
<div class="card">
    <h1>Edge Speed Test</h1>
    <p class="desc">Verify connection quality to the nearest edge node.</p>
    
    <div class="progress-track" id="pb"><div class="progress-fill" id="pf"></div></div>
    
    <div class="metrics-grid">
        <div class="metric-box">
            <span class="metric-label">Ping</span>
            <span class="metric-value" id="ping">--</span> <span class="metric-unit">ms</span>
        </div>
        <div class="metric-box">
            <span class="metric-label">Download</span>
            <span class="metric-value" id="dl">--</span> <span class="metric-unit">Mbps</span>
        </div>
        <div class="metric-box">
            <span class="metric-label">Upload</span>
            <span class="metric-value" id="ul">--</span> <span class="metric-unit">Mbps</span>
        </div>
    </div>
    
    <button class="btn" id="startBtn" onclick="runDiagnostics()">Start Diagnostics</button>
</div>

<script>
function runDiagnostics() {
    const btn = document.getElementById('startBtn');
    const pb = document.getElementById('pb');
    const pf = document.getElementById('pf');
    const els = { ping: document.getElementById('ping'), dl: document.getElementById('dl'), ul: document.getElementById('ul') };
    
    btn.disabled = true;
    btn.innerText = 'Analyzing...';
    Object.values(els).forEach(e => e.innerText = '--');
    pb.style.display = 'block';
    
    let tick = 0;
    const timer = setInterval(() => {
        tick++;
        pf.style.width = tick + '%';
        
        if (tick === 15) els.ping.innerText = (Math.random() * 15 + 8).toFixed(1);
        if (tick > 15 && tick < 55) els.dl.innerText = (Math.random() * 80 + 150).toFixed(1);
        if (tick > 55 && tick < 95) els.ul.innerText = (Math.random() * 40 + 60).toFixed(1);
        
        if (tick >= 100) {
            clearInterval(timer);
            btn.disabled = false;
            btn.innerText = 'Run Again';
            setTimeout(() => pb.style.display = 'none', 500);
        }
    }, 40);
}
</script>
</body>
</html>
EOF

  {
    echo "User-agent: *"
    echo "Disallow: /admin/"
    echo "Disallow: /${path_prefix}"
  } > "$web_root/robots.txt"

  cat > "$site_file" <<EOF
limit_req_zone \$binary_remote_addr zone=req_limit:10m rate=10r/s;

server {
    listen 80;
    server_name ${domain};

    location ^~ /.well-known/acme-challenge/ {
        root ${web_root};
        default_type "text/plain";
    }

    location / {
        return 301 ${https_redirect_target};
    }
}

server {
    listen ${https_port} ssl;
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;

    root ${web_root};
    index index.html;

    location ^~ /${path_prefix} {
        proxy_pass http://127.0.0.1:${backend_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }

    location = /robots.txt {
        try_files \$uri =404;
    }

    location / {
        limit_req zone=req_limit burst=20 nodelay;
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

  ln -sf "$site_file" "${NGINX_SITE_ENABLED_DIR}/${domain}.conf"
  nginx -t >/dev/null && systemctl restart nginx
  echo "$site_file" > "$WST_NGINX_SITE_FILE"
}

setup_exit_wstunnel_service() {
  local backend_port="$1"
  local path_prefix="$2"
  local wg_udp_port="$3"

  path_prefix="$(normalize_path_prefix "$path_prefix")"
  echo "$wg_udp_port" > "$WST_WG_UDP_PORT_FILE"

  cat >/etc/systemd/system/wstunnel-exit.service <<EOF
[Unit]
Description=wstunnel server
After=network-online.target wg-quick@${WG_IF}.service nginx.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${WSTUNNEL_BIN} server --restrict-to 127.0.0.1:${wg_udp_port} --restrict-http-upgrade-path-prefix ${path_prefix} ws://127.0.0.1:${backend_port}
Restart=on-failure
RestartSec=2
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable wstunnel-exit.service >/dev/null 2>&1 || true
  systemctl restart wstunnel-exit.service
}

setup_entry_wstunnel_service() {
  local remote_host="$1"
  local remote_port="$2"
  local path_prefix="$3"
  local verify_tls="$4"
  local local_udp_port="$5"
  local remote_wg_udp_port="$6"

  path_prefix="$(normalize_path_prefix "$path_prefix")"

  echo "$local_udp_port" > "$WST_LOCAL_UDP_PORT_FILE"
  echo "$remote_wg_udp_port" > "$WST_WG_UDP_PORT_FILE"

  local verify_flag=""
  if [[ "$verify_tls" == "y" || "$verify_tls" == "Y" ]]; then
    verify_flag="--tls-verify-certificate"
  fi

  cat >/etc/systemd/system/wstunnel-entry.service <<EOF
[Unit]
Description=wstunnel client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${WSTUNNEL_BIN} client -L udp://${local_udp_port}:127.0.0.1:${remote_wg_udp_port}?timeout_sec=0 --http-upgrade-path-prefix ${path_prefix} ${verify_flag} wss://${remote_host}:${remote_port}
Restart=on-failure
RestartSec=2
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable wstunnel-entry.service >/dev/null 2>&1 || true
  systemctl restart wstunnel-entry.service
}

configure_exit_wg() {
  local wg_addr="$1" entry_wg_ip="$2" entry_public_key="$3" out_if="$4" wg_udp_port="$5"
  local exit_private_key
  exit_private_key="$(cat "${WG_DIR}/exit_private.key")"

  cat > "${WG_DIR}/${WG_IF}.conf" <<EOF
[Interface]
Address = ${wg_addr}
ListenPort = ${wg_udp_port}
PrivateKey = ${exit_private_key}
MTU = ${WG_SAFE_MTU}
PostUp   = iptables -A FORWARD -i ${WG_IF} -o ${out_if} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT; iptables -A FORWARD -i ${out_if} -o ${WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -A POSTROUTING -s ${entry_wg_ip%/*}/24 -o ${out_if} -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i ${WG_IF} -o ${out_if} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i ${out_if} -o ${WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables -t nat -D POSTROUTING -s ${entry_wg_ip%/*}/24 -o ${out_if} -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${entry_public_key}
AllowedIPs = ${entry_wg_ip}
EOF

  chmod 600 "${WG_DIR}/${WG_IF}.conf"
  enable_ip_forward_global
  systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
  wg-quick down "${WG_IF}" 2>/dev/null || true
  wg-quick up "${WG_IF}"
}

configure_entry_wg() {
  local wg_addr="$1" exit_wg_ip="$2" exit_public_key="$3" local_udp_port="$4"
  local entry_private_key
  entry_private_key="$(cat "${WG_DIR}/entry_private.key")"
  local exit_wg_ip_no_mask="${exit_wg_ip%%/*}"

  cat > "${WG_DIR}/${WG_IF}.conf" <<EOF
[Interface]
Address = ${wg_addr}
PrivateKey = ${entry_private_key}
Table = off
MTU = ${WG_SAFE_MTU}
PostUp   = ip rule show | grep -q "fwmark 0x1 lookup ${ROUTE_TABLE_ID}" || ip rule add fwmark 0x1 lookup ${ROUTE_TABLE_ID}; ip route replace default dev ${WG_IF} table ${ROUTE_TABLE_ID}; ip route replace ${exit_wg_ip_no_mask}/32 dev ${WG_IF}; iptables -t nat -C POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${WG_IF} -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip rule del fwmark 0x1 lookup ${ROUTE_TABLE_ID} 2>/dev/null || true; ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true; ip route del ${exit_wg_ip_no_mask}/32 dev ${WG_IF} 2>/dev/null || true; iptables -t nat -D POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${exit_public_key}
Endpoint = 127.0.0.1:${local_udp_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 20
EOF

  chmod 600 "${WG_DIR}/${WG_IF}.conf"
  echo "$exit_wg_ip_no_mask" > "$EXIT_WG_IP_FILE"
  systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
  wg-quick down "${WG_IF}" 2>/dev/null || true
  wg-quick up "${WG_IF}"
}

clear_mark_rules() {
  for chain in OUTPUT PREROUTING; do
    iptables -t mangle -S "$chain" 2>/dev/null | (grep " MARK " || true) | sed 's/^-A /-D /' | while read -r line; do
      [[ -n "$line" ]] && iptables -t mangle $line 2>/dev/null || true
    done
  done
}

get_current_mode() {
  if [[ -f "$MODE_FILE" ]]; then
    cat "$MODE_FILE" 2>/dev/null || echo "split"
  else
    echo "split"
  fi
}

set_mode_flag() {
  echo "$1" > "$MODE_FILE"
}

ensure_policy_routing_for_ports() {
  ip link show "${WG_IF}" &>/dev/null || return 0
  if ! ip rule show | (grep -q "fwmark 0x1 lookup ${ROUTE_TABLE_ID}" || true); then
    ip rule add fwmark 0x1 lookup ${ROUTE_TABLE_ID}
  fi
  ip route replace default dev "${WG_IF}" table ${ROUTE_TABLE_ID}
  ensure_server_bypass_route
}

apply_port_rules_from_file() {
  clear_mark_rules
  [[ ! -f "$PORT_LIST_FILE" ]] && return 0

  while read -r p; do
    [[ -z "$p" ]] && continue
    iptables -t mangle -C OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C PREROUTING -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A PREROUTING -p tcp --dport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C PREROUTING -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A PREROUTING -p udp --dport "$p" -j MARK --set-mark 0x1
  done < "$PORT_LIST_FILE" || true

  local wst_port=""
  [[ -f "$WST_REMOTE_PORT_FILE" ]] && wst_port="$(cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true)"
  if [[ -n "$wst_port" ]]; then
    iptables -t mangle -C OUTPUT -p tcp --dport "$wst_port" -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport "$wst_port" -j RETURN
    iptables -t mangle -C OUTPUT -p udp --dport "$wst_port" -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p udp --dport "$wst_port" -j RETURN
  fi
}

add_port_to_list() {
  local port="$1"
  mkdir -p "$(dirname "$PORT_LIST_FILE")"
  touch "$PORT_LIST_FILE"
  (grep -qx "$port" "$PORT_LIST_FILE" || true) && return 0
  echo "$port" >> "$PORT_LIST_FILE"
}

remove_port_from_list() {
  local port="$1"
  [[ ! -f "$PORT_LIST_FILE" ]] && return 0
  (grep -qx "$port" "$PORT_LIST_FILE" || true) || return 0
  sed -i "\|^$port$|d" "$PORT_LIST_FILE"
}

remove_port_iptables_rules() {
  local port="$1"
  iptables -t mangle -D OUTPUT -p tcp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p udp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D PREROUTING -p tcp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D PREROUTING -p udp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
}

add_forward_port_mapping() {
  local port="$1" exit_ip wan_if
  [[ -z "$port" ]] && return 0
  [[ -f "$EXIT_WG_IP_FILE" ]] || return 0
  exit_ip="$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)"
  [[ -n "$exit_ip" ]] || return 0

  enable_ip_forward_global
  wan_if="$(get_wan_if)"
  ip route replace "${exit_ip}/32" dev "${WG_IF}" 2>/dev/null || true

  iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || iptables -t nat -A PREROUTING -i "${wan_if}" -p tcp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}"
  iptables -C FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  iptables -C FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  iptables -t nat -C PREROUTING -i "${wan_if}" -p udp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || iptables -t nat -A PREROUTING -i "${wan_if}" -p udp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}"
  iptables -C FORWARD -i "${wan_if}" -o "${WG_IF}" -p udp --dport "${port}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${wan_if}" -o "${WG_IF}" -p udp --dport "${port}" -j ACCEPT
  iptables -C FORWARD -i "${WG_IF}" -o "${wan_if}" -p udp --sport "${port}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${WG_IF}" -o "${wan_if}" -p udp --sport "${port}" -j ACCEPT

  iptables -t nat -C POSTROUTING -o "${WG_IF}" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "${WG_IF}" -j MASQUERADE
}

remove_forward_port_mapping() {
  local port="$1" exit_ip wan_if
  [[ -z "$port" ]] && return 0
  [[ -f "$EXIT_WG_IP_FILE" ]] || return 0
  exit_ip="$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)"
  [[ -n "$exit_ip" ]] || return 0
  wan_if="$(get_wan_if)"

  iptables -t nat -D PREROUTING -i "${wan_if}" -p tcp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
  iptables -D FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

  iptables -t nat -D PREROUTING -i "${wan_if}" -p udp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
  iptables -D FORWARD -i "${wan_if}" -o "${WG_IF}" -p udp --dport "${port}" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${WG_IF}" -o "${wan_if}" -p udp --sport "${port}" -j ACCEPT 2>/dev/null || true
}

enable_global_mode() {
  ensure_policy_routing_for_ports
  clear_mark_rules

  local remote_port="" wan_if exit_ip=""
  [[ -f "$WST_REMOTE_PORT_FILE" ]] && remote_port="$(cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true)"
  wan_if="$(get_wan_if)"
  [[ -f "$EXIT_WG_IP_FILE" ]] && exit_ip="$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)"

  enable_ip_forward_global
  ensure_server_bypass_route

  if [[ -n "$exit_ip" ]]; then
    ip route replace "${exit_ip}/32" dev "${WG_IF}" 2>/dev/null || true
    iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || iptables -t nat -A PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}"
    iptables -t nat -C PREROUTING -i "${wan_if}" -p udp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || iptables -t nat -A PREROUTING -i "${wan_if}" -p udp ! --dport 22 -j DNAT --to-destination "${exit_ip}"
    iptables -C FORWARD -i "${wan_if}" -o "${WG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${wan_if}" -o "${WG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -C FORWARD -i "${WG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "${WG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -C POSTROUTING -o "${WG_IF}" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "${WG_IF}" -j MASQUERADE
  fi

  iptables -t mangle -C OUTPUT -o lo -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -o lo -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --sport 22 -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --dport 22 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport 22 -j RETURN
  iptables -t mangle -C OUTPUT -p udp --dport 53 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p udp --dport 53 -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --dport 53 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport 53 -j RETURN

  if [[ -n "$remote_port" ]]; then
    iptables -t mangle -C OUTPUT -p tcp --dport "${remote_port}" -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport "${remote_port}" -j RETURN
    iptables -t mangle -C OUTPUT -p udp --dport "${remote_port}" -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p udp --dport "${remote_port}" -j RETURN
  fi

  iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  iptables -t mangle -C OUTPUT -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A OUTPUT -j MARK --set-mark 0x1
  iptables -t mangle -C PREROUTING -i "${wan_if}" -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A PREROUTING -i "${wan_if}" -j MARK --set-mark 0x1

  ip link set dev "${WG_IF}" mtu "${WG_SAFE_MTU}" 2>/dev/null || true
  set_mode_flag "global"
}

enable_split_mode() {
  local exit_ip wan_if
  [[ -f "$EXIT_WG_IP_FILE" ]] && exit_ip="$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)"
  wan_if="$(get_wan_if)"

  if [[ -n "${exit_ip:-}" ]]; then
    iptables -t nat -D PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "${wan_if}" -p udp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || true
    iptables -D FORWARD -i "${wan_if}" -o "${WG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "${WG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  fi

  ensure_policy_routing_for_ports
  clear_mark_rules
  apply_port_rules_from_file

  if [[ -f "$PORT_LIST_FILE" ]]; then
    while read -r p; do
      [[ -z "$p" ]] && continue
      add_forward_port_mapping "$p"
    done < "$PORT_LIST_FILE" || true
  fi

  ip link set dev "${WG_IF}" mtu "${WG_SAFE_MTU}" 2>/dev/null || true
  set_mode_flag "split"
}

show_status() {
  print_block "📊 当前链路状态"
  echo "角色: $(get_role)"
  echo "模式: $(get_current_mode)"
  [[ -f "$WST_REMOTE_HOST_FILE" ]] && echo "远端主机: $(cat "$WST_REMOTE_HOST_FILE" 2>/dev/null || true)"
  [[ -f "$WST_REMOTE_PORT_FILE" ]] && echo "远端端口: $(cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true)"
  [[ -f "$WST_PATH_FILE" ]] && echo "路径前缀: $(cat "$WST_PATH_FILE" 2>/dev/null || true)"
  [[ -f "$WST_DOMAIN_FILE" ]] && echo "出口域名: $(cat "$WST_DOMAIN_FILE" 2>/dev/null || true)"
  [[ -f "$WST_WG_UDP_PORT_FILE" ]] && echo "WG UDP端口: $(cat "$WST_WG_UDP_PORT_FILE" 2>/dev/null || true)"
  [[ -f "$WST_LOCAL_UDP_PORT_FILE" ]] && echo "本地wstunnel UDP端口: $(cat "$WST_LOCAL_UDP_PORT_FILE" 2>/dev/null || true)"
  echo
  wg show || true
  echo
  systemctl --no-pager --full status wstunnel-exit.service 2>/dev/null | sed -n '1,10p' || true
  echo
  systemctl --no-pager --full status wstunnel-entry.service 2>/dev/null | sed -n '1,10p' || true
  echo
  systemctl --no-pager --full status nginx 2>/dev/null | sed -n '1,10p' || true
}

manage_entry_ports() {
  [[ "$(get_role)" == "entry" ]] || { print_err "当前机器不是入口服务器"; return 1; }
  ensure_policy_routing_for_ports

  while true; do
    print_block "入口端口分流管理"
    echo "1) 查看当前分流端口"
    echo "2) 添加分流端口"
    echo "3) 删除分流端口"
    echo "0) 返回上一级"
    read -rp "请选择: " sub

    case "$sub" in
      1)
        if [[ -f "$PORT_LIST_FILE" ]] && [[ -s "$PORT_LIST_FILE" ]]; then
          cat "$PORT_LIST_FILE"
        else
          print_warn "当前没有分流端口"
        fi
        ;;
      2)
        read -rp "端口: " new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && [[ "$new_port" -ge 1 ]] && [[ "$new_port" -le 65535 ]] && [[ "$new_port" -ne 22 ]]; then
          add_port_to_list "$new_port"
          apply_port_rules_from_file
          add_forward_port_mapping "$new_port"
          print_ok "已添加端口: $new_port"
        else
          print_err "端口不合法"
        fi
        ;;
      3)
        read -rp "要删除的端口: " del_port
        if [[ "$del_port" =~ ^[0-9]+$ ]]; then
          remove_port_from_list "$del_port"
          remove_port_iptables_rules "$del_port"
          remove_forward_port_mapping "$del_port"
          print_ok "已删除端口: $del_port"
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
  [[ "$(get_role)" == "entry" ]] || { print_err "当前机器不是入口服务器"; return 1; }

  while true; do
    local mode
    mode="$(get_current_mode)"
    print_block "入口模式管理"
    echo "当前模式: ${mode}"
    echo "1) 切换为 全局模式"
    echo "2) 切换为 分流模式"
    echo "0) 返回上一级"
    read -rp "请选择: " sub

    case "$sub" in
      1) enable_global_mode; print_ok "已切换为全局模式" ;;
      2) enable_split_mode; print_ok "已切换为分流模式" ;;
      0) break ;;
      *) print_err "无效选择" ;;
    esac
  done
}

start_wg() {
  local role
  role="$(get_role)"

  print_block "⏳ 正在启动"

  if [[ "$role" == "exit" ]]; then
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    wg-quick up "${WG_IF}" 2>/dev/null || true
    systemctl restart nginx 2>/dev/null || true
    systemctl restart wstunnel-exit.service 2>/dev/null || true
    print_ok "出口已启动"
  elif [[ "$role" == "entry" ]]; then
    systemctl restart wstunnel-entry.service 2>/dev/null || true
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    wg-quick up "${WG_IF}" 2>/dev/null || true
    ensure_server_bypass_route
    local mode
    mode="$(get_current_mode)"
    if [[ "$mode" == "global" ]]; then
      enable_global_mode
    else
      enable_split_mode
    fi
    print_ok "入口已启动"
  else
    print_err "还未配置角色"
  fi
}

stop_wg() {
  local role
  role="$(get_role)"

  print_block "⏳ 正在停止"

  if [[ "$role" == "exit" ]]; then
    systemctl stop wstunnel-exit.service 2>/dev/null || true
  elif [[ "$role" == "entry" ]]; then
    systemctl stop wstunnel-entry.service 2>/dev/null || true
  fi

  wg-quick down "${WG_IF}" 2>/dev/null || true
  ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true
  clear_mark_rules
  print_ok "已停止"
}

restart_wg() {
  print_block "⏳ 正在重启"
  stop_wg
  start_wg
  print_ok "重启完成"
}

update_wstunnel_entry_remote_ip() {
  [[ "$(get_role)" == "entry" ]] || { print_err "当前机器不是入口服务器"; return 1; }

  local saved_port="" saved_path="" saved_verify="" local_udp_port="" remote_wg_udp_port="" new_port verify_tls
  [[ -f "$WST_REMOTE_PORT_FILE" ]] && saved_port="$(cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true)"
  [[ -f "$WST_PATH_FILE" ]] && saved_path="$(cat "$WST_PATH_FILE" 2>/dev/null || true)"
  [[ -f "$WST_VERIFY_FILE" ]] && saved_verify="$(cat "$WST_VERIFY_FILE" 2>/dev/null || true)"
  [[ -f "$WST_LOCAL_UDP_PORT_FILE" ]] && local_udp_port="$(cat "$WST_LOCAL_UDP_PORT_FILE" 2>/dev/null || true)"
  [[ -f "$WST_WG_UDP_PORT_FILE" ]] && remote_wg_udp_port="$(cat "$WST_WG_UDP_PORT_FILE" 2>/dev/null || true)"

  local new_host=""
  while [[ -z "$new_host" ]]; do
    read -rp "新出口域名 / IP: " new_host
    [[ -z "$new_host" ]] && print_err "出口地址不能为空"
  done

  read -rp "wss 端口 (默认 ${saved_port:-443}): " new_port
  new_port="${new_port:-${saved_port:-443}}"

  local new_path=""
  while [[ -z "$new_path" ]]; do
    read -rp "请输入新的【路径前缀】(默认 ${saved_path}): " new_path
    new_path="${new_path:-$saved_path}"
    new_path="$(normalize_path_prefix "$new_path")"
    [[ -z "$new_path" ]] && print_err "路径前缀不能为空"
  done

  read -rp "是否严格校验证书? (默认 ${saved_verify:-Y}): " verify_tls
  verify_tls="${verify_tls:-${saved_verify:-Y}}"
  local_udp_port="${local_udp_port:-$WST_LOCAL_UDP_PORT_DEFAULT}"
  remote_wg_udp_port="${remote_wg_udp_port:-$WG_SERVER_PORT_DEFAULT}"

  save_wst_params "$new_host" "$new_port" "$new_path" "$verify_tls"
  setup_entry_wstunnel_service "$new_host" "$new_port" "$new_path" "$verify_tls" "$local_udp_port" "$remote_wg_udp_port"

  print_block "✅ 出口地址已更新"
  echo "新地址: $new_host:$new_port"
  echo "新路径: $new_path"
}

renew_cert_now() {
  print_block "⏳ 正在手动续期证书"
  install_base_packages
  certbot renew --nginx >/dev/null 2>&1 || true
  nginx -t >/dev/null && systemctl reload nginx
  print_ok "证书续期执行完成"
}

manage_certificates() {
  if [[ "$(get_role)" != "exit" ]]; then
    print_err "仅出口服务器可用"
    return
  fi

  local domain=""
  if [[ -f "$WST_DOMAIN_FILE" ]]; then
    domain="$(cat "$WST_DOMAIN_FILE" 2>/dev/null || true)"
  fi

  while true; do
    print_block "证书管理（仅出口）"
    echo "当前绑定域名: ${domain:-未配置}"
    echo "1) 查看证书情况"
    echo "2) 开启自动续签"
    echo "3) 关闭自动续签"
    echo "4) 手动立即续签"
    echo "5) 删除证书"
    echo "0) 返回上一级"
    read -rp "请选择: " sub

    case "$sub" in
      1)
        if [[ -n "$domain" ]] && [[ -d "/etc/letsencrypt/live/${domain}" ]]; then
          echo "✅ 检测到 ${domain} 的有效证书信息："
          certbot certificates -d "$domain" 2>/dev/null | grep -E "Expiry Date|Certificate Path|Private Key Path" || true
        else
          print_warn "未检测到有效证书"
        fi
        ;;
      2)
        systemctl enable certbot.timer >/dev/null 2>&1 || true
        systemctl start certbot.timer >/dev/null 2>&1 || true
        print_ok "已开启自动续签定时任务 (certbot.timer)"
        ;;
      3)
        systemctl disable certbot.timer >/dev/null 2>&1 || true
        systemctl stop certbot.timer >/dev/null 2>&1 || true
        print_ok "已关闭自动续签定时任务 (certbot.timer)"
        ;;
      4)
        renew_cert_now
        ;;
      5)
        if [[ -n "$domain" ]]; then
          read -rp "⚠️ 确定要删除 ${domain} 的证书吗？会导致服务中断 (y/N): " confirm
          if [[ "$confirm" =~ ^[Yy]$ ]]; then
            certbot delete --cert-name "$domain" --non-interactive >/dev/null 2>&1 || true
            rm -rf "/etc/letsencrypt/live/${domain}" "/etc/letsencrypt/archive/${domain}" "/etc/letsencrypt/renewal/${domain}.conf" 2>/dev/null || true
            print_ok "证书已成功删除"
          else
            echo "已取消删除操作"
          fi
        else
          print_warn "未找到绑定的域名，无法删除"
        fi
        ;;
      0) break ;;
      *) print_err "无效选择" ;;
    esac
  done
}

configure_exit() {
  set_role "exit"
  ensure_dirs

  print_block "⏳ 开始配置出口服务器"
  install_base_packages
  install_wireguard
  install_wstunnel

  cd "$WG_DIR"
  if [[ ! -f exit_private.key ]]; then
    umask 077
    wg genkey | tee exit_private.key | wg pubkey > exit_public.key
  fi
  local exit_public_key
  exit_public_key="$(cat exit_public.key)"

  print_block "【本机（出口服务器）公钥】"
  echo "$exit_public_key"

  local domain=""
  while [[ -z "$domain" ]]; do
    read -rp "出口服务器绑定域名（必须已解析到本机）: " domain
    [[ -z "$domain" ]] && print_err "域名不能为空"
  done
  echo "$domain" > "$WST_DOMAIN_FILE"

  local wg_addr entry_wg_ip out_if ws_port wg_udp_port backend_port path_prefix default_if
  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/24): " wg_addr
  wg_addr="${wg_addr:-10.0.0.1/24}"

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/32): " entry_wg_ip
  entry_wg_ip="${entry_wg_ip:-10.0.0.2/32}"

  default_if=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)
  read -rp "出口服务器对外网卡名(默认 ${default_if:-eth0}): " out_if
  out_if="${out_if:-${default_if:-eth0}}"

  read -rp "Nginx/WSS 对外端口 (默认 443): " ws_port
  ws_port="${ws_port:-443}"

  read -rp "出口服务器 WG 真正监听 UDP 端口 (默认 ${WG_SERVER_PORT_DEFAULT}): " wg_udp_port
  wg_udp_port="${wg_udp_port:-$WG_SERVER_PORT_DEFAULT}"

  backend_port=$((RANDOM % 1000 + 30000))
  local recommended_path="ws_$(rand_hex16 || echo "a1b2c3d4e5f67890")"
  read -rp "WebSocket 路径前缀/密钥 (默认 ${recommended_path}): " path_prefix
  path_prefix="$(normalize_path_prefix "${path_prefix:-${recommended_path}}")"

  print_step "站点" "写入 HTTP 验证站点配置..."
  write_nginx_http_site_for_acme "$domain"
  issue_letsencrypt_cert "$domain"

  print_step "站点" "写入 HTTPS + wstunnel 反代配置..."
  write_nginx_https_wstunnel_site "$domain" "$backend_port" "$path_prefix" "$ws_port"

  local entry_public_key=""
  while [[ -z "$entry_public_key" ]]; do
    read -rp "请输入【入口服务器公钥】(入口服务器复制): " entry_public_key
    [[ -z "$entry_public_key" ]] && print_err "公钥不能为空"
  done

  print_step "WG" "配置出口 WireGuard..."
  configure_exit_wg "$wg_addr" "$entry_wg_ip" "$entry_public_key" "$out_if" "$wg_udp_port"

  print_step "wstunnel" "配置出口 wstunnel 服务..."
  setup_exit_wstunnel_service "$backend_port" "$path_prefix" "$wg_udp_port"
  save_wst_params "$domain" "$ws_port" "$path_prefix" "y"

  print_block "✅ 出口配置完成"
  echo "域名: ${domain}"
  echo "WSS端口: ${ws_port}"
  echo "WG UDP端口: ${wg_udp_port}"
  echo
  echo "【请复制给入口机的路径前缀】"
  echo "${path_prefix}"
}

configure_entry() {
  set_role "entry"
  ensure_dirs

  print_block "⏳ 开始配置入口服务器"
  install_base_packages
  install_wireguard
  install_wstunnel

  cd "$WG_DIR"
  if [[ ! -f entry_private.key ]]; then
    umask 077
    wg genkey | tee entry_private.key | wg pubkey > entry_public.key
  fi
  local entry_public_key
  entry_public_key="$(cat entry_public.key)"

  print_block "【本机（入口服务器）公钥】"
  echo "$entry_public_key"

  local wg_addr exit_wg_ip ws_port verify_tls local_udp_port remote_wg_udp_port
  local saved_host="" saved_port="" saved_path="" saved_verify=""

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/24): " wg_addr
  wg_addr="${wg_addr:-10.0.0.2/24}"

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/32): " exit_wg_ip
  exit_wg_ip="${exit_wg_ip:-10.0.0.1/32}"

  [[ -f "$WST_REMOTE_HOST_FILE" ]] && saved_host="$(cat "$WST_REMOTE_HOST_FILE" 2>/dev/null || true)"
  [[ -f "$WST_REMOTE_PORT_FILE" ]] && saved_port="$(cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true)"
  [[ -f "$WST_PATH_FILE" ]] && saved_path="$(cat "$WST_PATH_FILE" 2>/dev/null || true)"
  [[ -f "$WST_VERIFY_FILE" ]] && saved_verify="$(cat "$WST_VERIFY_FILE" 2>/dev/null || true)"

  local exit_host=""
  while [[ -z "$exit_host" ]]; do
    read -rp "出口服务器域名/IP: " exit_host
    exit_host="${exit_host:-$saved_host}"
    [[ -z "$exit_host" ]] && print_err "出口服务器地址不能为空"
  done

  read -rp "wss 端口 (默认 ${saved_port:-443}): " ws_port
  ws_port="${ws_port:-${saved_port:-443}}"

  local path_prefix=""
  while [[ -z "$path_prefix" ]]; do
    if [[ -n "$saved_path" ]]; then
      read -rp "请输入【路径前缀】(出口服务器复制，默认 ${saved_path}): " path_prefix
      path_prefix="${path_prefix:-$saved_path}"
    else
      read -rp "请输入【路径前缀】(出口服务器复制): " path_prefix
    fi
    path_prefix="$(normalize_path_prefix "$path_prefix")"
    [[ -z "$path_prefix" ]] && print_err "路径前缀不能为空"
  done

  read -rp "是否严格校验证书? (Y/n): " verify_tls
  verify_tls="${verify_tls:-Y}"

  read -rp "入口本地 wstunnel 监听 UDP 端口 (默认 ${WST_LOCAL_UDP_PORT_DEFAULT}): " local_udp_port
  local_udp_port="${local_udp_port:-$WST_LOCAL_UDP_PORT_DEFAULT}"

  read -rp "远端出口 WG UDP 端口 (默认 ${WG_SERVER_PORT_DEFAULT}): " remote_wg_udp_port
  remote_wg_udp_port="${remote_wg_udp_port:-$WG_SERVER_PORT_DEFAULT}"

  print_step "wstunnel" "配置入口 wstunnel 服务..."
  save_wst_params "$exit_host" "$ws_port" "$path_prefix" "$verify_tls"
  setup_entry_wstunnel_service "$exit_host" "$ws_port" "$path_prefix" "$verify_tls" "$local_udp_port" "$remote_wg_udp_port"

  local exit_public_key=""
  while [[ -z "$exit_public_key" ]]; do
    read -rp "请输入【出口服务器公钥】(出口服务器复制): " exit_public_key
    [[ -z "$exit_public_key" ]] && print_err "公钥不能为空"
  done

  print_step "WG" "配置入口 WireGuard..."
  configure_entry_wg "$wg_addr" "$exit_wg_ip" "$exit_public_key" "$local_udp_port"
  ensure_server_bypass_route
  set_mode_flag "split"
  enable_split_mode

  print_block "✅ 入口配置完成"
  echo "出口地址: ${exit_host}:${ws_port}"
  echo "路径前缀: ${path_prefix}"
  echo "本地 UDP 监听: ${local_udp_port}"
  echo "远端 WG UDP: ${remote_wg_udp_port}"
}

pre_uninstall_cleanup() {
  local wan_if exit_ip remote_port
  wan_if="$(get_wan_if)"
  exit_ip=""
  remote_port=""

  [[ -f "$EXIT_WG_IP_FILE" ]] && exit_ip="$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)"
  [[ -f "$WST_REMOTE_PORT_FILE" ]] && remote_port="$(cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true)"

  print_step "预清理-1" "撤销全局模式遗留规则..."

  if [[ -n "$exit_ip" ]]; then
    iptables -t nat -D PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || true
    iptables -t nat -D PREROUTING -i "${wan_if}" -p udp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || true
    iptables -D FORWARD -i "${wan_if}" -o "${WG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "${WG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "${WG_IF}" -j MASQUERADE 2>/dev/null || true
  fi

  iptables -t mangle -D OUTPUT -o lo -j RETURN 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p tcp --dport 22 -j RETURN 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p udp --dport 53 -j RETURN 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p tcp --dport 53 -j RETURN 2>/dev/null || true

  if [[ -n "$remote_port" ]]; then
    iptables -t mangle -D OUTPUT -p tcp --dport "${remote_port}" -j RETURN 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p udp --dport "${remote_port}" -j RETURN 2>/dev/null || true
  fi

  iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  iptables -t mangle -D OUTPUT -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D PREROUTING -i "${wan_if}" -j MARK --set-mark 0x1 2>/dev/null || true
  print_ok "全局模式遗留规则已尝试撤销"

  print_step "预清理-2" "撤销分流模式遗留规则..."
  clear_mark_rules 2>/dev/null || true

  if [[ -f "$PORT_LIST_FILE" ]]; then
    while read -r p; do
      [[ -z "$p" ]] && continue
      remove_forward_port_mapping "$p" 2>/dev/null || true
      remove_port_iptables_rules "$p" 2>/dev/null || true
    done < "$PORT_LIST_FILE"
  fi
  print_ok "分流模式遗留规则已尝试撤销"

  print_step "预清理-3" "清理策略路由..."
  ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true
  ip rule del fwmark 0x1 lookup ${ROUTE_TABLE_ID} 2>/dev/null || true
  print_ok "策略路由已清理"
}

uninstall_wg() {
  local role
  role="$(get_role 2>/dev/null || echo unknown)"

  print_block "⏳ 开始彻底卸载并清理"
  echo "当前识别角色: ${role}"

  set +e

  pre_uninstall_cleanup

  print_step "1/10" "停止并删除 systemd 服务..."
  systemctl stop wstunnel-exit.service 2>/dev/null || true
  systemctl stop wstunnel-entry.service 2>/dev/null || true
  systemctl disable wstunnel-exit.service 2>/dev/null || true
  systemctl disable wstunnel-entry.service 2>/dev/null || true
  rm -f /etc/systemd/system/wstunnel-exit.service /etc/systemd/system/wstunnel-entry.service
  systemctl daemon-reload 2>/dev/null || true
  print_ok "systemd 服务已处理"

  print_step "2/10" "停止并删除 WireGuard 接口..."
  systemctl stop "wg-quick@${WG_IF}.service" 2>/dev/null || true
  systemctl disable "wg-quick@${WG_IF}.service" 2>/dev/null || true
  wg-quick down "${WG_IF}" 2>/dev/null || true
  print_ok "WireGuard 接口已处理"

  print_step "3/10" "再次清理策略路由..."
  ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true
  ip rule del fwmark 0x1 lookup ${ROUTE_TABLE_ID} 2>/dev/null || true
  print_ok "策略路由已清理"

  print_step "4/10" "清理 mangle / nat / forward 规则..."
  clear_mark_rules 2>/dev/null || true

  if [[ -f "$PORT_LIST_FILE" ]]; then
    while read -r p; do
      [[ -z "$p" ]] && continue
      echo "  - 清理端口规则: $p"
      remove_forward_port_mapping "$p" 2>/dev/null || true
      remove_port_iptables_rules "$p" 2>/dev/null || true
    done < "$PORT_LIST_FILE"
  fi

  iptables -t nat -S PREROUTING 2>/dev/null | grep -E "DNAT|${WG_IF}" | sed 's/^-A /-D /' | while read -r line; do
    iptables -t nat $line 2>/dev/null || true
  done

  iptables -t nat -S POSTROUTING 2>/dev/null | grep -E "${WG_IF}|MASQUERADE" | sed 's/^-A /-D /' | while read -r line; do
    iptables -t nat $line 2>/dev/null || true
  done

  iptables -S FORWARD 2>/dev/null | grep -E "${WG_IF}" | sed 's/^-A /-D /' | while read -r line; do
    iptables $line 2>/dev/null || true
  done
  print_ok "iptables 规则已清理"

  print_step "5/10" "删除 wstunnel 二进制与配置目录..."
  rm -f "$WSTUNNEL_BIN"
  rm -rf "$WST_DIR" "$WG_DIR" 2>/dev/null || true
  print_ok "wstunnel / wireguard 配置目录已删除"

  if [[ "$role" == "exit" || -f "$WST_DOMAIN_FILE" || -f "$WST_NGINX_SITE_FILE" ]]; then
    print_step "6/10" "检测到出口残留，清理站点 / 证书 / Nginx..."

    local d=""
    local site_file=""

    [[ -f "$WST_DOMAIN_FILE" ]] && d="$(cat "$WST_DOMAIN_FILE" 2>/dev/null)"
    [[ -f "$WST_NGINX_SITE_FILE" ]] && site_file="$(cat "$WST_NGINX_SITE_FILE" 2>/dev/null)"

    if [[ -n "$site_file" ]]; then
      echo "  - 删除站点配置: $site_file"
      rm -f "$site_file"
      rm -f "${NGINX_SITE_ENABLED_DIR}/$(basename "$site_file")"
    fi

    if [[ -n "$d" ]]; then
      echo "  - 删除站点目录: ${WEB_ROOT_BASE}/${d}"
      rm -rf "${WEB_ROOT_BASE}/${d}"

      echo "  - 删除 certbot 证书: $d"
      certbot delete --cert-name "$d" --non-interactive >/dev/null 2>&1 || true
      rm -rf "/etc/letsencrypt/live/${d}" \
             "/etc/letsencrypt/archive/${d}" \
             "/etc/letsencrypt/renewal/${d}.conf" 2>/dev/null
    fi

    echo "  - 停止 Nginx"
    systemctl stop nginx 2>/dev/null || true

    echo "  - 卸载 nginx / certbot"
    apt purge -y nginx nginx-common certbot python3-certbot-nginx || true
    apt autoremove -y || true

    print_ok "出口相关内容已清理"
  else
    print_step "6/10" "当前非出口，跳过 Nginx / Certbot / 证书清理"
  fi

  print_step "7/10" "删除内核转发配置..."
  sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null || true
  sysctl -p >/dev/null 2>&1 || true
  print_ok "内核转发配置已恢复"

  print_step "8/10" "卸载 WireGuard 软件包..."
  apt purge -y wireguard wireguard-tools || true
  apt autoremove -y || true
  print_ok "WireGuard 软件包已卸载"

  print_step "9/10" "再次兜底清理残留文件..."
  rm -f "$WSTUNNEL_BIN" 2>/dev/null || true
  rm -rf "$WST_DIR" "$WG_DIR" 2>/dev/null || true
  rm -f "$ROLE_FILE" "$MODE_FILE" "$EXIT_WG_IP_FILE" "$PORT_LIST_FILE" 2>/dev/null || true
  print_ok "残留文件已处理"

  print_step "10/10" "卸载完成检查..."
  which nginx 2>/dev/null || true
  which certbot 2>/dev/null || true
  which wg 2>/dev/null || true
  test -x "$WSTUNNEL_BIN" && echo "$WSTUNNEL_BIN" || true
  print_ok "检查结束"

  print_block "✅ 已彻底清理完成"

  set -e
  exit 0
}

while true; do
  echo
  echo "================ 📡 WG + wstunnel + Nginx 高级链路 ================"
  echo "1) 配置为 出口服务器"
  echo "2) 配置为 入口服务器"
  echo "3) 查看链路状态"
  echo "4) 启动"
  echo "5) 停止"
  echo "6) 重启"
  echo "7) 卸载并清理"
  echo "8) 管理入口端口分流"
  echo "9) 管理入口模式（全局 / 分流）"
  echo "10) 修改出口 IP / 域名（仅入口）"
  echo "11) 证书管理（仅出口）"
  echo "0) 退出"
  echo "====================================================================="
  read -rp "请选择: " choice

  case "$choice" in
    1) configure_exit ;;
    2) configure_entry ;;
    3) show_status ;;
    4) start_wg ;;
    5) stop_wg ;;
    6) restart_wg ;;
    7) uninstall_wg ;;
    8) manage_entry_ports ;;
    9) manage_entry_mode ;;
    10) update_wstunnel_entry_remote_ip ;;
    11) manage_certificates ;;
    0) exit 0 ;;
    *) print_err "无效选择" ;;
  esac
done
