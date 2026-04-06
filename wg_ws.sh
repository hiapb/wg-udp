#!/usr/bin/env bash
set -euo pipefail

WG_IF="wg0"
WG_DIR="/etc/wireguard"
PORT_LIST_FILE="${WG_DIR}/.wg_ports"
MODE_FILE="${WG_DIR}/.wg_mode"
EXIT_WG_IP_FILE="${WG_DIR}/.exit_wg_ip"
ROLE_FILE="${WG_DIR}/.wg_role"
INSTALLED_PKGS_FILE="${WG_DIR}/.installed_pkgs"
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
WST_DEFAULT_PORT=443
WG_SERVER_PORT_DEFAULT=51820
WST_LOCAL_UDP_PORT_DEFAULT=51820
ROUTE_TABLE_ID=51820

if [[ $EUID -ne 0 ]]; then
  echo "❌ 权限不足：请以 root 身份运行此脚本。"
  exit 1
fi

get_role() {
  if [[ -f "$ROLE_FILE" ]]; then
    cat "$ROLE_FILE" 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

set_role() {
  local role="$1"
  mkdir -p "$(dirname "$ROLE_FILE")"
  echo "$role" > "$ROLE_FILE"
}

rand_str() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24
}

detect_public_ip() {
  local ip=""
  for svc in "https://api.ipify.org" "https://ifconfig.me" "https://ipinfo.io/ip"; do
    ip=$(curl -4 -fsS --max-time 3 "$svc" </dev/null 2>/dev/null || true)
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

resolve_ipv4() {
  local host="$1"
  getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}'
}

ensure_dirs() {
  mkdir -p "$WG_DIR" "$WST_DIR"
  chmod 700 "$WG_DIR" "$WST_DIR" 2>/dev/null || true
}

get_wan_if() {
  local wan
  wan=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1 | grep -v '^$')
  echo "${wan:-eth0}"
}

get_main_gateway() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="via"){print $(i+1); exit}}}'
}

enable_ip_forward_global() {
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
}

save_wst_params() {
  local host="$1" port="$2" path="$3" verify="$4"
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
  if [[ -z "$gateway" ]]; then
    return 0
  fi
  ip route replace "${remote_ip}/32" via "$gateway" dev "$wan_if" 2>/dev/null || true
}

install_base_packages() {
  local need_pkgs=(curl tar ca-certificates iproute2 iptables nginx openssl lsb-release certbot python3-certbot-nginx)
  local missing=()
  for pkg in "${need_pkgs[@]}"; do
    dpkg -s "$pkg" &>/dev/null || missing+=("$pkg")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt update </dev/null || true
  apt install -y "${missing[@]}" </dev/null
  
  ensure_dirs
  for pkg in "${missing[@]}"; do
    echo "$pkg" >> "$INSTALLED_PKGS_FILE"
  done
}

install_wireguard() {
  local need_pkgs=(wireguard wireguard-tools)
  local missing=()
  for pkg in "${need_pkgs[@]}"; do
    dpkg -s "$pkg" &>/dev/null || missing+=("$pkg")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt update </dev/null || true
  apt install -y "${missing[@]}" </dev/null

  ensure_dirs
  for pkg in "${missing[@]}"; do
    echo "$pkg" >> "$INSTALLED_PKGS_FILE"
  done
}

install_wstunnel() {
  if [[ -x "$WSTUNNEL_BIN" ]]; then
    local cur_ver
    cur_ver=$("$WSTUNNEL_BIN" --version 2>/dev/null || true)
    if [[ -n "$cur_ver" ]]; then
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
    *) echo "❌ 暂不支持的架构: $arch"; exit 1 ;;
  esac
  url_base="https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}"
  url_bin="${url_base}/${file}"
  # ❗ 修复了这里：GitHub上实际的校验文件名就是 checksums.txt
  url_sum="${url_base}/checksums.txt"
  tmpdir="$(mktemp -d)"
  
  echo "⏳ 正在从 GitHub 下载 wstunnel，请稍候..."
  (
    cd "$tmpdir"
    if ! curl -sL --fail "$url_sum" -o checksums.txt </dev/null; then
       echo "❌ 下载校验文件失败！请检查网络。"
       exit 1
    fi
    if ! curl -L --fail "$url_bin" -o "$file" </dev/null; then
       echo "❌ 下载 wstunnel 失败！请检查网络。"
       exit 1
    fi
    if ! grep "$file" checksums.txt | sha256sum -c -; then
       echo "❌ 文件校验失败！"
       exit 1
    fi
    tar -xzf "$file"
    bin_name="$(find . -maxdepth 1 -type f \( -name "wstunnel" -o -name "wstunnel-cli" \) | head -n1)"
    install -m 0755 "$bin_name" "$WSTUNNEL_BIN"
  ) || exit 1
  rm -rf "$tmpdir"
  echo "✅ wstunnel 安装完成。"
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
  nginx -t
  systemctl restart nginx
  echo "$site_file" > "$WST_NGINX_SITE_FILE"
}

issue_letsencrypt_cert() {
  local domain="$1"
  certbot --nginx -d "$domain" --non-interactive --agree-tos -m "admin@${domain}" --redirect </dev/null
}

write_nginx_https_wstunnel_site() {
  local domain="$1" backend_port="$2" path_prefix="$3"
  local site_file="${NGINX_SITE_DIR}/${domain}.conf"
  local web_root="${WEB_ROOT_BASE}/${domain}"
  mkdir -p "$web_root"
  cat > "$web_root/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>日常随笔</title>
    <style>body{font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif; margin:40px auto; max-width:700px; line-height:1.8; color:#444; padding:0 20px;} h1{color:#222; font-weight:normal;} .date{color:#999; font-size:0.9em; margin-bottom:30px;} p{margin-bottom:20px;} hr{border:0; border-top:1px solid #eee; margin:50px 0;} footer{color:#aaa; font-size:0.8em; text-align:center;}</style>
</head>
<body>
    <h1>春日漫无目的散步</h1>
    <p class="date">2026年4月</p>
    <p>周末难得是个大晴天，没有定闹钟，睡到自然醒。下楼顺着街边一直往前走，没开导航，就是想随便看看平时匆匆路过的风景。</p>
    <p>在转角的一家老旧咖啡馆坐了一个下午，看书，发呆，听隔壁桌聊着琐碎的生活日常。阳光打在木桌上，光影拉得很长。生活其实不需要那么多宏大的叙事，这种可以自由支配时间的缝隙，本身就是一种治愈。</p>
    <p>提醒自己：下周三记得把阳台的几盆植物换土。</p>
    <hr>
    <footer>© 2026 个人碎碎念. 安静生活.</footer>
</body>
</html>
EOF
  echo "User-agent: *" > "$web_root/robots.txt"
  echo "Disallow: /admin/" >> "$web_root/robots.txt"
  echo "Disallow: /${path_prefix}" >> "$web_root/robots.txt"
  cat > "$site_file" <<EOF
server {
    listen 80;
    server_name ${domain};
    location ^~ /.well-known/acme-challenge/ {
        root ${web_root};
        default_type "text/plain";
    }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl http2;
    server_name ${domain};
    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    root ${web_root};
    index index.html;
    location / {
        limit_req zone=req_limit burst=20 nodelay;
        try_files \$uri \$uri/ /index.html;
    }
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
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
limit_req_zone \$binary_remote_addr zone=req_limit:10m rate=10r/s;
EOF
  ln -sf "$site_file" "${NGINX_SITE_ENABLED_DIR}/${domain}.conf"
  nginx -t && systemctl restart nginx
  echo "$site_file" > "$WST_NGINX_SITE_FILE"
}

setup_exit_wstunnel_service() {
  local backend_port="$1" path_prefix="$2" wg_udp_port="$3"
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
  systemctl restart wstunnel-exit.service || true
}

setup_entry_wstunnel_service() {
  local remote_host="$1" remote_port="$2" path_prefix="$3" verify_tls="$4" local_udp_port="$5" remote_wg_udp_port="$6"
  echo "$local_udp_port" > "$WST_LOCAL_UDP_PORT_FILE"
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
ExecStart=${WSTUNNEL_BIN} client -L udp://${local_udp_port}:127.0.0.1:${remote_wg_udp_port}?timeout_sec=0 --http-upgrade-path-prefix ${path_prefix} --http-host-header "${remote_host}" --websocket-ping-frequency-sec 25 ${verify_flag} wss://${remote_host}:${remote_port}
Restart=on-failure
RestartSec=2
User=root
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable wstunnel-entry.service >/dev/null 2>&1 || true
  systemctl restart wstunnel-entry.service || true
}

configure_exit_wg() {
  local wg_addr="$1" entry_wg_ip="$2" entry_public_key="$3" out_if="$4" wg_udp_port="$5"
  cd "$WG_DIR"
  if [[ ! -f exit_private.key ]]; then
    umask 077
    wg genkey | tee exit_private.key | wg pubkey > exit_public.key
  fi
  local exit_private_key exit_public_key
  exit_private_key="$(cat exit_private.key)"
  exit_public_key="$(cat exit_public.key)"
  echo
  echo "====== 出口服务器 公钥（发给入口服务器用）======"
  echo "${exit_public_key}"
  echo "================================================"
  echo
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
  cd "$WG_DIR"
  if [[ ! -f entry_private.key ]]; then
    umask 077
    wg genkey | tee entry_private.key | wg pubkey > entry_public.key
  fi
  local entry_private_key entry_public_key
  entry_private_key="$(cat entry_private.key)"
  entry_public_key="$(cat entry_public.key)"
  echo
  echo "====== 入口服务器 公钥（出口服务器用）======"
  echo "${entry_public_key}"
  echo "================================================"
  echo
  cat > "${WG_DIR}/${WG_IF}.conf" <<EOF
[Interface]
Address = ${wg_addr}
PrivateKey = ${entry_private_key}
Table = off
MTU = ${WG_SAFE_MTU}
PostUp   = ip rule show | grep -q "fwmark 0x1 lookup ${ROUTE_TABLE_ID}" || ip rule add fwmark 0x1 lookup ${ROUTE_TABLE_ID}; ip route replace default dev ${WG_IF} table ${ROUTE_TABLE_ID}; iptables -t nat -C POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${WG_IF} -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip rule del fwmark 0x1 lookup ${ROUTE_TABLE_ID} 2>/dev/null || true; ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true; iptables -t nat -D POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
[Peer]
PublicKey = ${exit_public_key}
Endpoint = 127.0.0.1:${local_udp_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 20
EOF
  chmod 600 "${WG_DIR}/${WG_IF}.conf"
  local exit_wg_ip_no_mask="${exit_wg_ip%%/*}"
  echo "$exit_wg_ip_no_mask" > "$EXIT_WG_IP_FILE"
  systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
  wg-quick down "${WG_IF}" 2>/dev/null || true
  wg-quick up "${WG_IF}"
}

clear_mark_rules() {
  for chain in OUTPUT PREROUTING; do
    iptables -t mangle -S "$chain" 2>/dev/null | grep " MARK " | sed 's/^-A /-D /' | while read -r line; do
      iptables -t mangle $line 2>/dev/null || true
    done
  done
}

get_current_mode() {
  if [[ -f "$MODE_FILE" ]]; then cat "$MODE_FILE" 2>/dev/null || echo "split"; else echo "split"; fi
}

set_mode_flag() { echo "$1" > "$MODE_FILE"; }

ensure_policy_routing_for_ports() {
  if ! ip link show "${WG_IF}" &>/dev/null; then return 0; fi
  if ! ip rule show | grep -q "fwmark 0x1 lookup ${ROUTE_TABLE_ID}"; then ip rule add fwmark 0x1 lookup ${ROUTE_TABLE_ID}; fi
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
  done < "$PORT_LIST_FILE"
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
  if grep -qx "$port" "$PORT_LIST_FILE"; then
    return 0
  fi
  echo "$port" >> "$PORT_LIST_FILE"
}

remove_port_from_list() {
  local port="$1"
  [[ ! -f "$PORT_LIST_FILE" ]] && return 0
  if ! grep -qx "$port" "$PORT_LIST_FILE"; then
    return 0
  fi
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
    done < "$PORT_LIST_FILE"
  fi
  ip link set dev "${WG_IF}" mtu "${WG_SAFE_MTU}" 2>/dev/null || true
  set_mode_flag "split"
}

apply_current_mode() {
  local mode
  mode="$(get_current_mode)"
  if [[ "$mode" == "global" ]]; then
    enable_global_mode
  else
    enable_split_mode
  fi
}

configure_exit() {
  set_role "exit"
  ensure_dirs
  install_base_packages
  install_wireguard
  install_wstunnel
  local pub_ip_detected domain wg_addr entry_wg_ip out_if
  local entry_public_key ws_port path_prefix default_if
  local wg_udp_port backend_port
  pub_ip_detected="$(detect_public_ip || true)"
  read -rp "出口服务器绑定域名（必须已解析到本机）: " domain
  if [[ -z "$domain" ]]; then
    return
  fi
  echo "$domain" > "$WST_DOMAIN_FILE"
  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/24): " wg_addr
  wg_addr="${wg_addr:-10.0.0.1/24}"
  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/32): " entry_wg_ip
  entry_wg_ip="${entry_wg_ip:-10.0.0.2/32}"
  default_if=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
  read -rp "出口服务器对外网卡名(默认 ${default_if:-eth0}): " out_if
  out_if="${out_if:-${default_if:-eth0}}"
  read -rp "Nginx/WSS 对外端口 (默认 443): " ws_port
  ws_port="${ws_port:-443}"
  read -rp "出口服务器 WG 真正监听 UDP 端口 (默认 ${WG_SERVER_PORT_DEFAULT}): " wg_udp_port
  wg_udp_port="${wg_udp_port:-$WG_SERVER_PORT_DEFAULT}"
  backend_port=$((RANDOM % 1000 + 30000))
  local recommended_path="static/assets/img_$(rand_str | head -c 6)"
  read -rp "WebSocket 路径前缀/密钥 (默认 ${recommended_path}): " path_prefix
  path_prefix="${path_prefix:-${recommended_path}}"
  write_nginx_http_site_for_acme "$domain"
  issue_letsencrypt_cert "$domain"
  write_nginx_https_wstunnel_site "$domain" "$backend_port" "$path_prefix"
  read -rp "请输入【入口服务器公钥】: " entry_public_key
  entry_public_key="${entry_public_key:-CHANGE_ME_ENTRY_PUBLIC_KEY}"
  configure_exit_wg "$wg_addr" "$entry_wg_ip" "$entry_public_key" "$out_if" "$wg_udp_port"
  setup_exit_wstunnel_service "$backend_port" "$path_prefix" "$wg_udp_port"
  save_wst_params "$domain" "$ws_port" "$path_prefix" "y"
}

configure_entry() {
  set_role "entry"
  ensure_dirs
  install_base_packages
  install_wireguard
  install_wstunnel
  local wg_addr exit_wg_ip exit_public_key
  local exit_host ws_port path_prefix verify_tls
  local local_udp_port remote_wg_udp_port
  local saved_host saved_port saved_path saved_verify
  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/24): " wg_addr
  wg_addr="${wg_addr:-10.0.0.2/24}"
  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/32): " exit_wg_ip
  exit_wg_ip="${exit_wg_ip:-10.0.0.1/32}"
  saved_host=""
  saved_port=""
  saved_path=""
  saved_verify=""
  [[ -f "$WST_REMOTE_HOST_FILE" ]] && saved_host="$(cat "$WST_REMOTE_HOST_FILE" 2>/dev/null || true)"
  [[ -f "$WST_REMOTE_PORT_FILE" ]] && saved_port="$(cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true)"
  [[ -f "$WST_PATH_FILE" ]] && saved_path="$(cat "$WST_PATH_FILE" 2>/dev/null || true)"
  [[ -f "$WST_VERIFY_FILE" ]] && saved_verify="$(cat "$WST_VERIFY_FILE" 2>/dev/null || true)"
  read -rp "出口服务器域名 / IP (默认 ${saved_host:-}): " exit_host
  exit_host="${exit_host:-$saved_host}"
  read -rp "wss 端口 (默认 ${saved_port:-443}): " ws_port
  ws_port="${ws_port:-${saved_port:-443}}"
  read -rp "路径前缀 (默认 ${saved_path:-自动生成}): " path_prefix
  path_prefix="${path_prefix:-${saved_path:-$(rand_str)}}"
  read -rp "是否严格校验证书? (Y/n，正式域名证书建议 Y): " verify_tls
  verify_tls="${verify_tls:-Y}"
  read -rp "入口本地 wstunnel 监听 UDP 端口 (默认 ${WST_LOCAL_UDP_PORT_DEFAULT}): " local_udp_port
  local_udp_port="${local_udp_port:-$WST_LOCAL_UDP_PORT_DEFAULT}"
  read -rp "远端出口 WG UDP 端口 (默认 ${WG_SERVER_PORT_DEFAULT}): " remote_wg_udp_port
  remote_wg_udp_port="${remote_wg_udp_port:-$WG_SERVER_PORT_DEFAULT}"
  save_wst_params "$exit_host" "$ws_port" "$path_prefix" "$verify_tls"
  setup_entry_wstunnel_service "$exit_host" "$ws_port" "$path_prefix" "$verify_tls" "$local_udp_port" "$remote_wg_udp_port"
  if [[ -f "${WG_DIR}/entry_public.key" ]]; then
    cat "${WG_DIR}/entry_public.key" 2>/dev/null || true
  fi
  read -rp "请输入【出口服务器公钥】: " exit_public_key
  exit_public_key="${exit_public_key:-CHANGE_ME_EXIT_PUBLIC_KEY}"
  configure_entry_wg "$wg_addr" "$exit_wg_ip" "$exit_public_key" "$local_udp_port"
  ensure_server_bypass_route
  ensure_policy_routing_for_ports
  set_mode_flag "split"
  apply_current_mode
}

manage_entry_ports() {
  ensure_policy_routing_for_ports
  while true; do
    read -rp "请选择: " sub
    case "$sub" in
      1)
        if [[ -f "$PORT_LIST_FILE" ]] && [[ -s "$PORT_LIST_FILE" ]]; then
          cat "$PORT_LIST_FILE"
        fi
        ;;
      2)
        read -rp "端口: " new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && [[ "$new_port" -ge 1 ]] && [[ "$new_port" -le 65535 ]] && [[ "$new_port" -ne 22 ]]; then
          add_port_to_list "$new_port"
          ensure_policy_routing_for_ports
          apply_port_rules_from_file
          add_forward_port_mapping "$new_port"
        fi
        ;;
      3)
        read -rp "要删除的端口: " del_port
        if [[ "$del_port" =~ ^[0-9]+$ ]]; then
          remove_port_from_list "$del_port"
          remove_port_iptables_rules "$del_port"
          remove_forward_port_mapping "$del_port"
        fi
        ;;
      0) break ;;
    esac
  done
}

manage_entry_mode() {
  while true; do
    local mode
    mode="$(get_current_mode)"
    read -rp "请选择: " sub
    case "$sub" in
      1) enable_global_mode ;;
      2) enable_split_mode ;;
      0) break ;;
    esac
  done
}

show_status() {
  get_role
  get_current_mode
  if [[ -f "$WST_REMOTE_HOST_FILE" ]]; then cat "$WST_REMOTE_HOST_FILE" 2>/dev/null || true; fi
  if [[ -f "$WST_REMOTE_PORT_FILE" ]]; then cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true; fi
  if [[ -f "$WST_PATH_FILE" ]]; then cat "$WST_PATH_FILE" 2>/dev/null || true; fi
  if [[ -f "$WST_DOMAIN_FILE" ]]; then cat "$WST_DOMAIN_FILE" 2>/dev/null || true; fi
  wg show || true
  systemctl --no-pager --full status wstunnel-exit.service 2>/dev/null | sed -n '1,6p' || true
  systemctl --no-pager --full status wstunnel-entry.service 2>/dev/null | sed -n '1,6p' || true
  systemctl --no-pager --full status nginx 2>/dev/null | sed -n '1,6p' || true
  if [[ -f "$PORT_LIST_FILE" ]] && [[ -s "$PORT_LIST_FILE" ]]; then
    cat "$PORT_LIST_FILE"
  fi
}

start_wg() {
  local role
  role="$(get_role)"
  if [[ "$role" == "exit" ]]; then
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    wg-quick up "${WG_IF}" 2>/dev/null || true
    systemctl restart nginx 2>/dev/null || true
    systemctl restart wstunnel-exit.service 2>/dev/null || true
  elif [[ "$role" == "entry" ]]; then
    systemctl restart wstunnel-entry.service 2>/dev/null || true
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    wg-quick up "${WG_IF}" 2>/dev/null || true
    ensure_server_bypass_route
    apply_current_mode
  fi
}

stop_wg() {
  local role
  role="$(get_role)"
  if [[ "$role" == "exit" ]]; then
    systemctl stop wstunnel-exit.service 2>/dev/null || true
  elif [[ "$role" == "entry" ]]; then
    systemctl stop wstunnel-entry.service 2>/dev/null || true
  fi
  wg-quick down "${WG_IF}" 2>/dev/null || true
  ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true
  clear_mark_rules
}

restart_wg() {
  stop_wg
  start_wg
}

update_wstunnel_entry_remote_ip() {
  [[ "$(get_role)" == "entry" ]] || return 1
  ensure_dirs
  local new_host new_port new_path verify_tls
  local saved_port saved_path saved_verify local_udp_port remote_wg_udp_port
  [[ -f "$WST_REMOTE_PORT_FILE" ]] && saved_port="$(cat "$WST_REMOTE_PORT_FILE" 2>/dev/null || true)"
  [[ -f "$WST_PATH_FILE" ]] && saved_path="$(cat "$WST_PATH_FILE" 2>/dev/null || true)"
  [[ -f "$WST_VERIFY_FILE" ]] && saved_verify="$(cat "$WST_VERIFY_FILE" 2>/dev/null || true)"
  [[ -f "$WST_LOCAL_UDP_PORT_FILE" ]] && local_udp_port="$(cat "$WST_LOCAL_UDP_PORT_FILE" 2>/dev/null || true)"
  [[ -f "$WST_WG_UDP_PORT_FILE" ]] && remote_wg_udp_port="$(cat "$WST_WG_UDP_PORT_FILE" 2>/dev/null || true)"
  read -rp "新出口域名 / IP: " new_host
  read -rp "wss 端口 (默认 ${saved_port:-443}): " new_port
  new_port="${new_port:-${saved_port:-443}}"
  read -rp "路径前缀 (默认 ${saved_path:-v1}): " new_path
  new_path="${new_path:-${saved_path:-v1}}"
  read -rp "是否严格校验证书? (默认 ${saved_verify:-Y}): " verify_tls
  verify_tls="${verify_tls:-${saved_verify:-Y}}"
  local_udp_port="${local_udp_port:-$WST_LOCAL_UDP_PORT_DEFAULT}"
  remote_wg_udp_port="${remote_wg_udp_port:-$WG_SERVER_PORT_DEFAULT}"
  save_wst_params "$new_host" "$new_port" "$new_path" "$verify_tls"
  ensure_server_bypass_route
  setup_entry_wstunnel_service "$new_host" "$new_port" "$new_path" "$verify_tls" "$local_udp_port" "$remote_wg_udp_port"
}

renew_cert_now() {
  if [[ "$(get_role)" != "exit" ]]; then
    return
  fi
  install_certbot
  certbot renew --nginx </dev/null
  nginx -t && systemctl reload nginx
}

uninstall_wg() {
  read -rp "确认彻底卸载并清理？(y/N): " confirm
  if [[ ! "$confirm" =~ ^[yY]$ ]]; then
    return 0
  fi
  systemctl stop "wg-quick@${WG_IF}.service" 2>/dev/null || true
  systemctl disable "wg-quick@${WG_IF}.service" 2>/dev/null || true
  wg-quick down "${WG_IF}" 2>/dev/null || true
  ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true
  clear_mark_rules
  if [[ -f "$PORT_LIST_FILE" ]]; then
    while read -r p; do
      [[ -z "$p" ]] && continue
      iptables -t mangle -D OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || true
      iptables -t mangle -D OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || true
      iptables -t mangle -D PREROUTING -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || true
      iptables -t mangle -D PREROUTING -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || true
      remove_forward_port_mapping "$p"
    done < "$PORT_LIST_FILE"
  fi
  systemctl stop wstunnel-exit.service wstunnel-entry.service 2>/dev/null || true
  systemctl disable wstunnel-exit.service wstunnel-entry.service 2>/dev/null || true
  rm -f /etc/systemd/system/wstunnel-exit.service /etc/systemd/system/wstunnel-entry.service 2>/dev/null || true
  systemctl daemon-reload || true

  read -rp "是否连同Nginx伪装站点以及TLS证书一起彻底抹除？[y/N (默认N)]: " del_cert
  del_cert="${del_cert:-N}"

  if [[ "$del_cert" =~ ^[yY]$ ]]; then
    if [[ -f "$WST_DOMAIN_FILE" ]]; then
        local d
        d="$(cat "$WST_DOMAIN_FILE" 2>/dev/null || true)"
        if [[ -n "$d" ]]; then
           rm -rf "${WEB_ROOT_BASE}/${d}" 2>/dev/null || true
           certbot delete --cert-name "$d" --non-interactive </dev/null 2>/dev/null || true
        fi
    fi
    if [[ -f "$WST_NGINX_SITE_FILE" ]]; then
        local site_file
        site_file="$(cat "$WST_NGINX_SITE_FILE" 2>/dev/null || true)"
        if [[ -n "$site_file" ]]; then
          rm -f "$site_file" 2>/dev/null || true
          rm -f "${NGINX_SITE_ENABLED_DIR}/$(basename "$site_file")" 2>/dev/null || true
        fi
    fi
    sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null || true
    sysctl -p >/dev/null 2>&1 || true
  else
    if [[ -f "$WST_NGINX_SITE_FILE" ]]; then
      local site_file
      site_file="$(cat "$WST_NGINX_SITE_FILE" 2>/dev/null || true)"
      if [[ -n "$site_file" ]]; then
        rm -f "$site_file" 2>/dev/null || true
        rm -f "${NGINX_SITE_ENABLED_DIR}/$(basename "$site_file")" 2>/dev/null || true
        nginx -t && systemctl reload nginx || true
      fi
    fi
  fi

  if [[ -f "$INSTALLED_PKGS_FILE" ]]; then
    local pkgs_to_remove=()
    while read -r pkg; do
      [[ -z "$pkg" ]] && continue
      if [[ ! "$del_cert" =~ ^[yY]$ ]] && [[ "$pkg" =~ nginx|certbot ]]; then
        continue
      fi
      pkgs_to_remove+=("$pkg")
    done < "$INSTALLED_PKGS_FILE"

    if [[ ${#pkgs_to_remove[@]} -gt 0 ]]; then
      echo "⏳ 正在卸载由脚本安装的依赖: ${pkgs_to_remove[*]}"
      apt purge -y "${pkgs_to_remove[@]}" </dev/null 2>/dev/null || true
      apt autoremove -y </dev/null 2>/dev/null || true
    fi
  fi

  rm -rf "$WST_DIR" "$WG_DIR" 2>/dev/null || true
  rm -f "$WSTUNNEL_BIN" 2>/dev/null || true
  rm -f "$0" 2>/dev/null || true
  echo "✅ 卸载并清理完成。"
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
  echo "10) 修改出口 IP / 域名"
  echo "11) 手动执行证书续期（仅出口）"
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
    8) [[ "$(get_role)" == "entry" ]] && manage_entry_ports || echo "❌ 仅入口可用" ;;
    9) [[ "$(get_role)" == "entry" ]] && manage_entry_mode || echo "❌ 仅入口可用" ;;
    10) [[ "$(get_role)" == "entry" ]] && update_wstunnel_entry_remote_ip || echo "❌ 仅入口可用" ;;
    11) renew_cert_now ;;
    0) exit 0 ;;
    *) echo "无效。" ;;
  esac
done
