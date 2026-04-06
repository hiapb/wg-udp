#!/usr/bin/env bash
set -euo pipefail

SING_IF="tun0"
SING_DIR="/etc/singbox"
SING_BIN="/usr/local/bin/sing-box"
SING_VERSION="1.13.5"

PORT_LIST_FILE="${SING_DIR}/.ports"
MODE_FILE="${SING_DIR}/.mode"
EXIT_IP_FILE="${SING_DIR}/.exit_ip"
ROLE_FILE="${SING_DIR}/.role"

NGINX_SITE_DIR="/etc/nginx/sites-available"
NGINX_SITE_ENABLED_DIR="/etc/nginx/sites-enabled"
WEB_ROOT_BASE="/var/www"

SING_SAFE_MTU=1320
SING_DEFAULT_PORT=443

ROUTE_TABLE_ID=51820

SNI_LIST_FILE="${SING_DIR}/sni_list.txt"
SNI_ROTATE_TIMER="/etc/systemd/system/sni-rotate.timer"
SNI_ROTATE_SERVICE="/etc/systemd/system/sni-rotate.service"

if [[ $EUID -ne 0 ]]; then
  echo "❌ 权限不足：请以 root 身份运行此脚本。"
  exit 1
fi

get_role() {
  [[ -f "$ROLE_FILE" ]] && cat "$ROLE_FILE" 2>/dev/null || echo "unknown"
}

set_role() {
  local role="$1"
  mkdir -p "$(dirname "$ROLE_FILE")"
  echo "$role" > "$ROLE_FILE"
}

rand_str() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

detect_public_ip() {
  local ip=""
  for svc in "https://api.ipify.org" "https://ifconfig.me"; do
    ip=$(curl -4 -fsS --max-time 3 "$svc" 2>/dev/null || true)
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

ensure_dirs() {
  mkdir -p "$SING_DIR"
  chmod 700 "$SING_DIR"
}

get_wan_if() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || echo "eth0"
}

enable_ip_forward_global() {
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
}

install_base_packages() {
  echo "[*] 安装基础依赖..."
  apt-get update -yq
  apt-get install -yq curl wget tar jq nginx certbot python3-certbot-nginx
}

ensure_server_bypass_route() {
  echo "[*] 确保本地系统路由分流策略生效..."
  enable_ip_forward_global
}

init_sni_list() {
  mkdir -p "$SING_DIR"
  if [[ ! -f "$SNI_LIST_FILE" ]]; then
    cat > "$SNI_LIST_FILE" <<EOF
itunes.apple.com
www.apple.com
update.apple.com
gateway.icloud.com
www.samsung.com
www.google.com
EOF
  fi
}

get_random_sni() {
  init_sni_list
  shuf -n 1 "$SNI_LIST_FILE"
}

rotate_client_sni() {
  [[ "$(get_role)" != "entry" ]] && { echo "❌ 此功能仅限入口服务器可用"; return; }
  echo "==== 手动切换客户端 SNI ===="
  local new_sni
  new_sni=$(get_random_sni)
  echo "[*] 正在切换至: $new_sni"
  
  if [[ -f "${SING_DIR}/config.json" ]]; then
    /usr/bin/jq --arg sni "$new_sni" '.outbounds[0].tls.server_name = $sni' "${SING_DIR}/config.json" > "${SING_DIR}/config.json.tmp"
    mv "${SING_DIR}/config.json.tmp" "${SING_DIR}/config.json"
    systemctl restart singbox-entry.service
    echo "✅ SNI 切换成功！当前已生效: $new_sni"
  else
    echo "❌ 找不到配置文件！"
  fi
}

setup_sni_rotation() {
  echo "[*] 配置自动定时轮换机制 (Systemd Timer)..."
  
  cat > "${SING_DIR}/rotate.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
new_sni=$(shuf -n 1 /etc/singbox/sni_list.txt)
/usr/bin/jq --arg sni "$new_sni" '.outbounds[0].tls.server_name = $sni' /etc/singbox/config.json > /etc/singbox/config.json.tmp
mv /etc/singbox/config.json.tmp /etc/singbox/config.json
systemctl restart singbox-entry.service
EOF
  
  chmod +x "${SING_DIR}/rotate.sh"

  cat > "$SNI_ROTATE_SERVICE" <<EOF
[Unit]
Description=Rotate Sing-box Reality SNI

[Service]
Type=oneshot
ExecStart=/etc/singbox/rotate.sh
EOF

  cat > "$SNI_ROTATE_TIMER" <<EOF
[Unit]
Description=Timer for SNI Rotation

[Timer]
OnUnitActiveSec=6h
RandomizedDelaySec=1800
Unit=sni-rotate.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now sni-rotate.timer
  echo "✅ SNI 定时轮换开启（每 6 小时触发一次，外加 30 分钟随机时间扰动）"
}

install_singbox() {
  echo "[*] 检查 sing-box Reality 核心..."
  if [[ -x "$SING_BIN" ]]; then
    echo "[*] sing-box 已就绪"
    return 0
  fi

  local arch file url_base url_bin url_sum tmpdir
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) file="sing-box-${SING_VERSION}-linux-amd64.tar.gz" ;;
    aarch64|arm64) file="sing-box-${SING_VERSION}-linux-arm64.tar.gz" ;;
    *) echo "❌ 不支持的架构: $arch"; exit 1 ;;
  esac

  url_base="https://github.com/SagerNet/sing-box/releases/download/v${SING_VERSION}"
  url_bin="${url_base}/${file}"
  url_sum="${url_base}/sing-box-${SING_VERSION}-linux-amd64.tar.gz.sha256sum"

  tmpdir="$(mktemp -d)"
  (
    cd "$tmpdir"
    echo "[*] 下载 sing-box ${SING_VERSION}..."
    curl -L --fail "$url_bin" -o "$file"
    curl -L --fail "$url_sum" -o checksums.txt

    echo "[*] 执行 SHA256 校验..."
    if ! grep "$file" checksums.txt | sha256sum -c -; then
      echo "❌ 致命错误：sing-box 二进制哈希校验失败！"
      exit 1
    fi

    tar -xzf "$file"
    install -m 0755 sing-box "$SING_BIN"
  )
  rm -rf "$tmpdir"
  echo "✅ sing-box Reality 已安全安装"
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
    location / { return 301 https://\$host\$request_uri; }
}
EOF
  ln -sf "$site_file" "${NGINX_SITE_ENABLED_DIR}/${domain}.conf"
  nginx -t && systemctl restart nginx
}

issue_letsencrypt_cert() {
  local domain="$1"
  certbot --nginx -d "$domain" --non-interactive --agree-tos -m "admin@${domain}" --redirect
}

write_nginx_https_reality_site() {
  local domain="$1" short_id="$2"
  local site_file="${NGINX_SITE_DIR}/${domain}.conf"
  local web_root="${WEB_ROOT_BASE}/${domain}"

  mkdir -p "$web_root"
  cat > "$web_root/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>系统架构与研发笔记</title>
<style>body{font-family:system-ui;margin:40px auto;max-width:860px;line-height:1.6;color:#333;}</style>
</head>
<body>
<h1>后端架构与协议解析</h1>
<p>记录微服务、容器化、网络协议（TCP/IP、Reality、Vision）实战经验。</p>
<p>更新时间：2026年4月</p>
<hr>
<p>© 2026 All Rights Reserved. 内部技术文档。</p>
</body>
</html>
EOF

  echo "User-agent: *" > "$web_root/robots.txt"
  echo "Disallow: /${short_id}" >> "$web_root/robots.txt"

  cat > "$site_file" <<EOF
server {
    listen 80;
    server_name ${domain};
    location ^~ /.well-known/acme-challenge/ { root ${web_root}; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 127.0.0.1:8443 ssl http2;
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

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
        try_files \$uri \$uri/ /index.html;
    }

    location ^~ /${short_id} {
        return 444; 
    }
}
EOF

  ln -sf "$site_file" "${NGINX_SITE_ENABLED_DIR}/${domain}.conf"
  nginx -t && systemctl restart nginx
  echo "✅ 高保真静态伪装站已部署（Reality 隐藏在 443）"
}

build_singbox_routes() {
  [[ ! -f "${SING_DIR}/config.json" ]] && return 0
  
  local mode="$(cat "$MODE_FILE" 2>/dev/null || echo "split")"
  local ports_json="[]"
  
  if [[ -f "$PORT_LIST_FILE" ]]; then
    ports_json=$(awk 'NF && !/^#/{print int($1)}' "$PORT_LIST_FILE" | /usr/bin/jq -R . | /usr/bin/jq -s 'map(tonumber)')
    [[ -z "$ports_json" ]] && ports_json="[]"
  fi

  if [[ "$mode" == "global" ]]; then
    /usr/bin/jq '.route.rules = [
      {"port": [22], "outbound": "direct"},
      {"inbound": ["tun-in"], "outbound": "reality-out"}
    ]' "${SING_DIR}/config.json" > "${SING_DIR}/config.json.tmp"
  else
    if [[ "$ports_json" == "[]" ]]; then
      /usr/bin/jq '.route.rules = [
        {"port": [22], "outbound": "direct"},
        {"outbound": "direct"}
      ]' "${SING_DIR}/config.json" > "${SING_DIR}/config.json.tmp"
    else
      /usr/bin/jq --argjson p "$ports_json" '.route.rules = [
        {"port": [22], "outbound": "direct"},
        {"inbound": ["tun-in"], "port": $p, "outbound": "reality-out"},
        {"outbound": "direct"}
      ]' "${SING_DIR}/config.json" > "${SING_DIR}/config.json.tmp"
    fi
  fi
  
  mv "${SING_DIR}/config.json.tmp" "${SING_DIR}/config.json"
}

setup_exit_reality() {
  local domain="$1" short_id="$2" uuid="$3" private_key="$4"

  cat > "${SING_DIR}/config.json" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "vless",
    "tag": "reality-in",
    "listen": "::",
    "listen_port": 443,
    "users": [{"uuid": "${uuid}", "flow": "xtls-rprx-vision"}],
    "tls": {
      "enabled": true,
      "server_name": "${domain}",
      "reality": {
        "enabled": true,
        "handshake": {
          "server_opts": {
            "server_names": ["${domain}"]
          }
        },
        "private_key": "${private_key}",
        "short_id": ["${short_id}"],
        "dest": "127.0.0.1:8443"
      }
    }
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"inbound": "reality-in", "outbound": "direct"}]}
}
EOF

  cat > /etc/systemd/system/singbox-exit.service <<EOF
[Unit]
Description=sing-box Reality Exit (VLESS + Reality + Vision)
After=network-online.target
[Service]
Type=simple
ExecStart=${SING_BIN} run -c ${SING_DIR}/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now singbox-exit.service
  echo "✅ 出口 Reality 服务端已启动（端口 443）"
}

setup_entry_reality() {
  local remote_host="$1" short_id="$2" public_key="$3" uuid="$4" chosen_sni="$5"

  cat > "${SING_DIR}/config.json" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "tun",
    "tag": "tun-in",
    "interface_name": "${SING_IF}",
    "inet4_address": "172.19.0.1/30",
    "auto_route": true,
    "strict_route": true,
    "sniff": true,
    "stack": "system"
  }],
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-out",
      "server": "${remote_host}",
      "server_port": 443,
      "uuid": "${uuid}",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "xudp",
      "tls": {
        "enabled": true,
        "server_name": "${chosen_sni}",
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {
          "enabled": true,
          "public_key": "${public_key}",
          "short_id": "${short_id}"
        }
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": []
  }
}
EOF

  cat > /etc/systemd/system/singbox-entry.service <<EOF
[Unit]
Description=sing-box Reality Entry Client (TUN + VLESS-Reality-Vision)
After=network-online.target
[Service]
Type=simple
ExecStart=${SING_BIN} run -c ${SING_DIR}/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now singbox-entry.service
  echo "✅ 入口 Reality 客户端已启动（TUN 全局/分流模式）"
}

get_current_mode() {
  [[ -f "$MODE_FILE" ]] && cat "$MODE_FILE" 2>/dev/null || echo "split"
}

set_mode_flag() { echo "$1" > "$MODE_FILE"; }

enable_global_mode() {
  echo "[*] 切换为【全局模式】..."
  set_mode_flag "global"
  build_singbox_routes
  systemctl restart singbox-entry.service 2>/dev/null || true
  echo "✅ 已切换全局模式（sing-box TUN）"
}

enable_split_mode() {
  echo "[*] 切换为【端口分流模式】..."
  set_mode_flag "split"
  build_singbox_routes
  systemctl restart singbox-entry.service 2>/dev/null || true
  echo "✅ 已切换端口分流模式（sing-box TUN）"
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

choose_sni() {
  init_sni_list
  echo "==== 请选择初始 SNI ====" >&2
  echo "1) itunes.apple.com (默认)" >&2
  echo "2) www.apple.com" >&2
  echo "3) update.apple.com" >&2
  echo "4) gateway.icloud.com" >&2
  echo "5) www.samsung.com" >&2
  echo "6) www.google.com" >&2
  read -rp "输入序号 [1-6]: " sni_idx >&2
  case "$sni_idx" in
    2) echo "www.apple.com" ;;
    3) echo "update.apple.com" ;;
    4) echo "gateway.icloud.com" ;;
    5) echo "www.samsung.com" ;;
    6) echo "www.google.com" ;;
    *) echo "itunes.apple.com" ;;
  esac
}

configure_exit() {
  echo "==== 配置为【出口服务器】（Reality） ===="
  set_role "exit"

  ensure_dirs
  install_base_packages
  install_singbox

  local domain short_id uuid private_key pub_ip

  pub_ip="$(detect_public_ip || true)"
  [[ -n "$pub_ip" ]] && echo "[*] 检测到公网 IP：$pub_ip"

  read -rp "出口服务器绑定域名（必须解析到本机）: " domain
  [[ -z "$domain" ]] && { echo "❌ 域名不能为空"; return; }

  short_id="$(rand_str)"
  uuid="$(cat /proc/sys/kernel/random/uuid)"
  
  local keypair
  keypair=$(${SING_BIN} generate reality-keypair)
  private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
  public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')

  echo "$domain" > "${SING_DIR}/domain"
  echo "$short_id" > "${SING_DIR}/short_id"
  echo "$uuid" > "${SING_DIR}/uuid"
  echo "$public_key" > "${SING_DIR}/public_key"

  write_nginx_http_site_for_acme "$domain"
  issue_letsencrypt_cert "$domain"
  write_nginx_https_reality_site "$domain" "$short_id"

  setup_exit_reality "$domain" "$short_id" "$uuid" "$private_key"

  echo
  echo "====== 出口服务器信息（给入口用）======"
  echo "域名: ${domain}"
  echo "short_id: ${short_id}"
  echo "public_key: ${public_key}"
  echo "UUID: ${uuid}"
  echo "======================================"
}

configure_entry() {
  echo "==== 配置为【入口服务器】（Reality） ===="
  set_role "entry"

  ensure_dirs
  install_base_packages
  install_singbox

  local remote_host short_id public_key uuid chosen_sni enable_rotate

  read -rp "出口服务器域名/IP: " remote_host
  read -rp "short_id: " short_id
  read -rp "public_key: " public_key
  read -rp "UUID: " uuid

  chosen_sni=$(choose_sni)

  read -rp "是否开启 SNI 自动定时轮换？(Y/n): " enable_rotate
  if [[ "${enable_rotate,,}" == "y" || -z "$enable_rotate" ]]; then
    setup_sni_rotation
  fi

  echo "$remote_host" > "${SING_DIR}/remote_host"
  echo "$short_id" > "${SING_DIR}/short_id"
  echo "$public_key" > "${SING_DIR}/public_key"
  echo "$uuid" > "${SING_DIR}/uuid"
  echo "$chosen_sni" > "${SING_DIR}/chosen_sni"

  setup_entry_reality "$remote_host" "$short_id" "$public_key" "$uuid" "$chosen_sni"

  ensure_server_bypass_route
  set_mode_flag "split"
  build_singbox_routes
  systemctl restart singbox-entry.service
}

manage_entry_ports() {
  echo "端口分流管理"
  while true; do
    echo "1) 查看列表"
    echo "2) 添加端口"
    echo "3) 删除端口"
    echo "0) 返回"
    read -rp "请选择: " sub

    case "$sub" in
      1)
        if [[ -f "$PORT_LIST_FILE" ]] && [[ -s "$PORT_LIST_FILE" ]]; then
          cat "$PORT_LIST_FILE"
        else
          echo "(空)"
        fi
        ;;
      2)
        read -rp "端口: " new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ] && [ "$new_port" -ne 22 ]; then
          mkdir -p "$(dirname "$PORT_LIST_FILE")"
          touch "$PORT_LIST_FILE"
          if grep -qx "$new_port" "$PORT_LIST_FILE"; then
            echo "端口 $new_port 已存在列表中。"
          else
            echo "$new_port" >> "$PORT_LIST_FILE"
            echo "已添加端口 $new_port 到分流列表。"
            build_singbox_routes
            systemctl restart singbox-entry.service
          fi
        fi
        ;;
      3)
        read -rp "要删除的端口: " del_port
        if [[ "$del_port" =~ ^[0-9]+$ ]]; then
          if [[ -f "$PORT_LIST_FILE" ]] && grep -qx "$del_port" "$PORT_LIST_FILE"; then
            sed -i "\|^$del_port$|d" "$PORT_LIST_FILE"
            echo "已从分流列表中删除端口 $del_port。"
            build_singbox_routes
            systemctl restart singbox-entry.service
          else
            echo "端口 $del_port 不在列表中。"
          fi
        fi
        ;;
      0) break ;;
    esac
  done
}

manage_entry_mode() {
  while true; do
    local mode="$(get_current_mode)"
    echo "当前模式：$mode"
    echo "1) 切换为【全局模式】"
    echo "2) 切换为【端口分流模式】"
    echo "0) 返回"
    read -rp "请选择: " sub
    case "$sub" in
      1) enable_global_mode ;;
      2) enable_split_mode ;;
      0) break ;;
      *) echo "无效" ;;
    esac
  done
}

show_status() {
  echo "==== Reality 链路状态 ===="
  echo "角色：$(get_role)"
  echo "模式：$(get_current_mode)"
  echo
  [[ -f "${SING_DIR}/remote_host" ]] && echo "出口地址：$(cat "${SING_DIR}/remote_host")"
  echo
  echo "==== sing-box ===="
  systemctl --no-pager status singbox-exit.service 2>/dev/null | head -n 8 || true
  systemctl --no-pager status singbox-entry.service 2>/dev/null | head -n 8 || true
  echo
  echo "==== Nginx ===="
  systemctl --no-pager status nginx 2>/dev/null | head -n 6 || true
}

start_wg() {
  echo "[*] 启动 Reality 链路..."
  local role="$(get_role)"
  if [[ "$role" == "exit" ]]; then
    systemctl restart singbox-exit.service nginx 2>/dev/null || true
  elif [[ "$role" == "entry" ]]; then
    systemctl restart singbox-entry.service 2>/dev/null || true
    apply_current_mode
  fi
}

stop_wg() {
  echo "[*] 停止 Reality 链路..."
  systemctl stop singbox-exit.service singbox-entry.service 2>/dev/null || true
}

restart_wg() { stop_wg; start_wg; }

update_remote() {
  [[ "$(get_role)" != "entry" ]] && { echo "❌ 仅入口可用"; return; }
  echo "更新出口地址..."
  read -rp "新出口域名/IP: " new_host
  echo "$new_host" > "${SING_DIR}/remote_host"
  build_singbox_routes
  systemctl restart singbox-entry.service
  echo "✅ 已更新"
}

renew_cert_now() {
  [[ "$(get_role)" != "exit" ]] && { echo "❌ 仅出口可用"; return; }
  certbot renew --nginx
  nginx -t && systemctl reload nginx
}

uninstall() {
  read -rp "确认彻底卸载 Reality？(y/N): " confirm
  [[ ! "$confirm" =~ ^[yY]$ ]] && return
  systemctl stop singbox-exit.service singbox-entry.service nginx 2>/dev/null || true
  systemctl disable singbox-exit.service singbox-entry.service sni-rotate.timer 2>/dev/null || true
  rm -f /etc/systemd/system/singbox-*.service /etc/systemd/system/sni-rotate.*
  rm -rf "$SING_DIR" "$SING_BIN"
  apt remove -y wireguard wireguard-tools 2>/dev/null || true
  echo "✅ Reality 已彻底清理"
  rm -f "$0"
  exit 0
}

while true; do
  echo
  echo "================ 📡 Reality VLESS + Vision + uTLS 高级链路 ================"
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
  echo "12) 手动切换 SNI"
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
    7) uninstall ;;
    8) [[ "$(get_role)" == "entry" ]] && manage_entry_ports || echo "❌ 仅入口可用" ;;
    9) [[ "$(get_role)" == "entry" ]] && manage_entry_mode || echo "❌ 仅入口可用" ;;
    10) [[ "$(get_role)" == "entry" ]] && update_remote || echo "❌ 仅入口可用" ;;
    11) renew_cert_now ;;
    12) rotate_client_sni ;;
    0) exit 0 ;;
    *) echo "无效选项" ;;
  esac
done
