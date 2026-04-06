#!/usr/bin/env bash
set -e

WG_IF="wg0"
PORT_LIST_FILE="/etc/wireguard/.wg_ports"
MODE_FILE="/etc/wireguard/.wg_mode"
EXIT_WG_IP_FILE="/etc/wireguard/.exit_wg_ip"
ROLE_FILE="/etc/wireguard/.wg_role"

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

UDP2RAW_BIN="/usr/local/bin/udp2raw"
UDPSPEEDER_BIN="/usr/local/bin/speederv2"
UDP2RAW_WORKDIR="/etc/udp2raw"
UDP2RAW_PSK_FILE="${UDP2RAW_WORKDIR}/psk"
UDP2RAW_CLIENT_PORT_FILE="${UDP2RAW_WORKDIR}/client_port"
UDP2RAW_SERVER_PORT_FILE="${UDP2RAW_WORKDIR}/server_port"
UDP2RAW_REMOTE_FILE="${UDP2RAW_WORKDIR}/remote"

WG_SAFE_MTU=1390
UDP2RAW_DEFAULT_PORT=40008

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行这个脚本： sudo bash wg.sh"
  exit 1
fi

install_wireguard() {
  echo "[*] 检查 WireGuard 及相关依赖..."
  NEED_PKGS=(wireguard wireguard-tools iproute2 iptables curl)
  MISSING_PKGS=()

  for pkg in "${NEED_PKGS[@]}"; do
    dpkg -s "$pkg" &>/dev/null || MISSING_PKGS+=("$pkg")
  done

  if [ ${#MISSING_PKGS[@]} -eq 0 ]; then
    echo "[*] 所有依赖已安装，跳过安装。"
    return
  fi

  echo "[*] 将安装缺失的依赖包: ${MISSING_PKGS[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y "${MISSING_PKGS[@]}"
}

install_udp2raw() {
  echo "[*] 检查 udp2raw ..."
  if [[ -x "$UDP2RAW_BIN" ]]; then
    echo "[*] udp2raw 已存在：$UDP2RAW_BIN"
    return
  fi

  mkdir -p "$UDP2RAW_WORKDIR"
  local url="https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz"
  
  tmpdir=$(mktemp -d)
  (
    cd "$tmpdir"
    echo "[*] 正在下载 udp2raw 压缩包..."
    curl -L "$url" -o udp2raw_binaries.tar.gz
    tar -xzf udp2raw_binaries.tar.gz

    arch=$(uname -m)
    bin_name=""
    case "$arch" in
      x86_64|amd64) bin_name="udp2raw_amd64" ;;
      aarch64|arm64) bin_name="udp2raw_aarch64" ;;
      armv7l|armv6l) bin_name="udp2raw_arm" ;;
      *)
        read -rp "无法自动匹配架构 $arch，请输入适用的二进制文件名(如 udp2raw_amd64): " bin_name
        ;;
    esac

    install -m 0755 "$bin_name" "$UDP2RAW_BIN"
  )
  rm -rf "$tmpdir"
  echo "✅ udp2raw 已安装到 $UDP2RAW_BIN"
}

install_udpspeeder() {
  echo "[*] 检查 UDPspeeder ..."
  if [[ -x "$UDPSPEEDER_BIN" ]]; then
    echo "[*] UDPspeeder 已存在：$UDPSPEEDER_BIN"
    return
  fi

  local url="https://github.com/wangyu-/UDPspeeder/releases/download/20230206.0/speederv2_binaries.tar.gz"
  
  tmpdir=$(mktemp -d)
  (
    cd "$tmpdir"
    echo "[*] 正在下载 UDPspeeder 压缩包..."
    curl -L -s "$url" -o speederv2_binaries.tar.gz
    tar -xzf speederv2_binaries.tar.gz

    arch=$(uname -m)
    bin_name=""
    case "$arch" in
      x86_64|amd64) bin_name="speederv2_amd64" ;;
      aarch64|arm64) bin_name="speederv2_aarch64" ;;
      *) bin_name="speederv2_amd64" ;; 
    esac

    install -m 0755 "$bin_name" "$UDPSPEEDER_BIN"
  )
  rm -rf "$tmpdir"
  echo "✅ UDPspeeder 已安装到 $UDPSPEEDER_BIN"
}

setup_exit_services() {
  local wg_port="$1"          # 通常为 51820
  local speeder_port="40000"  # 中间层内部端口
  local listen_port="$2"      # 对外暴露的伪装 TCP 端口
  local psk="$3"

  mkdir -p "$UDP2RAW_WORKDIR"
  echo "$psk" > "$UDP2RAW_PSK_FILE"
  echo "$listen_port" > "$UDP2RAW_SERVER_PORT_FILE"

  # 部署 UDPspeeder 服务端 (解包冗余)
  cat >/etc/systemd/system/udpspeeder-exit.service <<EOF
[Unit]
Description=UDPspeeder server for WireGuard
After=network-online.target wg-quick@${WG_IF}.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${UDPSPEEDER_BIN} -s -l 127.0.0.1:${speeder_port} -r 127.0.0.1:${wg_port} -f20:10 -k "${psk}" --mode 0 -q1
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

  # 部署 udp2raw 服务端 (接收外部流量并解伪装后转给 speeder)
  cat >/etc/systemd/system/udp2raw-exit.service <<EOF
[Unit]
Description=udp2raw server for UDPspeeder
After=network-online.target udpspeeder-exit.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${UDP2RAW_BIN} -s -l 0.0.0.0:${listen_port} -r 127.0.0.1:${speeder_port} -k "${psk}" --raw-mode faketcp -a
Restart=on-failure
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable udpspeeder-exit.service udp2raw-exit.service >/dev/null 2>&1 || true
  systemctl restart udpspeeder-exit.service udp2raw-exit.service || true

  iptables -I INPUT -p tcp --dport "${listen_port}" -j DROP 2>/dev/null || true
  echo "✅ FEC链路服务端 (udp2raw -> UDPspeeder) 已配置并尝试启动"
}

setup_entry_services() {
  local remote_ip="$1"
  local remote_port="$2"      # 远端出口服务器的 udp2raw 端口
  local udp2raw_local="40007" # 本地 udp2raw 监听端口
  local speeder_local="39999" # 本地 speeder 监听端口 (WG endpoint 指向此)
  local psk="$3"

  mkdir -p "$UDP2RAW_WORKDIR"
  echo "$psk" > "$UDP2RAW_PSK_FILE"
  echo "$udp2raw_local" > "$UDP2RAW_CLIENT_PORT_FILE"
  echo "${remote_ip}:${remote_port}" > "$UDP2RAW_REMOTE_FILE"

  # 部署 udp2raw 客户端 (发往真实远端)
  cat >/etc/systemd/system/udp2raw-entry.service <<EOF
[Unit]
Description=udp2raw client for UDPspeeder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${UDP2RAW_BIN} -c -l 127.0.0.1:${udp2raw_local} -r ${remote_ip}:${remote_port} -k "${psk}" --raw-mode faketcp -a
Restart=on-failure
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  # 部署 UDPspeeder 客户端 (矩阵编码加冗余并发往本地 udp2raw)
  cat >/etc/systemd/system/udpspeeder-entry.service <<EOF
[Unit]
Description=UDPspeeder client for WireGuard
After=network-online.target udp2raw-entry.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${UDPSPEEDER_BIN} -c -l 127.0.0.1:${speeder_local} -r 127.0.0.1:${udp2raw_local} -f20:10 -k "${psk}" --mode 0 -q1
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable udp2raw-entry.service udpspeeder-entry.service >/dev/null 2>&1 || true
  systemctl restart udp2raw-entry.service udpspeeder-entry.service || true

  echo "✅ FEC链路客户端 (UDPspeeder -> udp2raw) 已配置并尝试启动"
}

detect_public_ip() {
  for svc in "https://api.ipify.org" "https://ifconfig.me" "https://ipinfo.io/ip"; do
    ip=$(curl -4 -fsS "$svc" 2>/dev/null || true)
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

configure_exit() {
  echo "==== 配置为【出口服务器】 ===="
  set_role "exit"

  install_wireguard
  install_udp2raw
  install_udpspeeder

  PUB_IP_DETECTED=$(detect_public_ip || true)
  if [[ -n "$PUB_IP_DETECTED" ]]; then
    echo "[*] 检测到出口服务器公网 IP：$PUB_IP_DETECTED"
    read -rp "出口服务器公网 IP (默认自动检测到的 IP): " EXIT_PUBLIC_IP
    EXIT_PUBLIC_IP=${EXIT_PUBLIC_IP:-$PUB_IP_DETECTED}
  else
    echo "[*] 未能自动检测公网 IP，请手动输入。"
    read -rp "出口服务器公网 IP: " EXIT_PUBLIC_IP
  fi

  echo "👉 最终使用的出口公网 IP：$EXIT_PUBLIC_IP"
  echo

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.1/24}

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/32): " ENTRY_WG_IP
  ENTRY_WG_IP=${ENTRY_WG_IP:-10.0.0.2/32}

  DEFAULT_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
  read -rp "出口服务器对外网卡名(默认 ${DEFAULT_IF:-ens3}): " OUT_IF
  OUT_IF=${OUT_IF:-${DEFAULT_IF:-ens3}}

  mkdir -p /etc/wireguard
  cd /etc/wireguard

  if [ ! -f exit_private.key ]; then
    echo "[*] 生成出口服务器密钥..."
    umask 077
    wg genkey | tee exit_private.key | wg pubkey > exit_public.key
  fi

  EXIT_PRIVATE_KEY=$(cat exit_private.key)
  EXIT_PUBLIC_KEY=$(cat exit_public.key)

  echo
  echo "====== 出口服务器 公钥（发给入口服务器用）======"
  echo "${EXIT_PUBLIC_KEY}"
  echo "================================================"
  echo

  read -rp "请输入【入口服务器公钥】: " ENTRY_PUBLIC_KEY
  ENTRY_PUBLIC_KEY=${ENTRY_PUBLIC_KEY:-CHANGE_ME_ENTRY_PUBLIC_KEY}

  local UDP2RAW_PORT
  read -rp "外层隧道监听端口 (默认 ${UDP2RAW_DEFAULT_PORT}): " UDP2RAW_PORT
  UDP2RAW_PORT=${UDP2RAW_PORT:-$UDP2RAW_DEFAULT_PORT}
  if [[ "$UDP2RAW_PORT" == "89" ]]; then
    echo "❌ 端口 89 不允许，请重新运行。"
    return
  fi

  local DEFAULT_PSK
  if [[ -f "$UDP2RAW_PSK_FILE" ]]; then
    DEFAULT_PSK=$(cat "$UDP2RAW_PSK_FILE")
  else
    DEFAULT_PSK=$(head -c 16 /dev/urandom | base64)
  fi
  read -rp "链路预共享密钥 PSK (默认自动生成): " UDP2RAW_PSK
  UDP2RAW_PSK=${UDP2RAW_PSK:-$DEFAULT_PSK}

  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true

  iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "${OUT_IF}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "${OUT_IF}" -j MASQUERADE

  cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_ADDR}
ListenPort = 51820
PrivateKey = ${EXIT_PRIVATE_KEY}
MTU = ${WG_SAFE_MTU}

PostUp   = iptables -A FORWARD -i ${WG_IF} -j ACCEPT; iptables -A FORWARD -o ${WG_IF} -j ACCEPT; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i ${WG_IF} -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o ${WG_IF} -j ACCEPT 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${ENTRY_PUBLIC_KEY}
AllowedIPs = ${ENTRY_WG_IP}
EOF

  chmod 600 /etc/wireguard/${WG_IF}.conf

  systemctl enable wg-quick@${WG_IF}.service >/dev/null 2>&1 || true
  wg-quick down ${WG_IF} 2>/dev/null || true
  wg-quick up ${WG_IF}

  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} || true

  # 启动 FEC 与伪装双层链路
  setup_exit_services 51820 "$UDP2RAW_PORT" "$UDP2RAW_PSK"

  echo
  echo "====== 综合链路连接信息（给入口服务器用）======"
  echo "出口公网 IP：${EXIT_PUBLIC_IP}"
  echo "远端监听端口：${UDP2RAW_PORT}"
  echo "PSK：${UDP2RAW_PSK}"
  echo "=============================================="
  echo
  echo "出口服务器配置完成，当前状态："
  wg show || true
}

ensure_policy_routing_for_ports() {
  if ! ip link show "${WG_IF}" &>/dev/null; then
    return 0
  fi
  if ! ip rule show | grep -q "fwmark 0x1 lookup 100"; then
    ip rule add fwmark 0x1 lookup 100
  fi
  ip route replace default dev ${WG_IF} table 100
}

clear_mark_rules() {
  for chain in OUTPUT PREROUTING; do
    iptables -t mangle -S "$chain" 2>/dev/null | grep " MARK " \
      | sed 's/^-A /-D /' | while read -r line; do
          iptables -t mangle $line 2>/dev/null || true
        done
  done
}

apply_port_rules_from_file() {
  clear_mark_rules
  [[ ! -f "$PORT_LIST_FILE" ]] && return 0

  while read -r p; do
    [[ -z "$p" ]] && continue
    [[ "$p" =~ ^# ]] && continue

    iptables -t mangle -C OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || \
      iptables -t mangle -A OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || \
      iptables -t mangle -A OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1

    iptables -t mangle -C PREROUTING -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || \
      iptables -t mangle -A PREROUTING -p tcp --dport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C PREROUTING -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || \
      iptables -t mangle -A PREROUTING -p udp --dport "$p" -j MARK --set-mark 0x1
  done < "$PORT_LIST_FILE"
}

add_port_to_list() {
  local port="$1"
  mkdir -p "$(dirname "$PORT_LIST_FILE")"
  touch "$PORT_LIST_FILE"
  if grep -qx "$port" "$PORT_LIST_FILE"; then
    echo "端口 $port 已存在列表中。"
    return 0
  fi
  echo "$port" >> "$PORT_LIST_FILE"
  echo "已添加端口 $port 到分流列表。"
}

remove_port_from_list() {
  local port="$1"
  [[ ! -f "$PORT_LIST_FILE" ]] && return 0
  if ! grep -qx "$port" "$PORT_LIST_FILE"; then
    echo "端口 $port 不在列表中。"
    return 0
  fi
  sed -i "\|^$port$|d" "$PORT_LIST_FILE"
  echo "已从分流列表中删除端口 $port。"
}

remove_port_iptables_rules() {
  local port="$1"
  iptables -t mangle -D OUTPUT -p tcp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p udp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D PREROUTING -p tcp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D PREROUTING -p udp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
}

get_current_mode() {
  if [[ -f "$MODE_FILE" ]]; then
    mode=$(cat "$MODE_FILE" 2>/dev/null || echo "split")
  else
    mode="split"
  fi
  echo "$mode"
}

set_mode_flag() {
  local mode="$1"
  echo "$mode" > "$MODE_FILE"
}

enable_ip_forward_global() {
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
}

get_wan_if() {
  local wan
  wan=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
  echo "${wan:-eth0}"
}

add_forward_port_mapping() {
  local port="$1"
  local exit_ip wan_if

  [[ -z "$port" ]] && return 0

  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi
  if [[ -z "$exit_ip" ]]; then
    echo "⚠ 未找到出口 WG 内网 IP，跳过端口映射配置。"
    return 0
  fi

  enable_ip_forward_global
  wan_if=$(get_wan_if)

  ip route replace "${exit_ip}/32" dev "${WG_IF}"

  iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "${wan_if}" -p tcp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}"

  iptables -C FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

  iptables -C FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m state --state ESTABLISHED,RELATED -j ACCEPT

  iptables -t nat -C POSTROUTING -o "${WG_IF}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "${WG_IF}" -j MASQUERADE
}

remove_forward_port_mapping() {
  local port="$1"
  local exit_ip wan_if

  [[ -z "$port" ]] && return 0
  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi
  [[ -z "$exit_ip" ]] && return 0
  wan_if=$(get_wan_if)

  iptables -t nat -D PREROUTING -i "${wan_if}" -p tcp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
  iptables -D FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
}

enable_global_mode() {
  echo "[*] 切换为【全局模式】..."
  ensure_policy_routing_for_ports
  clear_mark_rules

  local UDP2RAW_REMOTE_PORT="$UDP2RAW_DEFAULT_PORT"
  if [[ -f "$UDP2RAW_REMOTE_FILE" ]]; then
    local remote_str
    remote_str=$(cat "$UDP2RAW_REMOTE_FILE" 2>/dev/null || true)
    if [[ "$remote_str" == *:* ]]; then
      UDP2RAW_REMOTE_PORT="${remote_str##*:}"
    fi
  fi

  local wan_if exit_ip=""
  wan_if=$(get_wan_if)
  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi

  enable_ip_forward_global

  if [[ -n "$exit_ip" ]]; then
    ip route replace "${exit_ip}/32" dev "${WG_IF}" 2>/dev/null || true
    iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || \
    iptables -t nat -A PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}"
    iptables -t nat -C PREROUTING -i "${wan_if}" -p udp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || \
    iptables -t nat -A PREROUTING -i "${wan_if}" -p udp ! --dport 22 -j DNAT --to-destination "${exit_ip}"
    iptables -C FORWARD -i "${wan_if}" -o "${WG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${wan_if}" -o "${WG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -C FORWARD -i "${WG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${WG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -C POSTROUTING -o "${WG_IF}" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -o "${WG_IF}" -j MASQUERADE
  fi

  iptables -t mangle -C OUTPUT -o lo -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -o lo -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --sport 22 -j RETURN
  iptables -t mangle -C OUTPUT -p udp --dport 53 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p udp --dport 53 -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --dport 53 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport 53 -j RETURN
  
  # 放行底层传输端口
  iptables -t mangle -C OUTPUT -p tcp --dport "${UDP2RAW_REMOTE_PORT}" -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --dport "${UDP2RAW_REMOTE_PORT}" -j RETURN
  iptables -t mangle -C OUTPUT -p udp --dport "${UDP2RAW_REMOTE_PORT}" -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p udp --dport "${UDP2RAW_REMOTE_PORT}" -j RETURN

  iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  iptables -t mangle -C OUTPUT -j MARK --set-mark 0x1 2>/dev/null || \
    iptables -t mangle -A OUTPUT -j MARK --set-mark 0x1
  iptables -t mangle -C PREROUTING -i "${wan_if}" -j MARK --set-mark 0x1 2>/dev/null || \
    iptables -t mangle -A PREROUTING -i "${wan_if}" -j MARK --set-mark 0x1

  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} 2>/dev/null || true
  set_mode_flag "global"
  echo "✅ 已切到【全局模式】"
}

enable_split_mode() {
  echo "[*] 切换为【端口分流模式】..."

  local exit_ip wan_if
  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi
  wan_if=$(get_wan_if)
  if [[ -n "$exit_ip" ]]; then
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
      [[ "$p" =~ ^# ]] && continue
      add_forward_port_mapping "$p"
    done < "$PORT_LIST_FILE"
  fi

  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} 2>/dev/null || true
  set_mode_flag "split"
  echo "✅ 已切回【端口分流模式】"
}

apply_current_mode() {
  local mode=$(get_current_mode)
  if [[ "$mode" == "global" ]]; then
    enable_global_mode
  else
    enable_split_mode
  fi
}

manage_entry_mode() {
  echo "==== 入口服务器 模式切换 ===="
  while true; do
    local mode=$(get_current_mode)
    echo "当前模式：$mode"
    echo "1) 切换为【全局模式】"
    echo "2) 切换为【端口分流模式】"
    echo "0) 返回"
    read -rp "请选择: " sub
    case "$sub" in
      1) enable_global_mode ;;
      2) enable_split_mode ;;
      0) break ;;
      *) echo "无效。" ;;
    esac
  done
}

configure_entry() {
  echo "==== 配置为【入口服务器】 ===="
  set_role "entry"

  install_wireguard
  install_udp2raw
  install_udpspeeder

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.2/24}

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/32): " EXIT_WG_IP
  EXIT_WG_IP=${EXIT_WG_IP:-10.0.0.1/32}

  mkdir -p /etc/wireguard
  EXIT_WG_IP_NO_MASK="${EXIT_WG_IP%%/*}"
  echo "$EXIT_WG_IP_NO_MASK" > "$EXIT_WG_IP_FILE"

  SAVED_EXIT_IP=""
  if [[ -f /etc/wireguard/.exit_public_ip ]]; then
    SAVED_EXIT_IP=$(cat /etc/wireguard/.exit_public_ip 2>/dev/null || true)
  fi

  if [[ -n "$SAVED_EXIT_IP" ]]; then
    read -rp "出口服务器公网 IP (默认 ${SAVED_EXIT_IP}): " EXIT_PUBLIC_IP
    EXIT_PUBLIC_IP=${EXIT_PUBLIC_IP:-$SAVED_EXIT_IP}
  else
    read -rp "出口服务器公网 IP: " EXIT_PUBLIC_IP
  fi

  echo "$EXIT_PUBLIC_IP" > /etc/wireguard/.exit_public_ip
  cd /etc/wireguard

  if [ ! -f entry_private.key ]; then
    echo "[*] 生成入口服务器密钥..."
    umask 077
    wg genkey | tee entry_private.key | wg pubkey > entry_public.key
  fi

  ENTRY_PRIVATE_KEY=$(cat entry_private.key)
  ENTRY_PUBLIC_KEY=$(cat entry_public.key)

  echo
  echo "====== 入口服务器 公钥（出口服务器用）======"
  echo "${ENTRY_PUBLIC_KEY}"
  echo "================================================"
  echo

  read -rp "出口服务器隧道监听端口 (默认 ${UDP2RAW_DEFAULT_PORT}): " UDP2RAW_REMOTE_PORT
  UDP2RAW_REMOTE_PORT=${UDP2RAW_REMOTE_PORT:-$UDP2RAW_DEFAULT_PORT}

  local DEFAULT_PSK
  if [[ -f "$UDP2RAW_PSK_FILE" ]]; then
    DEFAULT_PSK=$(cat "$UDP2RAW_PSK_FILE")
  else
    DEFAULT_PSK=$(head -c 16 /dev/urandom | base64)
  fi
  read -rp "请输入与出口服务器一致的 PSK: " UDP2RAW_PSK
  UDP2RAW_PSK=${UDP2RAW_PSK:-$DEFAULT_PSK}

  # 启动 FEC 与解伪装双层链路
  setup_entry_services "$EXIT_PUBLIC_IP" "$UDP2RAW_REMOTE_PORT" "$UDP2RAW_PSK"

  # WG 直接打给本地的 UDPspeeder 客户端
  local endpoint="127.0.0.1:39999"

  read -rp "请输入【出口服务器公钥】: " EXIT_PUBLIC_KEY
  EXIT_PUBLIC_KEY=${EXIT_PUBLIC_KEY:-CHANGE_ME_EXIT_PUBLIC_KEY}

  cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_ADDR}
PrivateKey = ${ENTRY_PRIVATE_KEY}
Table = off
MTU = ${WG_SAFE_MTU}

PostUp   = ip rule show | grep -q "fwmark 0x1 lookup 100" || ip rule add fwmark 0x1 lookup 100; ip route replace default dev ${WG_IF} table 100; iptables -t nat -C POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${WG_IF} -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip rule del fwmark 0x1 lookup 100 2>/dev/null || true; ip route flush table 100 2>/dev/null || true; iptables -t nat -D POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${EXIT_PUBLIC_KEY}
Endpoint = ${endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

  chmod 600 /etc/wireguard/${WG_IF}.conf

  systemctl enable wg-quick@${WG_IF}.service >/dev/null 2>&1 || true
  wg-quick down ${WG_IF} 2>/dev/null || true
  wg-quick up ${WG_IF}

  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} 2>/dev/null || true
  ensure_policy_routing_for_ports
  set_mode_flag "split"
  apply_current_mode

  echo "入口服务器配置完成，当前状态："
  wg show || true
}

manage_entry_ports() {
  ensure_policy_routing_for_ports
  while true; do
    echo "---- 端口分流管理 ----"
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

show_status() {
  echo "==== 状态查询 ===="
  echo "角色：$(get_role)"
  echo "==== WG ===="
  wg show || echo "wg0 未运行"
  echo "==== FEC 与混淆层 ===="
  systemctl status udpspeeder-exit.service 2>/dev/null | sed -n '1,5p'
  systemctl status udp2raw-exit.service 2>/dev/null | sed -n '1,5p'
  systemctl status udpspeeder-entry.service 2>/dev/null | sed -n '1,5p'
  systemctl status udp2raw-entry.service 2>/dev/null | sed -n '1,5p'
}

start_wg() {
  echo "[*] 启动链路..."
  wg-quick up ${WG_IF} || true
  apply_current_mode
}

stop_wg() {
  echo "[*] 停止链路..."
  wg-quick down ${WG_IF} 2>/dev/null || true
  ip route flush table 100 2>/dev/null || true
  clear_mark_rules
}

restart_wg() {
  stop_wg
  start_wg
}

uninstall_wg() {
  read -rp "确认彻底卸载并清理？(y/N): " confirm
  if [[ "$confirm" =~ ^[yY]$ ]]; then
    systemctl stop wg-quick@${WG_IF}.service 2>/dev/null || true
    systemctl disable wg-quick@${WG_IF}.service 2>/dev/null || true
    stop_wg

    if [[ -f "$PORT_LIST_FILE" ]]; then
      while read -r p; do
        [[ -z "$p" ]] && continue
        [[ "$p" =~ ^# ]] && continue
        remove_port_iptables_rules "$p"
        remove_forward_port_mapping "$p"
      done < "$PORT_LIST_FILE"
    fi

    systemctl stop udp2raw-exit.service udpspeeder-exit.service udp2raw-entry.service udpspeeder-entry.service 2>/dev/null || true
    systemctl disable udp2raw-exit.service udpspeeder-exit.service udp2raw-entry.service udpspeeder-entry.service 2>/dev/null || true
    rm -f /etc/systemd/system/udp2raw-*.service /etc/systemd/system/udpspeeder-*.service 2>/dev/null || true
    systemctl daemon-reload || true

    rm -rf "$UDP2RAW_WORKDIR" /etc/wireguard 2>/dev/null || true
    rm -f "$UDP2RAW_BIN" "$UDPSPEEDER_BIN" 2>/dev/null || true
    apt remove -y wireguard wireguard-tools 2>/dev/null || true
    apt autoremove -y 2>/dev/null || true

    echo "✅ 清理完毕，正在自毁脚本。"
    rm -f "$0" 2>/dev/null || true
    exit 0
  fi
}

update_udp2raw_entry_remote_ip() {
  local unit="/etc/systemd/system/udp2raw-entry.service"
  [[ -f "$unit" ]] || return 1
  read -rp "新出口公网 IP: " new_ip
  sed -i -E "s/( -r )[[:graph:]]+:[0-9]+/\1${new_ip}:$(cat $UDP2RAW_REMOTE_FILE | cut -d: -f2)/" "$unit"
  systemctl daemon-reload
  systemctl restart udp2raw-entry.service
  echo "✅ IP 已更新为 $new_ip"
}

while true; do
  echo
  echo "================ 📡 WG-Raw-FEC 高级链路 ================"
  echo "1) 配置为 出口服务器"
  echo "2) 配置为 入口服务器"
  echo "3) 查看链路状态"
  echo "4) 启动"
  echo "5) 停止"
  echo "6) 重启"
  echo "7) 卸载并清理"
  echo "8) 管理入口端口分流"
  echo "9) 管理入口模式（全局 / 分流）"
  echo "10) 修改出口 IP"
  echo "0) 退出"
  echo "========================================================"
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
    10) [[ "$(get_role)" == "entry" ]] && update_udp2raw_entry_remote_ip || echo "❌ 仅入口可用" ;;
    0) exit 0 ;;
    *) echo "无效。" ;;
  esac
done
