#!/usr/bin/env bash
set -e

WG_IF="wg0"
PORT_LIST_FILE="/etc/wireguard/.wg_ports"
MODE_FILE="/etc/wireguard/.wg_mode"
EXIT_WG_IP_FILE="/etc/wireguard/.exit_wg_ip"
ROLE_FILE="/etc/wireguard/.wg_role"

# 角色相关：entry / exit
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

# udp2raw 相关
UDP2RAW_BIN="/usr/local/bin/udp2raw"
UDP2RAW_WORKDIR="/etc/udp2raw"
UDP2RAW_PSK_FILE="${UDP2RAW_WORKDIR}/psk"
UDP2RAW_CLIENT_PORT_FILE="${UDP2RAW_WORKDIR}/client_port"
UDP2RAW_SERVER_PORT_FILE="${UDP2RAW_WORKDIR}/server_port"
UDP2RAW_REMOTE_FILE="${UDP2RAW_WORKDIR}/remote"

# 统一安全 MTU
WG_SAFE_MTU=1320

# 不常见的默认 udp2raw 端口
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
    echo "[*] 所有依赖已安装，跳过安装步骤。"
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
  echo "[*] 将从固定地址下载 udp2raw_binaries.tar.gz"

  tmpdir=$(mktemp -d)
  (
    cd "$tmpdir"
    echo "[*] 正在下载 udp2raw 压缩包..."
    curl -L "$url" -o udp2raw_binaries.tar.gz
    echo "[*] 解压..."
    tar -xzf udp2raw_binaries.tar.gz

    arch=$(uname -m)
    bin_name=""
    case "$arch" in
      x86_64|amd64) bin_name="udp2raw_amd64" ;;
      aarch64|arm64) bin_name="udp2raw_aarch64" ;;
      armv7l|armv6l) bin_name="udp2raw_arm" ;;
      *)
        echo "无法自动匹配架构 $arch"
        ls
        read -rp "请输入压缩包内适用的二进制文件名(如 udp2raw_amd64): " bin_name
        ;;
    esac

    if [[ ! -f "$bin_name" ]]; then
      echo "未找到可执行文件 $bin_name，请检查压缩包内容。"
      exit 1
    fi

    echo "[*] 安装 udp2raw 到 $UDP2RAW_BIN ..."
    install -m 0755 "$bin_name" "$UDP2RAW_BIN"
  )
  rm -rf "$tmpdir"

  echo "✅ udp2raw 已安装到 $UDP2RAW_BIN"
}

setup_udp2raw_server() {
  local wg_port="$1"
  local listen_port="$2"
  local psk="$3"

  mkdir -p "$UDP2RAW_WORKDIR"
  echo "$psk" > "$UDP2RAW_PSK_FILE"
  echo "$listen_port" > "$UDP2RAW_SERVER_PORT_FILE"

  cat >/etc/systemd/system/udp2raw-exit.service <<EOF
[Unit]
Description=udp2raw server for WireGuard
After=network-online.target wg-quick@${WG_IF}.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${UDP2RAW_BIN} -s -l 0.0.0.0:${listen_port} -r 127.0.0.1:${wg_port} -k "${psk}" --raw-mode faketcp --fix-gro
Restart=on-failure
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable udp2raw-exit.service >/dev/null 2>&1 || true
  systemctl restart udp2raw-exit.service || true

  # faketcp 防 RST
  iptables -I INPUT -p tcp --dport "${listen_port}" -j DROP 2>/dev/null || true

  echo "✅ udp2raw 出口服务已配置并尝试启动 (udp2raw-exit.service)"
}

setup_udp2raw_client() {
  local remote_ip="$1"
  local remote_port="$2"
  local local_port="$3"
  local psk="$4"

  mkdir -p "$UDP2RAW_WORKDIR"
  echo "$psk" > "$UDP2RAW_PSK_FILE"
  echo "$local_port" > "$UDP2RAW_CLIENT_PORT_FILE"
  echo "${remote_ip}:${remote_port}" > "$UDP2RAW_REMOTE_FILE"

  cat >/etc/systemd/system/udp2raw-entry.service <<EOF
[Unit]
Description=udp2raw client for WireGuard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${UDP2RAW_BIN} -c -l 127.0.0.1:${local_port} -r ${remote_ip}:${remote_port} -k "${psk}" --raw-mode faketcp --fix-gro
Restart=on-failure
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable udp2raw-entry.service >/dev/null 2>&1 || true
  systemctl restart udp2raw-entry.service || true

  echo "✅ udp2raw 入口客户端已配置并尝试启动 (udp2raw-entry.service)"
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

# ====================== 出口服务器配置 ======================
configure_exit() {
  echo "==== 配置为【出口服务器】 ===="
  set_role "exit"

  install_wireguard
  install_udp2raw

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

  # 选择 udp2raw 监听端口，禁止 89
  local UDP2RAW_PORT
  read -rp "udp2raw 出口服务端监听端口 (默认 ${UDP2RAW_DEFAULT_PORT}): " UDP2RAW_PORT
  UDP2RAW_PORT=${UDP2RAW_PORT:-$UDP2RAW_DEFAULT_PORT}
  if [[ "$UDP2RAW_PORT" == "89" ]]; then
    echo "❌ 端口 89 不允许作为出口 udp2raw 端口，请重新运行脚本并选择其他端口。"
    return
  fi
  if ! [[ "$UDP2RAW_PORT" =~ ^[0-9]+$ ]] || [ "$UDP2RAW_PORT" -lt 1 ] || [ "$UDP2RAW_PORT" -gt 65535 ]; then
    echo "❌ udp2raw 端口不合法，退出。"
    return
  fi

  # PSK
  local DEFAULT_PSK
  if [[ -f "$UDP2RAW_PSK_FILE" ]]; then
    DEFAULT_PSK=$(cat "$UDP2RAW_PSK_FILE")
  else
    DEFAULT_PSK=$(head -c 16 /dev/urandom | base64)
  fi
  read -rp "udp2raw 预共享密钥 PSK (默认自动生成): " UDP2RAW_PSK
  UDP2RAW_PSK=${UDP2RAW_PSK:-$DEFAULT_PSK}

  # 开启 IPv4 转发 + NAT
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

  # 再安全兜底设一遍 MTU（防旧配置残留）
  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} || true

  setup_udp2raw_server 51820 "$UDP2RAW_PORT" "$UDP2RAW_PSK"

  echo
  echo "====== udp2raw 连接信息（给入口服务器用）======"
  echo "出口公网 IP：${EXIT_PUBLIC_IP}"
  echo "udp2raw 监听端口：${UDP2RAW_PORT}"
  echo "PSK：${UDP2RAW_PSK}"
  echo "raw-mode：faketcp"
  echo "=============================================="
  echo

  echo
  echo "出口服务器配置完成，当前状态："
  wg show || true
}

# ====================== 入口通用函数 ======================

ensure_policy_routing_for_ports() {
  if ! ip link show "${WG_IF}" &>/dev/null; then
    return 0
  fi
  if ! ip rule show | grep -q "fwmark 0x1 lookup 100"; then
    ip rule add fwmark 0x1 lookup 100
  fi
  ip route replace default dev ${WG_IF} table 100
}

# 清理 mangle 表里所有打 MARK 的规则（OUTPUT + PREROUTING）
clear_mark_rules() {
  for chain in OUTPUT PREROUTING; do
    iptables -t mangle -S "$chain" 2>/dev/null | grep " MARK " \
      | sed 's/^-A /-D /' | while read -r line; do
          iptables -t mangle $line 2>/dev/null || true
        done
  done
}

# 端口分流规则（按目标端口 dport）
apply_port_rules_from_file() {
  clear_mark_rules
  [[ ! -f "$PORT_LIST_FILE" ]] && return 0

  while read -r p; do
    [[ -z "$p" ]] && continue
    [[ "$p" =~ ^# ]] && continue

    # 本机出站：按目标端口分流
    iptables -t mangle -C OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || \
      iptables -t mangle -A OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || \
      iptables -t mangle -A OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1

    # 转发流量：同样按目标端口分流（给内网设备用）
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

  # 本机出站
  iptables -t mangle -D OUTPUT -p tcp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p udp --dport "$port" -j MARK --set-mark 0x1 2>/dev/null || true

  # 转发流量
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

# === 一些公共小工具 ===

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

# A:port → B:port 端口转发（走 wg0）
add_forward_port_mapping() {
  local port="$1"
  local exit_ip
  local wan_if

  [[ -z "$port" ]] && return 0

  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi
  if [[ -z "$exit_ip" ]]; then
    echo "⚠ 未找到出口 WG 内网 IP (${EXIT_WG_IP_FILE})，跳过 A:${port} → B:${port} 的转发配置。"
    return 0
  fi

  enable_ip_forward_global
  wan_if=$(get_wan_if)

  # 关键：主路由表里给出口 wg IP 加一条直连走 wg0
  # 发往 exit_ip 的流量一定从 wg0 出去
  ip route replace "${exit_ip}/32" dev "${WG_IF}"

  # A:port → DNAT 到 B_wg_ip:port（不再打 mark，避免和其它策略路由冲突）
  iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp --dport "${port}" \
    -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "${wan_if}" -p tcp --dport "${port}" \
    -j DNAT --to-destination "${exit_ip}:${port}"

  # FORWARD：外网 -> wg0
  iptables -C FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" \
    -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" \
    -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

  # FORWARD：wg0 -> 外网
  iptables -C FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" \
    -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" \
    -m state --state ESTABLISHED,RELATED -j ACCEPT

  # 出 wg0 时 SNAT/MASQUERADE（兜底）
  iptables -t nat -C POSTROUTING -o "${WG_IF}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "${WG_IF}" -j MASQUERADE

  echo "✅ 已开启 A:${port} → B(${exit_ip}):${port} 的转发（经 ${WG_IF}）"
}

remove_forward_port_mapping() {
  local port="$1"
  local exit_ip
  local wan_if

  [[ -z "$port" ]] && return 0

  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi
  [[ -z "$exit_ip" ]] && return 0
  wan_if=$(get_wan_if)

  iptables -t nat -D PREROUTING -i "${wan_if}" -p tcp --dport "${port}" \
    -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
  iptables -D FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp --dport "${port}" \
    -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp --sport "${port}" \
    -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

  echo "✅ 已尝试移除 A:${port} → B(${exit_ip}):${port} 的转发规则。"
}

# === 全局模式下原来的“全端口 1:1 转发 A→B”（排除 22）
# 现在保留函数，但默认不再调用，避免抢占所有端口导致其它转发失效 ===

enable_full_port_forward_to_exit_all() {
  local exit_ip
  local wan_if

  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi
  if [[ -z "$exit_ip" ]]; then
    echo "⚠ 未找到出口 WG 内网 IP (${EXIT_WG_IP_FILE})，跳过全端口 1:1 转发配置。"
    return 0
  fi

  enable_ip_forward_global
  wan_if=$(get_wan_if)

  echo "[*] 开启【全端口 1:1 转发】：A 公网 IP:任意 TCP 端口 → B(${exit_ip}):同端口（经 ${WG_IF}）"
  echo "    外网网卡: ${wan_if}"

  # 保护 22 端口：对 dport=22 直接 RETURN，不做 DNAT
  iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp --dport 22 -j RETURN 2>/dev/null || \
    iptables -t nat -I PREROUTING -i "${wan_if}" -p tcp --dport 22 -j RETURN

  # 其它 TCP 端口（非 22）全部 DNAT 到 B（端口保持不变）
  iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || \
    iptables -t nat -A PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}"

  # FORWARD：外网 -> wg0 放行
  iptables -C FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

  # FORWARD：wg0 -> 外网 放行回程
  iptables -C FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

  # 出 wg0 做 SNAT/MASQUERADE
  iptables -t nat -C POSTROUTING -o "${WG_IF}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "${WG_IF}" -j MASQUERADE

  echo "✅ 已开启【全端口 1:1 转发】(排除 22)：O → A:任意 TCP 端口 ≈ O → B(${exit_ip}):同端口"
}

disable_full_port_forward_to_exit_all() {
  local exit_ip
  local wan_if

  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi
  [[ -z "$exit_ip" ]] && return 0

  wan_if=$(get_wan_if)

  # 删掉保护 22 的 RETURN
  iptables -t nat -D PREROUTING -i "${wan_if}" -p tcp --dport 22 -j RETURN 2>/dev/null || true

  # 删掉「其它端口全部 DNAT 到 B」这条
  iptables -t nat -D PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || true

  # 删掉 FORWARD 放行
  iptables -D FORWARD -i "${wan_if}" -o "${WG_IF}" -p tcp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${WG_IF}" -o "${wan_if}" -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

  echo "✅ 已关闭【全端口 1:1 转发 A→B】规则。"
}

enable_global_mode() {
  echo "[*] 切换为【全局模式】..."
  ensure_policy_routing_for_ports
  clear_mark_rules

  # 读取 udp2raw 远端端口（客户端向这个端口发包）
  local UDP2RAW_REMOTE_PORT="$UDP2RAW_DEFAULT_PORT"
  if [[ -f "$UDP2RAW_REMOTE_FILE" ]]; then
    local remote_str
    remote_str=$(cat "$UDP2RAW_REMOTE_FILE" 2>/dev/null || true)
    if [[ "$remote_str" == *:* ]]; then
      UDP2RAW_REMOTE_PORT="${remote_str##*:}"
    fi
  fi

  # 不处理 lo
  iptables -t mangle -C OUTPUT -o lo -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -o lo -j RETURN

  # 保护 SSH（本机发出的源端口 22）
  iptables -t mangle -C OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --sport 22 -j RETURN

  # 保护 WireGuard 本身
  iptables -t mangle -C OUTPUT -p udp --sport 51820 -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p udp --sport 51820 -j RETURN
  iptables -t mangle -C OUTPUT -p udp --dport 51820 -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p udp --dport 51820 -j RETURN

  # 保护 DNS
  iptables -t mangle -C OUTPUT -p udp --dport 53 -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p udp --dport 53 -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --dport 53 -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --dport 53 -j RETURN

  # 保护 udp2raw 通道（发往出口 udp2raw 的流量）
  iptables -t mangle -C OUTPUT -p tcp --dport "${UDP2RAW_REMOTE_PORT}" -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --dport "${UDP2RAW_REMOTE_PORT}" -j RETURN
  iptables -t mangle -C OUTPUT -p udp --dport "${UDP2RAW_REMOTE_PORT}" -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p udp --dport "${UDP2RAW_REMOTE_PORT}" -j RETURN

  # 再加 TCPMSS（入口自己发出的 TCP）
  iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

  # 其余所有出站流量全部打 mark=0x1 → table100 → wg0
  iptables -t mangle -C OUTPUT -j MARK --set-mark 0x1 2>/dev/null || \
    iptables -t mangle -A OUTPUT -j MARK --set-mark 0x1

  # 兜底再设一遍 wg0 MTU
  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} 2>/dev/null || true

  # ⚠ 不再默认开启全端口 1:1 转发，避免影响其他端口转发
  # enable_full_port_forward_to_exit_all

  set_mode_flag "global"
  echo "✅ 已切到【全局模式】，本机出站全走出口（不会抢占所有外部端口 DNAT）。"
}

enable_split_mode() {
  echo "[*] 切换为【端口分流模式】..."

  # 退回分流时，先关掉全局模式下的全端口 1:1 转发（即便没开也无所谓）
  disable_full_port_forward_to_exit_all

  ensure_policy_routing_for_ports
  clear_mark_rules
  apply_port_rules_from_file

  # 分流模式下同样兜底 wg0 MTU
  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} 2>/dev/null || true

  set_mode_flag "split"
  echo "✅ 已切回【端口分流模式】，只有端口列表中目标端口才走出口。"
}

apply_current_mode() {
  local mode
  mode=$(get_current_mode)
  if [[ "$mode" == "global" ]]; then
    enable_global_mode
  else
    enable_split_mode
  fi
}

manage_entry_mode() {
  echo "==== 入口服务器 模式切换 ===="
  while true; do
    local mode
    mode=$(get_current_mode)
    echo
    echo "当前模式：$mode"
    echo "1) 切换为【全局模式】"
    echo "2) 切换为【端口分流模式】"
    echo "3) 仅查看当前模式"
    echo "0) 返回主菜单"
    read -rp "请选择: " sub
    case "$sub" in
      1) enable_global_mode ;;
      2) enable_split_mode ;;
      3) ;;
      0) break ;;
      *) echo "无效选项。" ;;
    esac
  done
}

# ====================== 入口配置 ======================

configure_entry() {
  echo "==== 配置为【入口服务器】 ===="
  set_role "entry"

  install_wireguard
  install_udp2raw

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.2/24}

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/32): " EXIT_WG_IP
  EXIT_WG_IP=${EXIT_WG_IP:-10.0.0.1/32}

  mkdir -p /etc/wireguard

  # 记录出口的 WG 内网 IP（不带掩码，用于端口 1:1 转发）
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

  if [ -z "$EXIT_PUBLIC_IP" ]; then
    echo "出口服务器公网 IP 不能为空"
    exit 1
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

  read -rp "出口服务器 udp2raw 监听端口 (默认 ${UDP2RAW_DEFAULT_PORT}): " UDP2RAW_REMOTE_PORT
  UDP2RAW_REMOTE_PORT=${UDP2RAW_REMOTE_PORT:-$UDP2RAW_DEFAULT_PORT}

  read -rp "本机 udp2raw 本地监听端口 (默认 ${UDP2RAW_DEFAULT_PORT}): " UDP2RAW_LOCAL_PORT
  UDP2RAW_LOCAL_PORT=${UDP2RAW_LOCAL_PORT:-$UDP2RAW_DEFAULT_PORT}

  local DEFAULT_PSK
  if [[ -f "$UDP2RAW_PSK_FILE" ]]; then
    DEFAULT_PSK=$(cat "$UDP2RAW_PSK_FILE")
  else
    DEFAULT_PSK=$(head -c 16 /dev/urandom | base64)
  fi
  read -rp "请输入与出口服务器一致的 udp2raw PSK: " UDP2RAW_PSK
  UDP2RAW_PSK=${UDP2RAW_PSK:-$DEFAULT_PSK}

  setup_udp2raw_client "$EXIT_PUBLIC_IP" "$UDP2RAW_REMOTE_PORT" "$UDP2RAW_LOCAL_PORT" "$UDP2RAW_PSK"

  local endpoint="127.0.0.1:${UDP2RAW_LOCAL_PORT}"

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

  # 兜底设置 MTU
  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} 2>/dev/null || true

  ensure_policy_routing_for_ports
  set_mode_flag "split"
  apply_current_mode

  echo
  echo "入口服务器配置完成，当前状态："
  wg show || true

  echo
  echo "✅ 之后如果要切换："
  echo "  - 菜单 8 管理端口分流"
  echo "  - 菜单 9 切换【全局模式】 / 【端口分流模式】"
}

manage_entry_ports() {
  echo "==== 入口服务器 端口分流管理 ===="
  echo "说明："
  echo "  - 管的是【入口这台机器】本地和转发流量的目标端口分流规则；"
  echo "  - 目标端口在列表中的所有 TCP/UDP 流量 → mark=0x1 → table100 → wg0 → 出口；"
  echo "  - 同时：从外部打到入口 A:该端口的 TCP，会转发到出口 B 的 WG 内网 IP:同端口；"
  echo "  - 其它端口流量 → 走入口自己的公网或你已有的转发规则。"
  echo

  ensure_policy_routing_for_ports

  while true; do
    echo
    echo "---- 端口管理菜单 ----"
    echo "1) 查看当前分流端口列表"
    echo "2) 添加端口到分流"
    echo "3) 删除分流列表端口"
    echo "0) 返回主菜单"
    echo "----------------------"
    read -rp "请选择: " sub

    case "$sub" in
      1)
        echo "当前端口列表（$PORT_LIST_FILE）："
        if [[ -f "$PORT_LIST_FILE" ]] && [[ -s "$PORT_LIST_FILE" ]]; then
          cat "$PORT_LIST_FILE"
        else
          echo "(空)"
        fi
        ;;
      2)
        read -rp "请输入要添加的端口(单个数字，如 8080): " new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
          if [ "$new_port" -eq 22 ]; then
            echo "出于安全考虑，禁止将 22 加入分流/映射列表。"
          else
            add_port_to_list "$new_port"
            ensure_policy_routing_for_ports
            apply_port_rules_from_file
            add_forward_port_mapping "$new_port"
          fi
        else
          echo "端口不合法。"
        fi
        ;;
      3)
        read -rp "请输入要删除的端口: " del_port
        if [[ "$del_port" =~ ^[0-9]+$ ]]; then
          remove_port_from_list "$del_port"
          remove_port_iptables_rules("$del_port")
          remove_forward_port_mapping "$del_port"
        else
          echo "端口不合法。"
        fi
        ;;
      0)
        break
        ;;
      *)
        echo "无效选项。" ;;
    esac
  done
}

show_status() {
  echo "==== 当前角色 ===="
  echo "角色：$(get_role) (entry=入口 / exit=出口 / unknown=未配置)"
  echo
  echo "==== WireGuard 状态 ===="
  if command -v wg >/dev/null 2>&1; then
    wg show || echo "wg0 似乎还没配置/启动。"
  else
    echo "系统未安装 WireGuard。"
  fi

  echo
  echo "==== udp2raw 服务状态 ===="
  systemctl status udp2raw-exit.service 2>/dev/null | sed -n '1,5p' || echo "udp2raw-exit.service 不存在或未运行。"
  echo
  systemctl status udp2raw-entry.service 2>/dev/null | sed -n '1,5p' || echo "udp2raw-entry.service 不存在或未运行。"
}

start_wg() {
  echo "[*] 启动 WG-Raw (${WG_IF})..."
  wg-quick up ${WG_IF} || true
  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} 2>/dev/null || true
  ensure_policy_routing_for_ports
  apply_current_mode
  wg show || true
}

stop_wg() {
  echo "[*] 停止 WG-Raw (${WG_IF})..."
  wg-quick down ${WG_IF} || true
  wg show || true
}

restart_wg() {
  echo "[*] 重启 WG-Raw (${WG_IF})..."
  wg-quick down ${WG_IF} 2>/dev/null || true
  wg-quick up ${WG_IF} || true
  ip link set dev ${WG_IF} mtu ${WG_SAFE_MTU} 2>/dev/null || true
  ensure_policy_routing_for_ports
  apply_current_mode
  wg show || true
}

uninstall_wg() {
  echo "==== 卸载 WG-Raw ===="
  echo "此操作将会："
  echo "  - 停止 wg-quick@${WG_IF} 服务并取消开机自启"
  echo "  - 删除 /etc/wireguard 内的配置、密钥、端口分流配置、模式配置、角色标记"
  echo "  - 移除策略路由 / iptables 标记"
  echo "  - 停用并删除 udp2raw systemd 服务和配置"
  echo "  - 删除 udp2raw 二进制"
  echo "  - 删除当前脚本文件：$0"
  echo
  read -rp "确认卸载并删除脚本？(y/N): " confirm
  case "$confirm" in
    y|Y)
      systemctl stop wg-quick@${WG_IF}.service 2>/dev/null || true
      systemctl disable wg-quick@${WG_IF}.service 2>/dev/null || true
      wg-quick down ${WG_IF} 2>/dev/null || true

      ip rule del fwmark 0x1 lookup 100 2>/dev/null || true
      ip route flush table 100 2>/dev/null || true

      clear_mark_rules

      systemctl stop udp2raw-exit.service 2>/dev/null || true
      systemctl disable udp2raw-exit.service 2>/dev/null || true
      systemctl stop udp2raw-entry.service 2>/dev/null || true
      systemctl disable udp2raw-entry.service 2>/dev/null || true
      rm -f /etc/systemd/system/udp2raw-exit.service /etc/systemd/system/udp2raw-entry.service 2>/dev/null || true
      systemctl daemon-reload || true

      rm -f /etc/wireguard/${WG_IF}.conf \
            /etc/wireguard/exit_private.key /etc/wireguard/exit_public.key \
            /etc/wireguard/entry_private.key /etc/wireguard/entry_public.key \
            /etc/wireguard/.exit_public_ip \
            "$PORT_LIST_FILE" "$MODE_FILE" "$EXIT_WG_IP_FILE" "$ROLE_FILE" 2>/dev/null || true
      rmdir /etc/wireguard 2>/dev/null || true

      rm -rf "$UDP2RAW_WORKDIR" 2>/dev/null || true
      rm -f "$UDP2RAW_BIN" 2>/dev/null || true

      export DEBIAN_FRONTEND=noninteractive
      apt remove -y wireguard wireguard-tools 2>/dev/null || true
      apt autoremove -y 2>/dev/null || true

      echo "✅ WireGuard 与 udp2raw 已卸载，配置和端口分流规则已清理。"
      echo "✅ 正在删除当前脚本：$0"
      rm -f "$0" 2>/dev/null || true
      echo "✅ 脚本已删除，退出。"
      exit 0
      ;;
    *)
      echo "已取消卸载。"
      ;;
  esac
}

while true; do
  echo
  echo "================ 📡 WG-Raw 一键脚本测试 ================"
  echo "1) 配置为 出口服务器"
  echo "2) 配置为 入口服务器"
  echo "3) 查看 WG-Raw 状态"
  echo "4) 启动 WG-Raw"
  echo "5) 停止 WG-Raw"
  echo "6) 重启 WG-Raw"
  echo "7) 卸载 WG-Raw"
  echo "8) 管理入口端口分流"
  echo "9) 管理入口模式（全局 / 分流）"
  echo "0) 退出"
  echo "=================================================================="
  read -rp "请选择: " choice

  case "$choice" in
    1) configure_exit ;;
    2) configure_entry ;;
    3) show_status ;;
    4) start_wg ;;
    5) stop_wg ;;
    6) restart_wg ;;
    7) uninstall_wg ;;
    8)
      if [[ "$(get_role)" != "entry" ]]; then
        echo "❌ 当前标记为【出口】或未配置为入口，本菜单仅在【入口服务器】上使用。"
      else
        manage_entry_ports
      fi
      ;;
    9)
      if [[ "$(get_role)" != "entry" ]]; then
        echo "❌ 当前标记为【出口】或未配置为入口，本菜单仅在【入口服务器】上使用。"
      else
        manage_entry_mode
      fi
      ;;
    0) exit 0 ;;
    *) echo "无效选项。" ;;
  esac
done
