#!/usr/bin/env bash
set -e

AWG_IF="awg0"
AWG_DIR="/etc/amnezia/amneziawg"
PORT_LIST_FILE="${AWG_DIR}/.awg_ports"
MODE_FILE="${AWG_DIR}/.awg_mode"
EXIT_WG_IP_FILE="${AWG_DIR}/.exit_awg_ip"
ROLE_FILE="${AWG_DIR}/.awg_role"

AWG_SAFE_MTU=1320
AWG_DEFAULT_PORT=51820

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

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行这个脚本： sudo bash awg.sh"
  exit 1
fi

install_amneziawg() {
  echo "[*] 检查 AmneziaWG 及相关依赖..."
  if command -v awg-quick &>/dev/null && command -v awg &>/dev/null; then
    echo "[*] AmneziaWG 已存在，跳过安装。"
    return
  fi

  echo "[*] 启动环境防御机制：执行焦土清理..."
  rm -f /etc/apt/sources.list.d/*amnezia*.list 2>/dev/null || true

  export DEBIAN_FRONTEND=noninteractive
  apt update

  echo "[*] 正在安装底层 C 语言核心编译链..."
  apt install -y build-essential git curl iproute2 iptables jq libmnl-dev linux-headers-$(uname -r)

  echo "[*] 正在执行云主机阉割环境补丁：强制重装编译器底层组件..."
  apt install --reinstall -y gcc g++ libc6-dev build-essential 2>/dev/null || true

  local WORKDIR="/usr/local/src/awg_build"

  echo "[*] 正在清理构建目录的脏数据..."
  rm -rf "$WORKDIR"
  mkdir -p "$WORKDIR"

  echo "[*] 正在编译 amneziawg.ko 内核模块..."
  cd "$WORKDIR"
  git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git
  cd amneziawg-linux-kernel-module/src
  make module
  make install
  modprobe amneziawg || true

  echo "[*] 正在编译 awg 工具链..."
  cd "$WORKDIR"
  git clone https://github.com/amnezia-vpn/amneziawg-tools.git
  cd amneziawg-tools/src
  make
  make install

  command -v awg >/dev/null 2>&1 || { echo "❌ awg 安装失败"; exit 1; }
  command -v awg-quick >/dev/null 2>&1 || { echo "❌ awg-quick 安装失败"; exit 1; }

  echo "✅ AmneziaWG 编译并安装完成"
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

generate_awg_params() {
  JC=$((RANDOM % 10 + 3))
  JMIN=$((RANDOM % 30 + 20))
  JMAX=$((JMIN + RANDOM % 40 + 10))
  S1=$((RANDOM % 100 + 30))
  S2=$((RANDOM % 100 + 30))
  H1=$((RANDOM % 2000000000 + 1000000000))
  H2=$((RANDOM % 2000000000 + 1000000000))
  H3=$((RANDOM % 2000000000 + 1000000000))
  H4=$((RANDOM % 2000000000 + 1000000000))
}

configure_exit() {
  echo "==== 配置为【出口服务器】 ===="
  set_role "exit"
  install_amneziawg

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

  read -rp "出口服务器 AWG 内网 IP (默认 10.0.0.1/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.1/24}

  read -rp "入口服务器 AWG 内网 IP (默认 10.0.0.2/32): " ENTRY_WG_IP
  ENTRY_WG_IP=${ENTRY_WG_IP:-10.0.0.2/32}

  DEFAULT_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
  read -rp "出口服务器对外网卡名(默认 ${DEFAULT_IF:-ens3}): " OUT_IF
  OUT_IF=${OUT_IF:-${DEFAULT_IF:-ens3}}

  read -rp "隧道监听端口 (默认 ${AWG_DEFAULT_PORT}): " LISTEN_PORT
  LISTEN_PORT=${LISTEN_PORT:-$AWG_DEFAULT_PORT}

  mkdir -p "${AWG_DIR}"
  cd "${AWG_DIR}"

  if [ ! -f exit_private.key ]; then
    echo "[*] 生成出口服务器密钥..."
    umask 077
    awg genkey | tee exit_private.key | awg pubkey > exit_public.key
  fi
  EXIT_PRIVATE_KEY=$(cat exit_private.key)
  EXIT_PUBLIC_KEY=$(cat exit_public.key)

  read -rp "请输入【入口服务器公钥】: " ENTRY_PUBLIC_KEY
  ENTRY_PUBLIC_KEY=${ENTRY_PUBLIC_KEY:-CHANGE_ME_ENTRY_PUBLIC_KEY}

  generate_awg_params
  LINK_TOKEN=$(echo -n "${EXIT_PUBLIC_IP}|${LISTEN_PORT}|${EXIT_PUBLIC_KEY}|${JC}|${JMIN}|${JMAX}|${S1}|${S2}|${H1}|${H2}|${H3}|${H4}" | base64 -w 0)

  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true

  iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "${OUT_IF}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "${OUT_IF}" -j MASQUERADE

  cat > "${AWG_DIR}/${AWG_IF}.conf" <<EOF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${LISTEN_PORT}
PrivateKey = ${EXIT_PRIVATE_KEY}
MTU = ${AWG_SAFE_MTU}

# AmneziaWG 混淆参数
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}

PostUp   = iptables -A FORWARD -i ${AWG_IF} -j ACCEPT; iptables -A FORWARD -o ${AWG_IF} -j ACCEPT; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i ${AWG_IF} -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o ${AWG_IF} -j ACCEPT 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${ENTRY_PUBLIC_KEY}
AllowedIPs = ${ENTRY_WG_IP}
EOF

  chmod 600 "${AWG_DIR}/${AWG_IF}.conf"
  systemctl enable awg-quick@${AWG_IF}.service >/dev/null 2>&1 || true
  awg-quick down ${AWG_IF} 2>/dev/null || true
  awg-quick up ${AWG_IF}

  echo
  echo "====== 综合链路连接信息（给入口服务器用）======"
  echo "${LINK_TOKEN}"
  echo "=============================================="
  echo
  echo "出口服务器配置完成，当前状态："
  awg show || true
}

ensure_policy_routing_for_ports() {
  if ! ip link show "${AWG_IF}" &>/dev/null; then
    return 0
  fi
  if ! ip rule show | grep -q "fwmark 0x1 lookup 100"; then
    ip rule add fwmark 0x1 lookup 100
  fi
  ip route replace default dev ${AWG_IF} table 100
}

clear_mark_rules() {
  local wan_if awg_remote_port
  wan_if=$(get_wan_if)

  iptables -t mangle -D OUTPUT -o lo -j RETURN 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p udp --dport 53 -j RETURN 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p tcp --dport 53 -j RETURN 2>/dev/null || true

  awg_remote_port=$(grep "Endpoint" "${AWG_DIR}/${AWG_IF}.conf" 2>/dev/null | awk -F':' '{print $NF}' | tail -n1)
  awg_remote_port=${awg_remote_port:-$AWG_DEFAULT_PORT}
  iptables -t mangle -D OUTPUT -p udp --dport "${awg_remote_port}" -j RETURN 2>/dev/null || true

  iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  iptables -t mangle -D OUTPUT -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D PREROUTING -i "${wan_if}" -j MARK --set-mark 0x1 2>/dev/null || true

  if [[ -f "$PORT_LIST_FILE" ]]; then
    while read -r p; do
      [[ -z "$p" ]] && continue
      [[ "$p" =~ ^# ]] && continue

      iptables -t mangle -D OUTPUT -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || true
      iptables -t mangle -D OUTPUT -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || true
      iptables -t mangle -D PREROUTING -p tcp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || true
      iptables -t mangle -D PREROUTING -p udp --dport "$p" -j MARK --set-mark 0x1 2>/dev/null || true
    done < "$PORT_LIST_FILE"
  fi
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

  ip route replace "${exit_ip}/32" dev "${AWG_IF}"

  iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || \
    iptables -t nat -A PREROUTING -i "${wan_if}" -p tcp --dport "${port}" -j DNAT --to-destination "${exit_ip}:${port}"

  iptables -C FORWARD -i "${wan_if}" -o "${AWG_IF}" -p tcp --dport "${port}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${wan_if}" -o "${AWG_IF}" -p tcp --dport "${port}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

  iptables -C FORWARD -i "${AWG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${AWG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m state --state ESTABLISHED,RELATED -j ACCEPT

  iptables -t nat -C POSTROUTING -o "${AWG_IF}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "${AWG_IF}" -j MASQUERADE
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
  iptables -D FORWARD -i "${wan_if}" -o "${AWG_IF}" -p tcp --dport "${port}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${AWG_IF}" -o "${wan_if}" -p tcp --sport "${port}" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
}

enable_global_mode() {
  echo "[*] 切换为【全局模式】..."
  ensure_policy_routing_for_ports
  clear_mark_rules

  local wan_if exit_ip=""
  wan_if=$(get_wan_if)
  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    exit_ip=$(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)
  fi

  local AWG_REMOTE_PORT
  AWG_REMOTE_PORT=$(grep "Endpoint" "${AWG_DIR}/${AWG_IF}.conf" 2>/dev/null | awk -F':' '{print $NF}' | tail -n1)
  AWG_REMOTE_PORT=${AWG_REMOTE_PORT:-$AWG_DEFAULT_PORT}

  enable_ip_forward_global

  if [[ -n "$exit_ip" ]]; then
    ip route replace "${exit_ip}/32" dev "${AWG_IF}" 2>/dev/null || true
    iptables -t nat -C PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || \
      iptables -t nat -A PREROUTING -i "${wan_if}" -p tcp ! --dport 22 -j DNAT --to-destination "${exit_ip}"
    iptables -t nat -C PREROUTING -i "${wan_if}" -p udp ! --dport 22 -j DNAT --to-destination "${exit_ip}" 2>/dev/null || \
      iptables -t nat -A PREROUTING -i "${wan_if}" -p udp ! --dport 22 -j DNAT --to-destination "${exit_ip}"
    iptables -C FORWARD -i "${wan_if}" -o "${AWG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
      iptables -A FORWARD -i "${wan_if}" -o "${AWG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -C FORWARD -i "${AWG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
      iptables -A FORWARD -i "${AWG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -C POSTROUTING -o "${AWG_IF}" -j MASQUERADE 2>/dev/null || \
      iptables -t nat -A POSTROUTING -o "${AWG_IF}" -j MASQUERADE
  fi

  iptables -t mangle -C OUTPUT -o lo -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -o lo -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --sport 22 -j RETURN
  iptables -t mangle -C OUTPUT -p udp --dport 53 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p udp --dport 53 -j RETURN
  iptables -t mangle -C OUTPUT -p tcp --dport 53 -j RETURN 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --dport 53 -j RETURN
  iptables -t mangle -C OUTPUT -p udp --dport "${AWG_REMOTE_PORT}" -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p udp --dport "${AWG_REMOTE_PORT}" -j RETURN

  iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  iptables -t mangle -C OUTPUT -j MARK --set-mark 0x1 2>/dev/null || \
    iptables -t mangle -A OUTPUT -j MARK --set-mark 0x1
  iptables -t mangle -C PREROUTING -i "${wan_if}" -j MARK --set-mark 0x1 2>/dev/null || \
    iptables -t mangle -A PREROUTING -i "${wan_if}" -j MARK --set-mark 0x1

  ip link set dev ${AWG_IF} mtu ${AWG_SAFE_MTU} 2>/dev/null || true
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
    iptables -D FORWARD -i "${wan_if}" -o "${AWG_IF}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "${AWG_IF}" -o "${wan_if}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
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

  ip link set dev ${AWG_IF} mtu ${AWG_SAFE_MTU} 2>/dev/null || true
  set_mode_flag "split"
  echo "✅ 已切回【端口分流模式】"
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
  install_amneziawg

  mkdir -p "${AWG_DIR}"
  cd "${AWG_DIR}"

  if [ ! -f entry_private.key ]; then
    echo "[*] 生成入口服务器密钥..."
    umask 077
    awg genkey | tee entry_private.key | awg pubkey > entry_public.key
  fi
  ENTRY_PRIVATE_KEY=$(cat entry_private.key)
  ENTRY_PUBLIC_KEY=$(cat entry_public.key)

  echo
  echo "====== 入口服务器 公钥（出口服务器用）======"
  echo "${ENTRY_PUBLIC_KEY}"
  echo "================================================"
  echo

  read -rp "请粘贴出口服务器生成的连接信息（Link-Token）: " TOKEN_B64
  TOKEN_DECODED=$(echo "$TOKEN_B64" | base64 -d 2>/dev/null || true)

  if [[ -z "$TOKEN_DECODED" || "$TOKEN_DECODED" != *"|"* ]]; then
    echo "❌ 解析失败，请检查复制是否完整。"
    return
  fi

  IFS='|' read -r REMOTE_IP REMOTE_PORT EXIT_PUBKEY P_JC P_JMIN P_JMAX P_S1 P_S2 P_H1 P_H2 P_H3 P_H4 <<< "$TOKEN_DECODED"

  read -rp "入口服务器 AWG 内网 IP (默认 10.0.0.2/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.2/24}

  read -rp "出口服务器 AWG 内网 IP (默认 10.0.0.1/32): " EXIT_WG_IP
  EXIT_WG_IP=${EXIT_WG_IP:-10.0.0.1/32}

  EXIT_WG_IP_NO_MASK="${EXIT_WG_IP%%/*}"
  echo "$EXIT_WG_IP_NO_MASK" > "$EXIT_WG_IP_FILE"

  cat > "${AWG_DIR}/${AWG_IF}.conf" <<EOF
[Interface]
Address = ${WG_ADDR}
PrivateKey = ${ENTRY_PRIVATE_KEY}
Table = off
MTU = ${AWG_SAFE_MTU}

# AmneziaWG 混淆参数
Jc = ${P_JC}
Jmin = ${P_JMIN}
Jmax = ${P_JMAX}
S1 = ${P_S1}
S2 = ${P_S2}
H1 = ${P_H1}
H2 = ${P_H2}
H3 = ${P_H3}
H4 = ${P_H4}

PostUp   = ip rule show | grep -q "fwmark 0x1 lookup 100" || ip rule add fwmark 0x1 lookup 100; ip route replace default dev ${AWG_IF} table 100; iptables -t nat -C POSTROUTING -o ${AWG_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${AWG_IF} -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip rule del fwmark 0x1 lookup 100 2>/dev/null || true; ip route flush table 100 2>/dev/null || true; iptables -t nat -D POSTROUTING -o ${AWG_IF} -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${EXIT_PUBKEY}
Endpoint = ${REMOTE_IP}:${REMOTE_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

  chmod 600 "${AWG_DIR}/${AWG_IF}.conf"

  systemctl enable awg-quick@${AWG_IF}.service >/dev/null 2>&1 || true
  awg-quick down ${AWG_IF} 2>/dev/null || true
  awg-quick up ${AWG_IF}

  ip link set dev ${AWG_IF} mtu ${AWG_SAFE_MTU} 2>/dev/null || true
  ensure_policy_routing_for_ports
  set_mode_flag "split"
  apply_current_mode

  echo "入口服务器配置完成，当前状态："
  awg show || true
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
  echo "==== AWG ===="
  awg show || echo "awg0 未运行"
}

start_wg() {
  echo "[*] 启动链路..."
  if awg-quick up "${AWG_IF}"; then
    apply_current_mode
  else
    echo "❌ AWG 启动失败，未应用模式规则。"
    return 1
  fi
}

stop_wg() {
  echo "[*] 停止链路..."
  awg-quick down ${AWG_IF} 2>/dev/null || true
  ip route flush table 100 2>/dev/null || true
  clear_mark_rules
}

restart_wg() {
  stop_wg
  start_wg
}

uninstall_wg() {
  read -rp "🚨 确认执行焦土级卸载？将彻底抹除所有二进制、内核模块及路由规则！(y/N): " confirm
  if [[ "$confirm" =~ ^[yY]$ ]]; then
    echo "[*] 开始执行物理级深度大扫除..."

    systemctl stop awg-quick@${AWG_IF}.service 2>/dev/null || true
    systemctl disable awg-quick@${AWG_IF}.service 2>/dev/null || true
    stop_wg

    if [[ -f "$PORT_LIST_FILE" ]]; then
      while read -r p; do
        [[ -z "$p" ]] && continue
        [[ "$p" =~ ^# ]] && continue
        remove_port_iptables_rules "$p"
        remove_forward_port_mapping "$p"
      done < "$PORT_LIST_FILE"
    fi

    echo "[*] 清洗 Netfilter 路由与防火墙残留..."
    ip rule del fwmark 0x1 lookup 100 2>/dev/null || true
    ip route flush table 100 2>/dev/null || true
    ip link delete ${AWG_IF} 2>/dev/null || true

    echo "[*] 正在从系统内核拔除 AmneziaWG 驱动..."
    modprobe -r amneziawg 2>/dev/null || true
    rm -f /lib/modules/$(uname -r)/extra/amneziawg.ko 2>/dev/null || true
    depmod -a 2>/dev/null || true

    echo "[*] 正在物理销毁二进制可执行文件与目录痕迹..."
    rm -rf "${AWG_DIR}" 2>/dev/null || true
    rm -rf /usr/local/src/awg_build 2>/dev/null || true
    rm -f /usr/bin/awg /usr/bin/awg-quick /usr/local/bin/awg /usr/local/bin/awg-quick 2>/dev/null || true
    rm -f /usr/share/man/man8/awg.8 /usr/share/man/man8/awg-quick.8 2>/dev/null || true
    rm -f /usr/share/bash-completion/completions/awg /usr/share/bash-completion/completions/awg-quick 2>/dev/null || true

    sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null || true
    sysctl -p >/dev/null 2>&1 || true

    echo "✅ 焦土清理完毕。系统已恢复至部署前的绝对纯净态。正在自毁脚本..."
    rm -f "$0" 2>/dev/null || true
    exit 0
  fi
}

update_entry_remote_ip() {
  local conf="${AWG_DIR}/${AWG_IF}.conf"
  [[ -f "$conf" ]] || return 1
  read -rp "新出口公网 IP: " new_ip
  sed -i -E "s#^(Endpoint = )[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)#\1${new_ip}\2#" "$conf"
  restart_wg
  echo "✅ IP 已更新为 $new_ip"
}

while true; do
  echo
  echo "================ 📡 AWG 高级链路 ================"
  echo "1) 配置为 出口服务器"
  echo "2) 配置为 入口服务器"
  echo "3) 查看链路状态"
  echo "4) 启动"
  echo "5) 停止"
  echo "6) 重启"
  echo "7) 卸载并彻底清理"
  echo "8) 管理入口端口分流"
  echo "9) 管理入口模式（全局 / 分流）"
  echo "10) 修改出口 IP"
  echo "0) 退出"
  echo "================================================="
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
    10) [[ "$(get_role)" == "entry" ]] && update_entry_remote_ip || echo "❌ 仅入口可用" ;;
    0) exit 0 ;;
    *) echo "无效。" ;;
  esac
done
