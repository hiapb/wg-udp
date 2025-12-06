#!/usr/bin/env bash
set -e

WG_IF="wg0"
PORT_LIST_FILE="/etc/wireguard/.wg_ports"
MODE_FILE="/etc/wireguard/.wg_mode"   # 记录入口当前模式：split / global
UDP2RAW_EXIT_CONF="/etc/wireguard/.udp2raw_exit"
UDP2RAW_ENTRY_CONF="/etc/wireguard/.udp2raw_entry"

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行这个脚本： sudo bash wg.sh"
  exit 1
fi

# ====================== udp2raw 安装（只安装，不自动启用） ======================
install_udp2raw() {
  if command -v udp2raw >/dev/null 2>&1; then
    echo "[*] udp2raw 已安装：$(command -v udp2raw)"
    return
  fi

  echo "[*] 开始安装 udp2raw..."
  TMPDIR=$(mktemp -d)
  cd "$TMPDIR" || exit 1

  # 官方 20230206.0 版本二进制包
  UDP2RAW_URL="https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz"

  echo "[*] 下载：$UDP2RAW_URL"
  if ! curl -L --fail -o udp2raw_binaries.tar.gz "$UDP2RAW_URL"; then
    echo "❌ 自动下载 udp2raw 失败。请手动安装："
    echo "   1) 浏览器打开：https://github.com/wangyu-/udp2raw/releases"
    echo "   2) 下载 udp2raw_binaries.tar.gz，到服务器解压"
    echo "   3) 把 udp2raw_amd64 复制到 /usr/local/bin/udp2raw 并 chmod +x"
    cd / || true
    rm -rf "$TMPDIR"
    return
  fi

  echo "[*] 解压..."
  tar -xzf udp2raw_binaries.tar.gz

  if [[ -f udp2raw_amd64 ]]; then
    install -m 755 udp2raw_amd64 /usr/local/bin/udp2raw
    echo "✅ udp2raw 已安装到 /usr/local/bin/udp2raw"
  else
    echo "❌ 解压成功，但未找到 udp2raw_amd64，请检查 release 包结构。"
  fi

  cd / || true
  rm -rf "$TMPDIR"
}

# ====================== WireGuard 基础依赖 ======================
install_wireguard() {
  echo "[*] 检查 WireGuard 及相关依赖..."
  NEED_PKGS=(wireguard wireguard-tools iproute2 iptables curl)
  MISSING_PKGS=()

  for pkg in "${NEED_PKGS[@]}"; do
    dpkg -s "$pkg" &>/dev/null || MISSING_PKGS+=("$pkg")
  done

  if [ ${#MISSING_PKGS[@]} -eq 0 ]; then
    echo "[*] 所有依赖已安装，跳过安装步骤。"
  else
    echo "[*] 将安装缺失的依赖包: ${MISSING_PKGS[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y "${MISSING_PKGS[@]}"
  fi

  # 顺便安装 udp2raw（只是准备好）
  install_udp2raw
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

  install_wireguard

  PUB_IP_DETECTED=$(detect_public_ip || true)
  if [[ -n "$PUB_IP_DETECTED" ]]; then
    echo "[*] 检测到出口服务器公网 IP 可能是：$PUB_IP_DETECTED"
  else
    echo "[*] 未能自动检测公网 IP，请查看服务商面板。"
  fi

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.1/24}

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/32): " ENTRY_WG_IP
  ENTRY_WG_IP=${ENTRY_WG_IP:-10.0.0.2/32}

  DEFAULT_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
  read -rp "出口服务器对外网卡名(默认 ${DEFAULT_IF:-eth0}): " OUT_IF
  OUT_IF=${OUT_IF:-${DEFAULT_IF:-eth0}}

  # udp2raw 相关
  read -rp "udp2raw 服务器监听端口 (默认 4000): " UDP2RAW_PORT
  UDP2RAW_PORT=${UDP2RAW_PORT:-4000}

  # 密码尽量简单点（不含空格和引号）
  DEFAULT_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
  read -rp "udp2raw 密码 (默认随机: ${DEFAULT_PASS}，不要包含空格和引号): " UDP2RAW_PASS
  UDP2RAW_PASS=${UDP2RAW_PASS:-$DEFAULT_PASS}

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
  echo "⚙ udp2raw 参数："
  echo "   监听端口：${UDP2RAW_PORT}"
  echo "   密码：${UDP2RAW_PASS}"
  echo

  read -rp "请输入【入口服务器公钥】(可以先占位，之后再改): " ENTRY_PUBLIC_KEY
  ENTRY_PUBLIC_KEY=${ENTRY_PUBLIC_KEY:-CHANGE_ME_ENTRY_PUBLIC_KEY}

  # 开启 IPv4 转发
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi

  # 保存 udp2raw 出口配置
  cat > "$UDP2RAW_EXIT_CONF" <<EOF
PORT=${UDP2RAW_PORT}
PASS=${UDP2RAW_PASS}
EOF

  # WireGuard 监听本机 UDP 51820，由 udp2raw 转发过来
  WG_PORT=51820

  cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${EXIT_PRIVATE_KEY}

PostUp   = iptables -A FORWARD -i ${WG_IF} -j ACCEPT; iptables -A FORWARD -o ${WG_IF} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${OUT_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_IF} -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o ${WG_IF} -j ACCEPT 2>/dev/null || true; iptables -t nat -D POSTROUTING -o ${OUT_IF} -j MASQUERADE 2>/dev/null || true

[Peer]
PublicKey = ${ENTRY_PUBLIC_KEY}
AllowedIPs = ${ENTRY_WG_IP}
EOF

  chmod 600 /etc/wireguard/${WG_IF}.conf

  systemctl enable wg-quick@${WG_IF}.service >/dev/null 2>&1 || true
  wg-quick down ${WG_IF} 2>/dev/null || true
  wg-quick up ${WG_IF}

  # 创建 udp2raw server systemd 服务
  if command -v udp2raw >/dev/null 2>&1; then
    cat > /etc/systemd/system/udp2raw-wg-exit.service <<EOF
[Unit]
Description=udp2raw for WireGuard (exit server)
After=network-online.target wg-quick@${WG_IF}.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw -s \\
  -l 0.0.0.0:${UDP2RAW_PORT} \\
  -r 127.0.0.1:${WG_PORT} \\
  --raw-mode faketcp \\
  --cipher-mode xor \\
  -k ${UDP2RAW_PASS} \\
  -a
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable udp2raw-wg-exit.service >/dev/null 2>&1 || true
    systemctl restart udp2raw-wg-exit.service || true
    echo "✅ udp2raw 服务器已通过 systemd 启动（udp2raw-wg-exit.service）。"
  else
    echo "⚠ udp2raw 未安装成功，暂时无法启用混淆，仅使用纯 WG。"
  fi

  echo
  echo "出口服务器配置完成，当前状态："
  wg show || true
}

# ====================== 入口服务器：策略路由 & 分流 ======================

ensure_policy_routing_for_ports() {
  if ! ip link show "${WG_IF}" &>/dev/null; then
    return 0
  fi

  if ! ip rule show | grep -q "fwmark 0x1 lookup 100"; then
    ip rule add fwmark 0x1 lookup 100
  fi

  ip route replace default dev ${WG_IF} table 100
}

# 清理 OUTPUT 链中所有 MARK 相关规则，避免模式切换后残留
clear_mark_rules() {
  iptables -t mangle -S OUTPUT 2>/dev/null | grep " MARK " \
    | sed 's/^-A /-D /' | while read -r line; do
        iptables -t mangle $line 2>/dev/null || true
      done
}

apply_port_rules_from_file() {
  clear_mark_rules
  [[ ! -f "$PORT_LIST_FILE" ]] && return 0

  while read -r p; do
    [[ -z "$p" ]] && continue
    [[ "$p" =~ ^# ]] && continue
    iptables -t mangle -C OUTPUT -p tcp --sport "$p" -j MARK --set-mark 0x1 2>/dev/null || \
      iptables -t mangle -A OUTPUT -p tcp --sport "$p" -j MARK --set-mark 0x1
    iptables -t mangle -C OUTPUT -p udp --sport "$p" -j MARK --set-mark 0x1 2>/dev/null || \
      iptables -t mangle -A OUTPUT -p udp --sport "$p" -j MARK --set-mark 0x1
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
  iptables -t mangle -D OUTPUT -p tcp --sport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
  iptables -t mangle -D OUTPUT -p udp --sport "$port" -j MARK --set-mark 0x1 2>/dev/null || true
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

enable_global_mode() {
  echo "[*] 切换为【全局模式】..."
  ensure_policy_routing_for_ports
  clear_mark_rules

  # 不处理 lo
  iptables -t mangle -C OUTPUT -o lo -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -o lo -j RETURN

  # SSH 不走 wg（避免断连）
  iptables -t mangle -C OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --sport 22 -j RETURN

  # WireGuard 隧道本身不走 wg（避免递归）
  iptables -t mangle -C OUTPUT -p udp --sport 51820 -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p udp --sport 51820 -j RETURN
  iptables -t mangle -C OUTPUT -p udp --dport 51820 -j RETURN 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p udp --dport 51820 -j RETURN

  # 其余所有出站流量打 mark=0x1 → table100 → wg0
  iptables -t mangle -C OUTPUT -j MARK --set-mark 0x1 2>/dev/null || \
    iptables -t mangle -A OUTPUT -j MARK --set-mark 0x1

  set_mode_flag("global") 2>/dev/null || set_mode_flag global
  echo "✅ 已切到【全局模式】，除 SSH/WG/lo 外全部流量走出口。"
}

enable_split_mode() {
  echo "[*] 切换为【端口分流模式】..."
  ensure_policy_routing_for_ports
  clear_mark_rules
  apply_port_rules_from_file
  set_mode_flag("split") 2>/dev/null || set_mode_flag split
  echo "✅ 已切回【端口分流模式】，只有端口列表中源端口才走出口。"
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

# ====================== 入口服务器配置（WG + udp2raw client） ======================
configure_entry() {
  echo "==== 配置为【入口服务器】 ===="

  install_wireguard

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.2/24}

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/32): " EXIT_WG_IP
  EXIT_WG_IP=${EXIT_WG_IP:-10.0.0.1/32}

  mkdir -p /etc/wireguard
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

  # udp2raw client 相关
  read -rp "出口 udp2raw 服务器端口 (默认 4000): " UDP2RAW_PORT
  UDP2RAW_PORT=${UDP2RAW_PORT:-4000}

  read -rp "本机 udp2raw 本地监听端口 (默认 51821): " UDP2RAW_LOCAL
  UDP2RAW_LOCAL=${UDP2RAW_LOCAL:-51821}

  read -rp "udp2raw 密码（必须和出口一致）: " UDP2RAW_PASS
  if [[ -z "$UDP2RAW_PASS" ]]; then
    echo "udp2raw 密码不能为空（需要和出口一致）。"
    exit 1
  fi

  cd /etc/wireguard

  if [ ! -f entry_private.key ]; then
    echo "[*] 生成入口服务器密钥..."
    umask 077
    wg genkey | tee entry_private.key | wg pubkey > entry_public.key
  fi

  ENTRY_PRIVATE_KEY=$(cat entry_private.key)
  ENTRY_PUBLIC_KEY=$(cat entry_public.key)

  echo
  echo "====== 入口服务器 公钥（发给出口用）======"
  echo "${ENTRY_PUBLIC_KEY}"
  echo "================================================"
  echo
  echo "⚙ udp2raw 参数："
  echo "   出口地址：${EXIT_PUBLIC_IP}"
  echo "   出口 udp2raw 端口：${UDP2RAW_PORT}"
  echo "   本机 udp2raw 监听：127.0.0.1:${UDP2RAW_LOCAL}"
  echo "   密码：${UDP2RAW_PASS}"
  echo

  read -rp "请输入【出口服务器公钥】: " EXIT_PUBLIC_KEY
  EXIT_PUBLIC_KEY=${EXIT_PUBLIC_KEY:-CHANGE_ME_EXIT_PUBLIC_KEY}

  # 保存入口 udp2raw 配置
  cat > "$UDP2RAW_ENTRY_CONF" <<EOF
EXIT_IP=${EXIT_PUBLIC_IP}
SERVER_PORT=${UDP2RAW_PORT}
LOCAL_PORT=${UDP2RAW_LOCAL}
PASS=${UDP2RAW_PASS}
EOF

  # WG 对 udp2raw 本地监听端口发包，而不是直接对出口公网发包
  cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_ADDR}
PrivateKey = ${ENTRY_PRIVATE_KEY}
Table = off

PostUp   = ip rule show | grep -q "fwmark 0x1 lookup 100" || ip rule add fwmark 0x1 lookup 100; \
           ip route replace default dev ${WG_IF} table 100; \
           iptables -t nat -C POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${WG_IF} -j MASQUERADE
PostDown = ip rule del fwmark 0x1 lookup 100 2>/dev/null || true; \
           ip route flush table 100 2>/dev/null || true; \
           iptables -t nat -D POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || true

[Peer]
PublicKey = ${EXIT_PUBLIC_KEY}
Endpoint = 127.0.0.1:${UDP2RAW_LOCAL}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

  chmod 600 /etc/wireguard/${WG_IF}.conf

  systemctl enable wg-quick@${WG_IF}.service >/dev/null 2>&1 || true
  wg-quick down ${WG_IF} 2>/dev/null || true
  wg-quick up ${WG_IF}

  ensure_policy_routing_for_ports

  # 创建 udp2raw client systemd 服务
  if command -v udp2raw >/dev/null 2>&1; then
    cat > /etc/systemd/system/udp2raw-wg-entry.service <<EOF
[Unit]
Description=udp2raw for WireGuard (entry client)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw -c \\
  -l 127.0.0.1:${UDP2RAW_LOCAL} \\
  -r ${EXIT_PUBLIC_IP}:${UDP2RAW_PORT} \\
  --raw-mode faketcp \\
  --cipher-mode xor \\
  -k ${UDP2RAW_PASS} \\
  -a
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable udp2raw-wg-entry.service >/dev/null 2>&1 || true
    systemctl restart udp2raw-wg-entry.service || true
    echo "✅ udp2raw 客户端已通过 systemd 启动（udp2raw-wg-entry.service）。"
  else
    echo "⚠ udp2raw 未安装成功，入口暂时只能直接连 WG（不走 udp2raw）。"
  fi

  # 默认先用端口分流模式
  set_mode_flag "split"
  apply_current_mode

  echo
  echo "入口服务器配置完成，当前状态："
  wg show || true

  echo
  echo "✅ 之后如果要切换："
  echo "  - 用本脚本菜单 8 管理分流端口（比如加 8080）。"
  echo "  - 用本脚本菜单 9 切换【全局模式】 / 【端口分流模式】。"
}

manage_entry_ports() {
  echo "==== 入口服务器 端口分流管理 ===="
  echo "说明："
  echo "  - 管的是【入口这台机器】本地源端口的分流规则；"
  echo "  - 源端口在列表中的所有 TCP/UDP 流量 → mark=0x1 → table100 → wg0 → 出口；"
  echo "  - 其它端口流量 → 走入口自己的公网。"
  echo

  ensure_policy_routing_for_ports

  while true; do
    echo
    echo "---- 端口管理菜单 ----"
    echo "1) 查看当前分流端口列表"
    echo "2) 添加端口到分流列表"
    echo "3) 从分流列表删除端口"
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
          add_port_to_list "$new_port"
          ensure_policy_routing_for_ports
          apply_port_rules_from_file
        else
          echo "端口不合法。"
        fi
        ;;
      3)
        read -rp "请输入要删除的端口: " del_port
        if [[ "$del_port" =~ ^[0-9]+$ ]]; then
          remove_port_from_list "$del_port"
          remove_port_iptables_rules "$del_port"
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

# ====================== 通用操作 ======================
show_status() {
  echo "==== WireGuard 状态 ===="
  if command -v wg >/dev/null 2>&1; then
    wg show || echo "wg0 似乎还没配置/启动。"
  else
    echo "系统未安装 WireGuard。"
  fi

  echo
  echo "==== udp2raw 服务状态（如果有） ===="
  systemctl is-active udp2raw-wg-exit.service >/dev/null 2>&1 && systemctl status udp2raw-wg-exit.service --no-pager || echo "udp2raw-wg-exit.service 未运行或未配置（出口机才有）。"
  echo
  systemctl is-active udp2raw-wg-entry.service >/dev/null 2>&1 && systemctl status udp2raw-wg-entry.service --no-pager || echo "udp2raw-wg-entry.service 未运行或未配置（入口机才有）。"
}

start_wg() {
  echo "[*] 启动 WireGuard (${WG_IF})..."
  wg-quick up ${WG_IF} || true
  ensure_policy_routing_for_ports
  apply_current_mode
  wg show || true
}

stop_wg() {
  echo "[*] 停止 WireGuard (${WG_IF})..."
  wg-quick down ${WG_IF} || true
  wg show || true
}

restart_wg() {
  echo "[*] 重启 WireGuard (${WG_IF})..."
  wg-quick down ${WG_IF} 2>/dev/null || true
  wg-quick up ${WG_IF} || true
  ensure_policy_routing_for_ports
  apply_current_mode
  wg show || true
}

uninstall_wg() {
  echo "==== 卸载 WireGuard ===="
  echo "此操作将会："
  echo "  - 停止 wg-quick@${WG_IF} / udp2raw-* 服务并取消开机自启"
  echo "  - 删除 /etc/wireguard 内的配置、密钥、端口分流配置、模式配置、公网 IP 记录、udp2raw 配置"
  echo "  - 移除策略路由 / iptables 标记 / NAT 规则"
  echo "  - 卸载 wireguard 与 wireguard-tools"
  echo
  read -rp "确认卸载？(y/N): " confirm
  case "$confirm" in
    y|Y)
      systemctl stop wg-quick@${WG_IF}.service 2>/dev/null || true
      systemctl disable wg-quick@${WG_IF}.service 2>/dev/null || true

      systemctl stop udp2raw-wg-exit.service 2>/dev/null || true
      systemctl disable udp2raw-wg-exit.service 2>/dev/null || true
      rm -f /etc/systemd/system/udp2raw-wg-exit.service 2>/dev/null || true

      systemctl stop udp2raw-wg-entry.service 2>/dev/null || true
      systemctl disable udp2raw-wg-entry.service 2>/dev/null || true
      rm -f /etc/systemd/system/udp2raw-wg-entry.service 2>/dev/null || true

      systemctl daemon-reload

      wg-quick down ${WG_IF} 2>/dev/null || true

      ip rule del fwmark 0x1 lookup 100 2>/dev/null || true
      ip route flush table 100 2>/dev/null || true

      clear_mark_rules
      iptables -t nat -D POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || true

      rm -f /etc/wireguard/${WG_IF}.conf \
            /etc/wireguard/exit_private.key /etc/wireguard/exit_public.key \
            /etc/wireguard/entry_private.key /etc/wireguard/entry_public.key \
            /etc/wireguard/.exit_public_ip \
            "$PORT_LIST_FILE" "$MODE_FILE" \
            "$UDP2RAW_EXIT_CONF" "$UDP2RAW_ENTRY_CONF" 2>/dev/null || true
      rmdir /etc/wireguard 2>/dev/null || true

      export DEBIAN_FRONTEND=noninteractive
      apt remove -y wireguard wireguard-tools 2>/dev/null || true
      apt autoremove -y 2>/dev/null || true

      echo "✅ WireGuard 和相关配置已卸载清理。"
      ;;
    *)
      echo "已取消卸载。"
      ;;
  esac
}

# ====================== 主菜单 ======================
while true; do
  echo
  echo "================ WireGuard + udp2raw 一键脚本 ================"
  echo "1) 配置为 出口服务器（WG + udp2raw server）"
  echo "2) 配置为 入口服务器（WG + udp2raw client + 分流）"
  echo "3) 查看 WireGuard / udp2raw 状态"
  echo "4) 启动 WireGuard"
  echo "5) 停止 WireGuard"
  echo "6) 重启 WireGuard"
  echo "7) 卸载 WireGuard（清理所有配置和服务）"
  echo "8) 管理入口端口分流"
  echo "9) 管理入口模式（全局 / 端口分流）"
  echo "0) 退出"
  echo "=============================================================="
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
    0) exit 0 ;;
    *) echo "无效选项。" ;;
  esac
done
