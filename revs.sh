#!/usr/bin/env bash
set -euo pipefail

########################################
# 基础变量
########################################
SING_DIR="/etc/singbox-reality-fw"
SING_BIN="/usr/local/bin/sing-box"
SING_VERSION="1.13.5"

ROLE_FILE="${SING_DIR}/.role"
MODE_FILE="${SING_DIR}/.mode"
PORT_LIST_FILE="${SING_DIR}/ports.list"
SNI_LIST_FILE="${SING_DIR}/sni.list"

REMOTE_HOST_FILE="${SING_DIR}/remote_host"
REMOTE_IP_FILE="${SING_DIR}/remote_ip"
UUID_FILE="${SING_DIR}/uuid"
SHORT_ID_FILE="${SING_DIR}/short_id"
PUBKEY_FILE="${SING_DIR}/public_key"
ACTIVE_SNI_FILE="${SING_DIR}/active_sni"
EXIT_PUBLIC_IP_FILE="${SING_DIR}/exit_public_ip"

TPROXY_PORT="60080"
TPROXY_MARK="0x1"
TPROXY_TABLE="100"
TPROXY_CHAIN="RLY_TPROXY"
TPROXY_DIVERT_CHAIN="RLY_DIVERT"

ENTRY_SERVICE="/etc/systemd/system/reality-fw-entry.service"
EXIT_SERVICE="/etc/systemd/system/reality-fw-exit.service"

########################################
# root 检查
########################################
if [[ $EUID -ne 0 ]]; then
  echo "❌ 请用 root 运行"
  exit 1
fi

########################################
# 工具函数
########################################
trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

cmd_exists() {
  command -v "$1" >/dev/null 2>&1
}

require_apt() {
  if ! cmd_exists apt-get; then
    echo "❌ 仅支持 Debian / Ubuntu（需要 apt-get）"
    exit 1
  fi
}

ensure_dirs() {
  mkdir -p "$SING_DIR"
  chmod 700 "$SING_DIR"
  touch "$PORT_LIST_FILE" "$SNI_LIST_FILE"
}

get_role() {
  [[ -f "$ROLE_FILE" ]] && cat "$ROLE_FILE" 2>/dev/null || echo "unknown"
}

set_role() {
  ensure_dirs
  echo "$1" > "$ROLE_FILE"
}

get_mode() {
  [[ -f "$MODE_FILE" ]] && cat "$MODE_FILE" 2>/dev/null || echo "split"
}

set_mode() {
  ensure_dirs
  echo "$1" > "$MODE_FILE"
}

detect_public_ip() {
  local ip=""
  for svc in "https://api.ipify.org" "https://ifconfig.me" "https://ipinfo.io/ip"; do
    ip="$(curl -4 -fsS --max-time 5 "$svc" 2>/dev/null || true)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

resolve_ipv4() {
  local host="$1"
  local ip=""
  ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')"
  [[ -n "$ip" ]] && echo "$ip"
}

gen_short_id() {
  if cmd_exists openssl; then
    openssl rand -hex 4 | tr 'A-F' 'a-f'
  else
    hexdump -n 4 -ve '/1 "%02x"' /dev/urandom
  fi
}

get_wan_if() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1
}

########################################
# 安装依赖
########################################
install_base_packages() {
  echo "[*] 检查并安装依赖..."
  require_apt
  export DEBIAN_FRONTEND=noninteractive

  local pkgs=()

  cmd_exists curl || pkgs+=("curl")
  cmd_exists jq || pkgs+=("jq")
  cmd_exists iptables || pkgs+=("iptables")
  cmd_exists ip || pkgs+=("iproute2")
  cmd_exists openssl || pkgs+=("openssl")
  cmd_exists getent || pkgs+=("libc-bin")
  cmd_exists ss || pkgs+=("iproute2")
  cmd_exists modprobe || pkgs+=("kmod")

  if ! dpkg -s ca-certificates >/dev/null 2>&1; then
    pkgs+=("ca-certificates")
  fi

  if [[ "${#pkgs[@]}" -gt 0 ]]; then
    apt-get update -yq
    apt-get install -yq "${pkgs[@]}"
  else
    echo "[*] 依赖已齐全"
  fi
}

install_singbox() {
  echo "[*] 检查 sing-box ..."
  if [[ -x "$SING_BIN" ]]; then
    echo "[*] sing-box 已存在：$($SING_BIN version 2>/dev/null | head -n1 || true)"
    return 0
  fi

  local arch file release_json bin_url digest extracted_bin actual expected
  local tmpdir=""
  arch="$(uname -m)"

  case "$arch" in
    x86_64|amd64) file="sing-box-${SING_VERSION}-linux-amd64.tar.gz" ;;
    aarch64|arm64) file="sing-box-${SING_VERSION}-linux-arm64.tar.gz" ;;
    armv7l|armv7) file="sing-box-${SING_VERSION}-linux-armv7.tar.gz" ;;
    armv6l|armv6) file="sing-box-${SING_VERSION}-linux-armv6.tar.gz" ;;
    i386|i686) file="sing-box-${SING_VERSION}-linux-386.tar.gz" ;;
    s390x) file="sing-box-${SING_VERSION}-linux-s390x.tar.gz" ;;
    riscv64) file="sing-box-${SING_VERSION}-linux-riscv64.tar.gz" ;;
    loongarch64) file="sing-box-${SING_VERSION}-linux-loong64.tar.gz" ;;
    *)
      echo "❌ 不支持的架构: $arch"
      exit 1
      ;;
  esac

  tmpdir="$(mktemp -d)"
  release_json="${tmpdir}/release.json"

  curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: sing-box-installer" \
    "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v${SING_VERSION}" \
    -o "$release_json"

  bin_url="$(
    jq -r --arg name "$file" '.assets[] | select(.name == $name) | .browser_download_url' "$release_json" | head -n1
  )"

  digest="$(
    jq -r --arg name "$file" '.assets[] | select(.name == $name) | .digest // empty' "$release_json" | head -n1
  )"

  if [[ -z "${bin_url:-}" || "$bin_url" == "null" ]]; then
    rm -rf "$tmpdir"
    echo "❌ 未找到二进制下载地址: $file"
    exit 1
  fi

  if [[ -z "${digest:-}" || "$digest" == "null" ]]; then
    rm -rf "$tmpdir"
    echo "❌ 未找到官方 digest，终止"
    exit 1
  fi

  if [[ "$digest" =~ ^sha256:([A-Fa-f0-9]{64})$ ]]; then
    expected="${BASH_REMATCH[1],,}"
  elif [[ "$digest" =~ ^[A-Fa-f0-9]{64}$ ]]; then
    expected="${digest,,}"
  else
    rm -rf "$tmpdir"
    echo "❌ digest 格式无法识别: $digest"
    exit 1
  fi

  echo "[*] 下载 sing-box ${SING_VERSION} ..."
  curl -fL --retry 3 --connect-timeout 15 "$bin_url" -o "${tmpdir}/${file}"

  actual="$(sha256sum "${tmpdir}/${file}" | awk '{print tolower($1)}')"
  echo "[*] SHA256 校验..."
  if [[ "$actual" != "$expected" ]]; then
    rm -rf "$tmpdir"
    echo "❌ SHA256 校验失败"
    echo "期望: $expected"
    echo "实际: $actual"
    exit 1
  fi

  tar -xzf "${tmpdir}/${file}" -C "$tmpdir"
  extracted_bin="$(find "$tmpdir" -type f -name sing-box | head -n1)"

  if [[ -z "${extracted_bin:-}" ]]; then
    rm -rf "$tmpdir"
    echo "❌ 解压后未找到 sing-box"
    exit 1
  fi

  install -m 0755 "$extracted_bin" "$SING_BIN"
  rm -rf "$tmpdir"

  echo "✅ sing-box 已安装：$($SING_BIN version 2>/dev/null | head -n1 || true)"
}

########################################
# SNI 管理
########################################
init_default_sni_list() {
  ensure_dirs
  if [[ ! -s "$SNI_LIST_FILE" ]]; then
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

get_active_sni() {
  if [[ -f "$ACTIVE_SNI_FILE" ]] && [[ -s "$ACTIVE_SNI_FILE" ]]; then
    cat "$ACTIVE_SNI_FILE"
  else
    init_default_sni_list
    head -n1 "$SNI_LIST_FILE"
  fi
}

set_active_sni() {
  ensure_dirs
  echo "$1" > "$ACTIVE_SNI_FILE"
}

list_sni() {
  init_default_sni_list
  nl -ba "$SNI_LIST_FILE"
}

add_sni() {
  init_default_sni_list
  local sni="$1"
  grep -Fxq "$sni" "$SNI_LIST_FILE" || echo "$sni" >> "$SNI_LIST_FILE"
}

del_sni() {
  local sni="$1"
  [[ -f "$SNI_LIST_FILE" ]] || return 0
  sed -i "\|^${sni}$|d" "$SNI_LIST_FILE"
}

choose_sni_menu() {
  init_default_sni_list
  while true; do
    echo "==== SNI 列表 ===="
    nl -ba "$SNI_LIST_FILE"
    echo "当前生效：$(get_active_sni)"
    echo "1) 选择当前 SNI"
    echo "2) 添加 SNI"
    echo "3) 删除 SNI"
    echo "0) 返回"
    read -rp "请选择: " sub
    case "$sub" in
      1)
        read -rp "输入序号: " idx
        local chosen
        chosen="$(sed -n "${idx}p" "$SNI_LIST_FILE" 2>/dev/null || true)"
        chosen="$(trim "${chosen:-}")"
        if [[ -n "$chosen" ]]; then
          set_active_sni "$chosen"
          echo "✅ 已切换为：$chosen"
          [[ "$(get_role)" == "entry" ]] && rebuild_entry_config_and_restart
        else
          echo "❌ 序号无效"
        fi
        ;;
      2)
        read -rp "输入要添加的 SNI: " sni
        sni="$(trim "${sni:-}")"
        [[ -n "$sni" ]] && add_sni "$sni" && echo "✅ 已添加"
        ;;
      3)
        read -rp "输入要删除的 SNI: " sni
        sni="$(trim "${sni:-}")"
        if [[ -n "$sni" ]]; then
          del_sni "$sni"
          echo "✅ 已删除"
          if [[ "$(get_active_sni)" == "$sni" ]]; then
            local fallback
            fallback="$(head -n1 "$SNI_LIST_FILE" 2>/dev/null || true)"
            fallback="$(trim "${fallback:-}")"
            [[ -n "$fallback" ]] && set_active_sni "$fallback"
          fi
          [[ "$(get_role)" == "entry" ]] && rebuild_entry_config_and_restart
        fi
        ;;
      0) break ;;
      *) echo "无效" ;;
    esac
  done
}

########################################
# 端口列表管理
########################################
add_port_to_list() {
  local port="$1"
  ensure_dirs
  touch "$PORT_LIST_FILE"
  if grep -qx "$port" "$PORT_LIST_FILE"; then
    echo "端口 $port 已存在"
    return 0
  fi
  echo "$port" >> "$PORT_LIST_FILE"
  sort -n -u "$PORT_LIST_FILE" -o "$PORT_LIST_FILE"
  echo "已添加端口 $port"
}

remove_port_from_list() {
  local port="$1"
  [[ -f "$PORT_LIST_FILE" ]] || return 0
  if grep -qx "$port" "$PORT_LIST_FILE"; then
    sed -i "\|^$port$|d" "$PORT_LIST_FILE"
    echo "已删除端口 $port"
  else
    echo "端口 $port 不在列表中"
  fi
}

########################################
# 内核 / 路由 / iptables
########################################
enable_ip_forward() {
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null || true
  sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
  sed -i '/net.ipv4.conf.all.route_localnet/d' /etc/sysctl.conf 2>/dev/null || true
  {
    echo "net.ipv4.ip_forward=1"
    echo "net.ipv4.conf.all.route_localnet=1"
  } >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
}

load_tproxy_modules() {
  modprobe xt_TPROXY 2>/dev/null || true
  modprobe nf_tproxy_ipv4 2>/dev/null || true
  modprobe xt_socket 2>/dev/null || true
}

create_tproxy_chains() {
  iptables -t mangle -N "$TPROXY_DIVERT_CHAIN" 2>/dev/null || true
  iptables -t mangle -N "$TPROXY_CHAIN" 2>/dev/null || true
}

flush_tproxy_chains() {
  iptables -t mangle -F "$TPROXY_DIVERT_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$TPROXY_CHAIN" 2>/dev/null || true
}

drop_tproxy_chains() {
  iptables -t mangle -D PREROUTING -j "$TPROXY_DIVERT_CHAIN" 2>/dev/null || true
  iptables -t mangle -D PREROUTING -j "$TPROXY_CHAIN" 2>/dev/null || true
  iptables -t mangle -D OUTPUT -j "$TPROXY_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$TPROXY_DIVERT_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$TPROXY_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$TPROXY_DIVERT_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$TPROXY_CHAIN" 2>/dev/null || true
}

ensure_policy_route() {
  ip rule show | grep -q "fwmark ${TPROXY_MARK} lookup ${TPROXY_TABLE}" || \
    ip rule add fwmark "${TPROXY_MARK}" lookup "${TPROXY_TABLE}"
  ip route replace local 0.0.0.0/0 dev lo table "${TPROXY_TABLE}"
}

clear_policy_route() {
  ip rule del fwmark "${TPROXY_MARK}" lookup "${TPROXY_TABLE}" 2>/dev/null || true
  ip route flush table "${TPROXY_TABLE}" 2>/dev/null || true
}

apply_split_mode_rules() {
  enable_ip_forward
  load_tproxy_modules
  create_tproxy_chains
  flush_tproxy_chains
  ensure_policy_route

  local wan_if
  wan_if="$(get_wan_if)"
  wan_if="${wan_if:-eth0}"

  iptables -t mangle -A "$TPROXY_DIVERT_CHAIN" -p tcp -m socket -j MARK --set-mark "$TPROXY_MARK"
  iptables -t mangle -A "$TPROXY_DIVERT_CHAIN" -p tcp -m socket -j ACCEPT
  iptables -t mangle -A "$TPROXY_DIVERT_CHAIN" -p udp -m socket -j MARK --set-mark "$TPROXY_MARK"
  iptables -t mangle -A "$TPROXY_DIVERT_CHAIN" -p udp -m socket -j ACCEPT

  iptables -t mangle -C PREROUTING -j "$TPROXY_DIVERT_CHAIN" 2>/dev/null || \
    iptables -t mangle -A PREROUTING -j "$TPROXY_DIVERT_CHAIN"

  iptables -t mangle -A "$TPROXY_CHAIN" -p tcp --dport 22 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p udp --dport 22 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -d 127.0.0.1/32 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p tcp --dport 443 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p udp --dport 443 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p tcp --dport "$TPROXY_PORT" -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p udp --dport "$TPROXY_PORT" -j RETURN

  if [[ -f "$PORT_LIST_FILE" ]]; then
    while read -r p; do
      p="$(trim "$p")"
      [[ -z "$p" ]] && continue
      [[ "$p" =~ ^# ]] && continue
      [[ "$p" =~ ^[0-9]+$ ]] || continue

      iptables -t mangle -A "$TPROXY_CHAIN" -p tcp --dport "$p" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$TPROXY_MARK/$TPROXY_MARK"
      iptables -t mangle -A "$TPROXY_CHAIN" -p udp --dport "$p" -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$TPROXY_MARK/$TPROXY_MARK"
    done < "$PORT_LIST_FILE"
  fi

  iptables -t mangle -C PREROUTING -j "$TPROXY_CHAIN" 2>/dev/null || \
    iptables -t mangle -A PREROUTING -j "$TPROXY_CHAIN"

  # 本机发起的同端口连接也走
  iptables -t mangle -C OUTPUT -j "$TPROXY_CHAIN" 2>/dev/null || \
    iptables -t mangle -A OUTPUT -j "$TPROXY_CHAIN"

  set_mode "split"
  echo "✅ 已切到【端口分流模式】"
}

apply_global_mode_rules() {
  enable_ip_forward
  load_tproxy_modules
  create_tproxy_chains
  flush_tproxy_chains
  ensure_policy_route

  iptables -t mangle -A "$TPROXY_DIVERT_CHAIN" -p tcp -m socket -j MARK --set-mark "$TPROXY_MARK"
  iptables -t mangle -A "$TPROXY_DIVERT_CHAIN" -p tcp -m socket -j ACCEPT
  iptables -t mangle -A "$TPROXY_DIVERT_CHAIN" -p udp -m socket -j MARK --set-mark "$TPROXY_MARK"
  iptables -t mangle -A "$TPROXY_DIVERT_CHAIN" -p udp -m socket -j ACCEPT

  iptables -t mangle -C PREROUTING -j "$TPROXY_DIVERT_CHAIN" 2>/dev/null || \
    iptables -t mangle -A PREROUTING -j "$TPROXY_DIVERT_CHAIN"

  iptables -t mangle -A "$TPROXY_CHAIN" -p tcp --dport 22 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p udp --dport 22 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -d 127.0.0.1/32 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p tcp --dport 443 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p udp --dport 443 -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p tcp --dport "$TPROXY_PORT" -j RETURN
  iptables -t mangle -A "$TPROXY_CHAIN" -p udp --dport "$TPROXY_PORT" -j RETURN

  iptables -t mangle -A "$TPROXY_CHAIN" -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$TPROXY_MARK/$TPROXY_MARK"
  iptables -t mangle -A "$TPROXY_CHAIN" -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$TPROXY_MARK/$TPROXY_MARK"

  iptables -t mangle -C PREROUTING -j "$TPROXY_CHAIN" 2>/dev/null || \
    iptables -t mangle -A PREROUTING -j "$TPROXY_CHAIN"

  iptables -t mangle -C OUTPUT -j "$TPROXY_CHAIN" 2>/dev/null || \
    iptables -t mangle -A OUTPUT -j "$TPROXY_CHAIN"

  set_mode "global"
  echo "✅ 已切到【全局模式】"
}

apply_current_mode() {
  [[ "$(get_role)" != "entry" ]] && return 0
  local mode
  mode="$(get_mode)"
  if [[ "$mode" == "global" ]]; then
    apply_global_mode_rules
  else
    apply_split_mode_rules
  fi
}

########################################
# 配置文件生成
########################################
write_exit_config() {
  local cover_sni="$1"
  local uuid="$2"
  local short_id="$3"
  local private_key="$4"

  cat > "${SING_DIR}/config.json" <<EOF
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "reality-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "uuid": "${uuid}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${cover_sni}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${cover_sni}",
            "server_port": 443
          },
          "private_key": "${private_key}",
          "short_id": [
            "${short_id}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": ["reality-in"],
        "action": "route-options",
        "override_address": "127.0.0.1"
      },
      {
        "inbound": ["reality-in"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
EOF
}

write_entry_config() {
  local remote_host="$1"
  local uuid="$2"
  local short_id="$3"
  local public_key="$4"
  local sni="$5"

  cat > "${SING_DIR}/config.json" <<EOF
{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [
      {
        "type": "local",
        "tag": "local"
      }
    ]
  },
  "inbounds": [
    {
      "type": "tproxy",
      "tag": "tproxy-in",
      "listen": "0.0.0.0",
      "listen_port": ${TPROXY_PORT},
      "network": "tcp"
    },
    {
      "type": "tproxy",
      "tag": "tproxy-udp-in",
      "listen": "0.0.0.0",
      "listen_port": ${TPROXY_PORT},
      "network": "udp"
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-out",
      "server": "${remote_host}",
      "server_port": 443,
      "uuid": "${uuid}",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "${sni}",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "${public_key}",
          "short_id": "${short_id}"
        }
      },
      "domain_resolver": {
        "server": "local",
        "strategy": "prefer_ipv4"
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": ["tproxy-in", "tproxy-udp-in"],
        "action": "route",
        "outbound": "reality-out"
      }
    ]
  }
}
EOF
}

########################################
# service
########################################
setup_exit_service() {
  cat > "$EXIT_SERVICE" <<EOF
[Unit]
Description=Reality Forward Exit
After=network-online.target
Wants=network-online.target

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
  systemctl enable --now reality-fw-exit.service
}

setup_entry_service() {
  cat > "$ENTRY_SERVICE" <<EOF
[Unit]
Description=Reality Forward Entry
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SING_BIN} run -c ${SING_DIR}/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now reality-fw-entry.service
}

########################################
# rebuild
########################################
rebuild_entry_config_and_restart() {
  [[ "$(get_role)" == "entry" ]] || return 0

  local remote_host uuid short_id public_key sni
  remote_host="$(cat "$REMOTE_HOST_FILE" 2>/dev/null || true)"
  uuid="$(cat "$UUID_FILE" 2>/dev/null || true)"
  short_id="$(cat "$SHORT_ID_FILE" 2>/dev/null || true)"
  public_key="$(cat "$PUBKEY_FILE" 2>/dev/null || true)"
  sni="$(get_active_sni)"

  [[ -n "$remote_host" && -n "$uuid" && -n "$short_id" && -n "$public_key" && -n "$sni" ]] || return 1

  write_entry_config "$remote_host" "$uuid" "$short_id" "$public_key" "$sni"
  "$SING_BIN" check -c "${SING_DIR}/config.json"
  systemctl restart reality-fw-entry.service
  apply_current_mode
}

########################################
# 配置出口
########################################
configure_exit() {
  echo "==== 配置为【出口服务器】 ===="
  set_role "exit"
  ensure_dirs
  install_base_packages
  install_singbox
  init_default_sni_list

  local cover_sni uuid short_id keypair private_key public_key exit_pub

  while true; do
    read -rp "Reality 伪装 SNI（默认 itunes.apple.com）: " cover_sni
    cover_sni="$(trim "${cover_sni:-}")"
    cover_sni="${cover_sni:-itunes.apple.com}"
    [[ -n "$cover_sni" ]] && break
  done

  uuid="$(cat /proc/sys/kernel/random/uuid)"
  short_id="$(gen_short_id)"
  keypair="$(${SING_BIN} generate reality-keypair)"
  private_key="$(echo "$keypair" | awk '/PrivateKey/ {print $2}')"
  public_key="$(echo "$keypair" | awk '/PublicKey/ {print $2}')"

  [[ -n "${private_key:-}" && -n "${public_key:-}" ]] || {
    echo "❌ 生成 Reality 密钥失败"
    exit 1
  }

  exit_pub="$(detect_public_ip || true)"
  [[ -n "$exit_pub" ]] && echo "$exit_pub" > "$EXIT_PUBLIC_IP_FILE"

  echo "$cover_sni" > "$ACTIVE_SNI_FILE"
  echo "$uuid" > "$UUID_FILE"
  echo "$short_id" > "$SHORT_ID_FILE"
  echo "$public_key" > "$PUBKEY_FILE"

  write_exit_config "$cover_sni" "$uuid" "$short_id" "$private_key"
  "$SING_BIN" check -c "${SING_DIR}/config.json"
  setup_exit_service

  echo
  echo "====== 出口信息（给入口机）======"
  echo "出口地址: ${exit_pub:-请手动查看公网 IP/域名}"
  echo "UUID: ${uuid}"
  echo "short_id: ${short_id}"
  echo "public_key: ${public_key}"
  echo "SNI: ${cover_sni}"
  echo "================================"
  echo
  echo "✅ 出口已就绪"
  echo "⚠ 说明：出口默认把经过 Reality 的流量转到 127.0.0.1:原端口"
  echo "⚠ 你在出口机本地让 realm/程序监听对应端口即可"
}

########################################
# 配置入口
########################################
configure_entry() {
  echo "==== 配置为【入口服务器】 ===="
  set_role "entry"
  ensure_dirs
  install_base_packages
  install_singbox
  init_default_sni_list

  local remote_host remote_ip uuid short_id public_key sni

  while true; do
    read -rp "出口服务器域名/IP: " remote_host
    remote_host="$(trim "$remote_host")"
    [[ -n "$remote_host" ]] && break
    echo "❌ 不能为空"
  done

  while true; do
    read -rp "UUID: " uuid
    uuid="$(trim "$uuid")"
    [[ -n "$uuid" ]] && break
    echo "❌ 不能为空"
  done

  while true; do
    read -rp "short_id（1-8 位十六进制）: " short_id
    short_id="$(trim "$short_id")"
    if [[ "$short_id" =~ ^[a-fA-F0-9]{1,8}$ ]]; then
      short_id="${short_id,,}"
      break
    fi
    echo "❌ short_id 格式不对"
  done

  while true; do
    read -rp "public_key: " public_key
    public_key="$(trim "$public_key")"
    [[ -n "$public_key" ]] && break
    echo "❌ 不能为空"
  done

  sni="$(get_active_sni)"
  echo "当前 SNI：$sni"

  remote_ip="$(resolve_ipv4 "$remote_host" || true)"
  [[ -z "$remote_ip" ]] && remote_ip="$remote_host"

  echo "$remote_host" > "$REMOTE_HOST_FILE"
  echo "$remote_ip" > "$REMOTE_IP_FILE"
  echo "$uuid" > "$UUID_FILE"
  echo "$short_id" > "$SHORT_ID_FILE"
  echo "$public_key" > "$PUBKEY_FILE"
  echo "$sni" > "$ACTIVE_SNI_FILE"

  write_entry_config "$remote_host" "$uuid" "$short_id" "$public_key" "$sni"
  "$SING_BIN" check -c "${SING_DIR}/config.json"
  setup_entry_service

  set_mode "split"
  apply_current_mode

  echo "✅ 入口已就绪"
  echo "⚠ 分流模式：只接你加入列表的端口（TCP/UDP）"
  echo "⚠ 全局模式：除 22 / 443 / 内部端口外，大多数 TCP/UDP 都会送入 Reality"
}

########################################
# 入口端口管理
########################################
manage_entry_ports() {
  [[ "$(get_role)" == "entry" ]] || { echo "❌ 仅入口可用"; return; }

  while true; do
    echo "---- 入口端口管理 ----"
    echo "1) 查看列表"
    echo "2) 添加端口"
    echo "3) 删除端口"
    echo "0) 返回"
    read -rp "请选择: " sub

    case "$sub" in
      1)
        if [[ -s "$PORT_LIST_FILE" ]]; then
          cat "$PORT_LIST_FILE"
        else
          echo "(空)"
        fi
        ;;
      2)
        read -rp "端口: " p
        p="$(trim "${p:-}")"
        if [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] && [ "$p" -ne 22 ] && [ "$p" -ne 443 ] && [ "$p" -ne "$TPROXY_PORT" ]; then
          add_port_to_list "$p"
          [[ "$(get_mode)" == "split" ]] && apply_split_mode_rules
        else
          echo "❌ 端口无效或为保留端口"
        fi
        ;;
      3)
        read -rp "要删除的端口: " p
        p="$(trim "${p:-}")"
        if [[ "$p" =~ ^[0-9]+$ ]]; then
          remove_port_from_list "$p"
          [[ "$(get_mode)" == "split" ]] && apply_split_mode_rules
        fi
        ;;
      0) break ;;
      *) echo "无效" ;;
    esac
  done
}

########################################
# 模式切换
########################################
manage_entry_mode() {
  [[ "$(get_role)" == "entry" ]] || { echo "❌ 仅入口可用"; return; }

  while true; do
    echo "当前模式：$(get_mode)"
    echo "1) 切换为【全局模式】"
    echo "2) 切换为【端口分流模式】"
    echo "0) 返回"
    read -rp "请选择: " sub

    case "$sub" in
      1) apply_global_mode_rules ;;
      2) apply_split_mode_rules ;;
      0) break ;;
      *) echo "无效" ;;
    esac
  done
}

########################################
# 修改出口地址
########################################
update_remote() {
  [[ "$(get_role)" == "entry" ]] || { echo "❌ 仅入口可用"; return; }

  local new_host new_ip
  while true; do
    read -rp "新出口域名/IP: " new_host
    new_host="$(trim "$new_host")"
    [[ -n "$new_host" ]] && break
    echo "❌ 不能为空"
  done

  new_ip="$(resolve_ipv4 "$new_host" || true)"
  [[ -z "$new_ip" ]] && new_ip="$new_host"

  echo "$new_host" > "$REMOTE_HOST_FILE"
  echo "$new_ip" > "$REMOTE_IP_FILE"

  rebuild_entry_config_and_restart
  echo "✅ 已更新出口地址为 $new_host"
}

########################################
# 状态
########################################
show_status() {
  echo "==== 状态 ===="
  echo "角色：$(get_role)"
  echo "模式：$(get_mode)"
  echo

  if [[ "$(get_role)" == "entry" ]]; then
    [[ -f "$REMOTE_HOST_FILE" ]] && echo "出口地址：$(cat "$REMOTE_HOST_FILE")"
    echo "当前 SNI：$(get_active_sni)"
    echo "tproxy 端口：${TPROXY_PORT}"
    echo
    systemctl --no-pager status reality-fw-entry.service 2>/dev/null | head -n 10 || true
    echo
    ss -lunp 2>/dev/null | grep ":${TPROXY_PORT}\b" || true
    ss -lntp 2>/dev/null | grep ":${TPROXY_PORT}\b" || true
    echo
    echo "==== mangle 规则 ===="
    iptables -t mangle -S "$TPROXY_DIVERT_CHAIN" 2>/dev/null || true
    iptables -t mangle -S "$TPROXY_CHAIN" 2>/dev/null || true
    echo
    echo "==== policy route ===="
    ip rule
    ip route show table "$TPROXY_TABLE"
  elif [[ "$(get_role)" == "exit" ]]; then
    systemctl --no-pager status reality-fw-exit.service 2>/dev/null | head -n 10 || true
    echo
    ss -lntp 2>/dev/null | grep ':443' || true
    [[ -f "$EXIT_PUBLIC_IP_FILE" ]] && echo "检测公网 IP：$(cat "$EXIT_PUBLIC_IP_FILE")"
  else
    echo "未配置"
  fi
}

########################################
# 启停
########################################
start_link() {
  local role
  role="$(get_role)"
  if [[ "$role" == "entry" ]]; then
    systemctl restart reality-fw-entry.service
    apply_current_mode
  elif [[ "$role" == "exit" ]]; then
    systemctl restart reality-fw-exit.service
  else
    echo "❌ 请先配置角色"
  fi
}

stop_link() {
  systemctl stop reality-fw-entry.service reality-fw-exit.service 2>/dev/null || true
  [[ "$(get_role)" == "entry" ]] && { drop_tproxy_chains; clear_policy_route; } || true
}

restart_link() {
  stop_link
  start_link
}

########################################
# 卸载
########################################
uninstall_all() {
  read -rp "确认彻底卸载？(y/N): " confirm
  confirm="$(trim "${confirm:-}")"
  [[ ! "$confirm" =~ ^[yY]$ ]] && return

  systemctl stop reality-fw-entry.service reality-fw-exit.service 2>/dev/null || true
  systemctl disable reality-fw-entry.service reality-fw-exit.service 2>/dev/null || true
  rm -f "$ENTRY_SERVICE" "$EXIT_SERVICE"
  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null || true

  drop_tproxy_chains
  clear_policy_route

  rm -rf "$SING_DIR"
  rm -f "$SING_BIN"

  echo "✅ 已清理 sing-box 与规则"
  echo "⚠ jq / curl / iptables / iproute2 保留"
}

########################################
# 菜单
########################################
while true; do
  echo
  echo "============= Reality TCP/UDP 转发（WG风格） ============="
  echo "1) 配置为 出口服务器"
  echo "2) 配置为 入口服务器"
  echo "3) 查看状态"
  echo "4) 启动"
  echo "5) 停止"
  echo "6) 重启"
  echo "7) 卸载并清理"
  echo "8) 管理入口端口列表"
  echo "9) 管理入口模式（全局 / 分流）"
  echo "10) 修改出口地址"
  echo "11) 管理 SNI（添加/删除/切换）"
  echo "0) 退出"
  echo "=========================================================="
  read -rp "请选择: " choice

  case "$choice" in
    1) configure_exit ;;
    2) configure_entry ;;
    3) show_status ;;
    4) start_link ;;
    5) stop_link ;;
    6) restart_link ;;
    7) uninstall_all ;;
    8) manage_entry_ports ;;
    9) manage_entry_mode ;;
    10) update_remote ;;
    11) choose_sni_menu ;;
    0) exit 0 ;;
    *) echo "无效选项" ;;
  esac
done
