#!/usr/bin/env bash
set -Eeuo pipefail

# WireGuard over VLESS + REALITY relay.
#
# The script deliberately manages only its own files, services and firewall
# chains.  It does not use Nginx, Certbot, WebSocket or another transport.

APP_NAME="wg-reality"
WG_IF="wg0"
WG_DIR="/etc/wireguard"
BASE_DIR="/etc/${APP_NAME}"
STATE_DIR="${BASE_DIR}/state"
XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/lib/${APP_NAME}"
XRAY_FALLBACK_VERSION="25.6.8"
XRAY_VERSION_OVERRIDE="${WG_REALITY_XRAY_VERSION:-}"

WG_CONFIG="${WG_DIR}/${WG_IF}.conf"
WG_MARKER="${WG_DIR}/.${APP_NAME}.managed"
ROLE_FILE="${STATE_DIR}/role"
MODE_FILE="${STATE_DIR}/mode"
XRAY_CONFIG_FILE="${BASE_DIR}/xray.json"
XRAY_ROLE_CONFIG_FILE="${BASE_DIR}/xray-role.json"
XRAY_MANAGED_FILE="${STATE_DIR}/xray_managed"
XRAY_INSTALLED_VERSION_FILE="${STATE_DIR}/xray_version"

WG_PRIVATE_KEY_FILE="${STATE_DIR}/wg_private.key"
WG_PUBLIC_KEY_FILE="${STATE_DIR}/wg_public.key"
PEER_PUBLIC_KEY_FILE="${STATE_DIR}/peer_public.key"
REALITY_PRIVATE_KEY_FILE="${STATE_DIR}/reality_private.key"
REALITY_PUBLIC_KEY_FILE="${STATE_DIR}/reality_public.key"
UUID_FILE="${STATE_DIR}/uuid"
SHORT_ID_FILE="${STATE_DIR}/short_id"
REMOTE_HOST_FILE="${STATE_DIR}/remote_host"
REMOTE_PORT_FILE="${STATE_DIR}/remote_port"
SERVER_NAME_FILE="${STATE_DIR}/server_name"
REALITY_DEST_FILE="${STATE_DIR}/reality_dest"
REALITY_PORT_FILE="${STATE_DIR}/reality_port"
WG_LISTEN_PORT_FILE="${STATE_DIR}/wg_listen_port"
WG_LOCAL_PORT_FILE="${STATE_DIR}/wg_local_port"
WG_ADDRESS_FILE="${STATE_DIR}/wg_address"
PEER_ADDRESS_FILE="${STATE_DIR}/peer_address"
WAN_IF_FILE="${STATE_DIR}/wan_if"

XRAY_ENTRY_SERVICE="wg-reality-entry.service"
XRAY_EXIT_SERVICE="wg-reality-exit.service"
ROUTE_TABLE_ID="51820"
FW_MARK="0x1"
CARRIER_MARK="0x66"
CARRIER_MARK_DEC="102"
CARRIER_RULE_PRIORITY="100"
MANGLE_OUT_CHAIN="WGR_OUT"
MANGLE_PRE_CHAIN="WGR_PRE"
NYANPASS_IN_CHAIN="WG_NYAN_IN"
NYANPASS_OUT_CHAIN="WG_NYAN_OUT"
INPUT_CHAIN="WGR_INPUT"
IP6_INPUT_CHAIN="WGR6_INPUT"
DEFAULT_REALITY_PORT="443"
DEFAULT_WG_LISTEN_PORT="51820"
DEFAULT_WG_LOCAL_PORT="51821"
DEFAULT_EXIT_WG_ADDRESS="10.0.0.1/24"
DEFAULT_ENTRY_WG_ADDRESS="10.0.0.2/24"
DEFAULT_REALITY_SNI="www.epicgames.com"
DEFAULT_REALITY_DEST="www.epicgames.com:443"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  printf '请使用 root 运行：sudo bash %s\n' "$0" >&2
  exit 1
fi

print_block() {
  printf '\n==================================================\n%s\n==================================================\n' "$1"
}

info() { printf '[信息] %s\n' "$*"; }
ok() { printf '[完成] %s\n' "$*"; }
warn() { printf '[注意] %s\n' "$*" >&2; }
err() { printf '[错误] %s\n' "$*" >&2; }
print_step() { printf '[%s] %s\n' "$1" "$2"; }
print_ok() { printf '✅ %s\n' "$*"; }
print_warn() { printf '⚠️  %s\n' "$*" >&2; }
print_err() { printf '❌ %s\n' "$*" >&2; }

ensure_dirs() {
  install -d -m 700 "$BASE_DIR" "$STATE_DIR" "$XRAY_DIR" "$WG_DIR"
}

write_value() {
  local file="$1" value="$2"
  ensure_dirs
  printf '%s\n' "$value" > "$file"
  chmod 600 "$file" 2>/dev/null || true
}

read_value() {
  local file="$1"
  [[ -s "$file" ]] && tr -d '\r\n' < "$file" || true
}

role() { read_value "$ROLE_FILE"; }
get_role() { role; }
set_role() { write_value "$ROLE_FILE" "$1"; }
mode() {
  local value
  value="$(read_value "$MODE_FILE")"
  printf '%s\n' "${value:-split}"
}

valid_port() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

valid_wg_key() {
  [[ "${1:-}" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

valid_uuid() { [[ "${1:-}" =~ ^[0-9a-fA-F-]{36}$ ]]; }
valid_short_id() { [[ "${1:-}" =~ ^[0-9a-fA-F]{2,32}$ && $(( ${#1} % 2 )) -eq 0 ]]; }
valid_host() { [[ "${1:-}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; }
valid_reality_dest() {
  [[ "${1:-}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?:[0-9]{1,5}$ ]] || return 1
  valid_port "${1##*:}"
}

select_reality_target() {
  local source choice custom_sni custom_dest
  REALITY_PROMPT_SNI=""
  REALITY_PROMPT_DEST=""

  while true; do
    read -rp "Reality 伪装目标使用脚本推荐还是自己填写？[1=脚本推荐，2=自己填写，默认 1]: " source
    source="${source:-1}"
    case "$source" in
      1) break ;;
      2)
        read -rp "自定义 Reality SNI: " custom_sni
        read -rp "自定义 Reality 目标 (host:port): " custom_dest
        if valid_host "$custom_sni" && valid_reality_dest "$custom_dest"; then
          REALITY_PROMPT_SNI="$custom_sni"
          REALITY_PROMPT_DEST="$custom_dest"
          return 0
        fi
        print_err "SNI 或目标格式无效，请重新填写"
        ;;
      *) print_err "请输入 1 或 2" ;;
    esac
  done

  print_block "Reality 推荐伪装目标"
  echo "1) www.epicgames.com  (Epic 游戏商城)"
  echo "2) www.nvidia.com     (NVIDIA 官网)"
  echo "3) www.amd.com        (AMD 官网)"
  echo "4) www.speedtest.net  (全球测速网)"
  echo "5) 手动填写 SNI 和目标"
  while true; do
    read -rp "请选择 [1-5，回车默认 1]: " choice
    choice="${choice:-1}"
    case "$choice" in
      1) REALITY_PROMPT_SNI="$DEFAULT_REALITY_SNI"; REALITY_PROMPT_DEST="$DEFAULT_REALITY_DEST"; return 0 ;;
      2) REALITY_PROMPT_SNI="www.nvidia.com"; REALITY_PROMPT_DEST="www.nvidia.com:443"; return 0 ;;
      3) REALITY_PROMPT_SNI="www.amd.com"; REALITY_PROMPT_DEST="www.amd.com:443"; return 0 ;;
      4) REALITY_PROMPT_SNI="www.speedtest.net"; REALITY_PROMPT_DEST="www.speedtest.net:443"; return 0 ;;
      5)
        read -rp "自定义 Reality SNI: " custom_sni
        read -rp "自定义 Reality 目标 (host:port): " custom_dest
        if valid_host "$custom_sni" && valid_reality_dest "$custom_dest"; then
          REALITY_PROMPT_SNI="$custom_sni"
          REALITY_PROMPT_DEST="$custom_dest"
          return 0
        fi
        print_err "SNI 或目标格式无效，请重新填写"
        ;;
      *) print_err "请选择 1-5" ;;
    esac
  done
}

test_reality_target() {
  local sni="$1" dest="$2" output
  command -v openssl >/dev/null 2>&1 || { print_warn "缺少 openssl，跳过 Reality 目标预检"; return 0; }
  command -v timeout >/dev/null 2>&1 || { print_warn "缺少 timeout，跳过 Reality 目标预检"; return 0; }
  print_step "预检" "测试 ${dest} 的 TLS 1.3 与 SNI ${sni}..."
  output="$(timeout 10 openssl s_client -connect "$dest" -servername "$sni" -tls1_3 -verify_hostname "$sni" -verify_return_error -brief </dev/null 2>&1 || true)"
  if grep -Eqi 'TLSv1\.3|Protocol version:[[:space:]]*TLSv1\.3' <<< "$output" && grep -Eqi 'Verification:[[:space:]]*OK|Verify return code:[[:space:]]*0' <<< "$output"; then
    print_ok "Reality 伪装目标 TLS 1.3 预检通过"
    return 0
  fi
  print_warn "Reality 伪装目标预检失败：出口机无法确认 ${dest} 的 TLS 1.3 握手"
  return 1
}

network_cidr() {
  local cidr="$1" address prefix a b c d
  address="${cidr%%/*}"; prefix="${cidr##*/}"
  [[ "$address" != "$cidr" && "$prefix" =~ ^[0-9]+$ ]] || { printf '%s\n' "$cidr"; return 0; }
  IFS=. read -r a b c d <<< "$address"
  case "$prefix" in
    8) printf '%s.0.0.0/8\n' "$a" ;;
    16) printf '%s.%s.0.0/16\n' "$a" "$b" ;;
    24) printf '%s.%s.%s.0/24\n' "$a" "$b" "$c" ;;
    32) printf '%s/32\n' "$address" ;;
    *) printf '%s\n' "$cidr" ;;
  esac
}

normalize_pathless_host() {
  local value="${1:-}"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  printf '%s\n' "$value"
}

get_wan_if() {
  local value
  value="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
  printf '%s\n' "${value:-eth0}"
}

get_gateway() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}' || true
}

resolve_ipv4s() {
  local host="$1"
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    printf '%s\n' "$host"
  else
    getent ahostsv4 "$host" 2>/dev/null | awk '!seen[$1]++ {print $1}' || true
  fi
}

policy_rule_exists() {
  local wanted_mark="$1" wanted_table="$2" wanted_priority="${3:-}"
  ip rule show 2>/dev/null | awk \
    -v wanted_mark="$wanted_mark" \
    -v wanted_table="$wanted_table" \
    -v wanted_priority="$wanted_priority" '
      {
        priority = $1
        sub(/:$/, "", priority)
        if (wanted_priority != "" && priority != wanted_priority) next
        mark_ok = 0
        table_ok = 0
        for (i = 1; i <= NF; i++) {
          if ($i == "fwmark" && i < NF) {
            split($(i + 1), mark_parts, "/")
            if (tolower(mark_parts[1]) == tolower(wanted_mark)) mark_ok = 1
          }
          if (($i == "lookup" || $i == "table") && i < NF && $(i + 1) == wanted_table) table_ok = 1
        }
        if (mark_ok && table_ok) found = 1
      }
      END { exit(found ? 0 : 1) }
    '
}

carrier_policy_rule_exists() {
  policy_rule_exists "$CARRIER_MARK" main "$CARRIER_RULE_PRIORITY"
}

fw_policy_rule_exists() {
  policy_rule_exists "$FW_MARK" "$ROUTE_TABLE_ID"
}

ensure_carrier_policy_rule() {
  carrier_policy_rule_exists && return 0
  if ip rule show 2>/dev/null | awk -v wanted="${CARRIER_RULE_PRIORITY}:" '$1 == wanted {found = 1} END {exit(found ? 0 : 1)}'; then
    err "ip rule 优先级 ${CARRIER_RULE_PRIORITY} 已被其他规则占用，无法保护 Reality 载体连接"
    return 1
  fi
  ip rule add priority "$CARRIER_RULE_PRIORITY" fwmark "$CARRIER_MARK" table main 2>/dev/null || true
  carrier_policy_rule_exists || { err 'Reality 载体 main 路由规则创建失败'; return 1; }
}

clear_carrier_policy_rule() {
  while carrier_policy_rule_exists; do
    ip rule del priority "$CARRIER_RULE_PRIORITY" fwmark "$CARRIER_MARK" table main 2>/dev/null || break
  done
}

ensure_ip_forward() {
  printf '1\n' > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  if [[ -f /etc/sysctl.conf ]] && ! grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*1[[:space:]]*$' /etc/sysctl.conf; then
    printf '\n# %s\nnet.ipv4.ip_forward=1\n' "$APP_NAME" >> /etc/sysctl.conf
  fi
  sysctl -p >/dev/null 2>&1 || true
}

install_packages() {
  command -v apt-get >/dev/null 2>&1 || { err '仅支持 Debian/Ubuntu 的 apt-get 系统'; return 1; }
  export DEBIAN_FRONTEND=noninteractive
  info '安装基础依赖...'
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y curl ca-certificates openssl unzip iproute2 iptables wireguard-tools >/dev/null 2>&1
}

get_xray_version() {
  local binary="${1:-$XRAY_BIN}"
  [[ -x "$binary" ]] || return 0
  "$binary" version 2>/dev/null | awk 'NR == 1 && $1 == "Xray" {print $2; exit}' || true
}

get_latest_xray_version() {
  local tag latest_url
  tag="$(curl -fsSL --connect-timeout 10 --max-time 20 \
    'https://api.github.com/repos/XTLS/Xray-core/releases/latest' 2>/dev/null \
    | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n1 || true)"
  if [[ -z "$tag" ]]; then
    latest_url="$(curl -fsSIL --connect-timeout 10 --max-time 20 -o /dev/null \
      -w '%{url_effective}' 'https://github.com/XTLS/Xray-core/releases/latest' 2>/dev/null || true)"
    tag="${latest_url##*/}"
  fi
  tag="${tag#v}"
  if [[ "$tag" =~ ^[0-9][0-9A-Za-z.-]*$ ]]; then
    printf '%s\n' "$tag"
  fi
  return 0
}

install_xray() {
  local arch asset version installed_version url tmpdir expected_hash candidate candidate_version backup=''
  installed_version="$(get_xray_version "$XRAY_BIN")"

  if [[ -x "$XRAY_BIN" && ! -f "$XRAY_MANAGED_FILE" ]]; then
    info "检测到现有 Xray ${installed_version:-未知版本}，不是本脚本安装，保持不变。"
    return 0
  fi

  if [[ -n "$XRAY_VERSION_OVERRIDE" ]]; then
    version="${XRAY_VERSION_OVERRIDE#v}"
    [[ "$version" =~ ^[0-9][0-9A-Za-z.-]*$ ]] || {
      err 'WG_REALITY_XRAY_VERSION 格式无效'
      return 1
    }
  else
    version="$(get_latest_xray_version)"
    if [[ -z "$version" && -x "$XRAY_BIN" ]]; then
      warn "无法查询 Xray 最新版本，继续使用现有版本 ${installed_version:-未知}。"
      return 0
    fi
    if [[ -z "$version" ]]; then
      version="$XRAY_FALLBACK_VERSION"
      warn "无法查询 Xray 最新版本，首次安装回退到 ${version}。"
    fi
  fi

  if [[ -x "$XRAY_BIN" && "$installed_version" == "$version" ]]; then
    write_value "$XRAY_INSTALLED_VERSION_FILE" "$version"
    info "Xray ${version} 已是目标版本。"
    return 0
  fi

  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset='Xray-linux-64.zip' ;;
    aarch64|arm64) asset='Xray-linux-arm64-v8a.zip' ;;
    armv7l|armv7) asset='Xray-linux-arm32-v7a.zip' ;;
    armv6l) asset='Xray-linux-arm32-v6.zip' ;;
    *) err "不支持的 CPU 架构: $arch"; return 1 ;;
  esac

  command -v sha256sum >/dev/null 2>&1 || { err '缺少 sha256sum，无法验证 Xray'; return 1; }
  tmpdir="$(mktemp -d)"
  url="https://github.com/XTLS/Xray-core/releases/download/v${version}"
  info "下载并验证 Xray ${version}..."

  if ! curl -fsSL --connect-timeout 15 --max-time 180 "${url}/${asset}" -o "${tmpdir}/${asset}"; then
    rm -rf "$tmpdir"
    err "Xray 安装包下载失败: ${asset}"
    return 1
  fi
  if ! curl -fsSL --connect-timeout 15 --max-time 60 "${url}/${asset}.dgst" -o "${tmpdir}/${asset}.dgst"; then
    rm -rf "$tmpdir"
    err 'Xray 官方 SHA-256 校验文件下载失败，已停止安装'
    return 1
  fi

  expected_hash="$(tr -d '\r' < "${tmpdir}/${asset}.dgst" | awk -F'=[[:space:]]*' '$1 == "SHA2-256" {print tolower($2); exit}')"
  if [[ ! "$expected_hash" =~ ^[0-9a-f]{64}$ ]]; then
    rm -rf "$tmpdir"
    err 'Xray 官方校验文件格式异常，已停止安装'
    return 1
  fi
  if ! (cd "$tmpdir" && printf '%s  %s\n' "$expected_hash" "$asset" | sha256sum -c - >/dev/null); then
    rm -rf "$tmpdir"
    err 'Xray 安装包 SHA-256 校验失败，已停止安装'
    return 1
  fi

  if ! unzip -oq "${tmpdir}/${asset}" -d "${tmpdir}/unpacked"; then
    rm -rf "$tmpdir"
    err 'Xray 安装包解压失败'
    return 1
  fi
  candidate="${tmpdir}/unpacked/xray"
  candidate_version="$(get_xray_version "$candidate")"
  if [[ ! -x "$candidate" ]] || [[ "$candidate_version" != "$version" ]]; then
    rm -rf "$tmpdir"
    err "Xray 候选二进制版本自检失败（期望 ${version}，实际 ${candidate_version:-未知}）"
    return 1
  fi

  install -d -m 755 "$XRAY_DIR"
  if [[ -x "$XRAY_BIN" ]]; then
    backup="${tmpdir}/xray.backup"
    cp -p "$XRAY_BIN" "$backup"
  fi
  if ! install -m 0755 "$candidate" "${XRAY_BIN}.new" || ! mv -f "${XRAY_BIN}.new" "$XRAY_BIN" || [[ "$(get_xray_version "$XRAY_BIN")" != "$version" ]]; then
    rm -f "${XRAY_BIN}.new"
    if [[ -n "$backup" && -x "$backup" ]]; then
      install -m 0755 "$backup" "$XRAY_BIN"
    else
      rm -f "$XRAY_BIN"
    fi
    rm -rf "$tmpdir"
    err 'Xray 替换后自检失败，已恢复原二进制'
    return 1
  fi

  write_value "$XRAY_MANAGED_FILE" yes
  write_value "$XRAY_INSTALLED_VERSION_FILE" "$version"
  rm -rf "$tmpdir"
  ok "Xray ${version} 安装并校验完成"
}

generate_wg_identity() {
  local private public
  if [[ -s "$WG_PRIVATE_KEY_FILE" && -s "$WG_PUBLIC_KEY_FILE" ]]; then
    return 0
  fi
  private="$(wg genkey)"
  public="$(printf '%s\n' "$private" | wg pubkey)"
  valid_wg_key "$private" && valid_wg_key "$public" || { err 'WireGuard 密钥生成失败'; return 1; }
  write_value "$WG_PRIVATE_KEY_FILE" "$private"
  write_value "$WG_PUBLIC_KEY_FILE" "$public"
}

ensure_local_wg_identity() {
  local role_label="$1" supplied_private private_key public_key old_public
  old_public="$(read_value "$WG_PUBLIC_KEY_FILE")"
  while true; do
    if [[ -s "$WG_PRIVATE_KEY_FILE" ]]; then
      read -rsp "自定义${role_label} WireGuard 私钥（可选；回车复用现有）: " supplied_private
    else
      read -rsp "自定义${role_label} WireGuard 私钥（可选；回车自动生成）: " supplied_private
    fi
    echo
    if [[ -n "$supplied_private" ]]; then
      private_key="$supplied_private"
    elif [[ -s "$WG_PRIVATE_KEY_FILE" ]]; then
      private_key="$(read_value "$WG_PRIVATE_KEY_FILE")"
    else
      private_key="$(wg genkey)"
    fi
    public_key="$(printf '%s\n' "$private_key" | wg pubkey 2>/dev/null || true)"
    if valid_wg_key "$private_key" && valid_wg_key "$public_key"; then
      write_value "$WG_PRIVATE_KEY_FILE" "$private_key"
      write_value "$WG_PUBLIC_KEY_FILE" "$public_key"
      if [[ -n "$old_public" && "$old_public" != "$public_key" ]]; then
        print_warn "本机 WireGuard 公钥已改变，必须在对端更新为新公钥"
      fi
      return 0
    fi
    print_err "WireGuard 私钥无效，请重新输入"
    supplied_private=""
  done
}

prompt_peer_public_key() {
  local peer_label="$1" key_file="$2" saved_key supplied_key peer_key
  saved_key="$(read_value "$key_file")"
  while true; do
    if [[ -n "$saved_key" ]]; then
      read -rp "请输入【${peer_label}公钥】（回车复用已保存公钥）: " supplied_key
      peer_key="${supplied_key:-$saved_key}"
    else
      read -rp "请输入【${peer_label}公钥】: " peer_key
    fi
    if valid_wg_key "$peer_key"; then
      write_value "$key_file" "$peer_key"
      return 0
    fi
    print_err "公钥格式无效，请输入完整的 WireGuard 公钥"
    saved_key=""
  done
}

generate_reality_identity() {
  local output private public
  if [[ -s "$REALITY_PRIVATE_KEY_FILE" && -s "$REALITY_PUBLIC_KEY_FILE" ]]; then
    return 0
  fi
  output="$($XRAY_BIN x25519 2>/dev/null || true)"
  private="$(printf '%s\n' "$output" | awk -F': *' 'tolower($1) ~ /private/ {print $2; exit}')"
  public="$(printf '%s\n' "$output" | awk -F': *' 'tolower($1) ~ /public/ {print $2; exit}')"
  [[ -n "$private" && -n "$public" ]] || { err 'Xray x25519 密钥生成失败'; return 1; }
  write_value "$REALITY_PRIVATE_KEY_FILE" "$private"
  write_value "$REALITY_PUBLIC_KEY_FILE" "$public"
}

generate_uuid_and_short_id() {
  local uuid short_id
  if [[ ! -s "$UUID_FILE" ]]; then
    uuid="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"
    valid_uuid "$uuid" || { err 'UUID 生成失败'; return 1; }
    write_value "$UUID_FILE" "$uuid"
  fi
  if [[ ! -s "$SHORT_ID_FILE" ]]; then
    short_id="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    valid_short_id "$short_id" || { err 'Short ID 生成失败'; return 1; }
    write_value "$SHORT_ID_FILE" "$short_id"
  fi
}

ensure_wg_conf_is_owned() {
  if [[ -e "$WG_CONFIG" && ! -e "$WG_MARKER" ]]; then
    err "检测到未由本脚本管理的 ${WG_CONFIG}，为避免覆盖现有 WireGuard 配置，已停止。"
    return 1
  fi
  touch "$WG_MARKER"
  chmod 600 "$WG_MARKER"
}

write_exit_wg_config() {
  local exit_addr entry_addr entry_pub wan_if wg_port private peer_network
  exit_addr="$(read_value "$WG_ADDRESS_FILE")"
  entry_addr="$(read_value "$PEER_ADDRESS_FILE")"
  entry_pub="$(read_value "$PEER_PUBLIC_KEY_FILE")"
  wan_if="$(read_value "$WAN_IF_FILE")"
  wg_port="$(read_value "$WG_LISTEN_PORT_FILE")"
  private="$(read_value "$WG_PRIVATE_KEY_FILE")"
  peer_network="$(network_cidr "$entry_addr")"

  ensure_wg_conf_is_owned
  {
    printf '[Interface]\nAddress = %s\nListenPort = %s\nPrivateKey = %s\nMTU = 1280\n' "$exit_addr" "$wg_port" "$private"
    printf 'PostUp = iptables -A FORWARD -i %s -o %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT; iptables -A FORWARD -i %s -o %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n' "$WG_IF" "$wan_if" "$wan_if" "$WG_IF" "$peer_network" "$wan_if"
    printf 'PostDown = iptables -D FORWARD -i %s -o %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i %s -o %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true\n' "$WG_IF" "$wan_if" "$wan_if" "$WG_IF" "$peer_network" "$wan_if"
    if [[ -n "$entry_pub" ]]; then
      printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' "$entry_pub" "${entry_addr%%/*}"
    fi
  } > "$WG_CONFIG"
  chmod 600 "$WG_CONFIG"
}

write_entry_wg_config() {
  local entry_addr exit_addr exit_pub local_port private
  entry_addr="$(read_value "$WG_ADDRESS_FILE")"
  exit_addr="$(read_value "$PEER_ADDRESS_FILE")"
  exit_pub="$(read_value "$PEER_PUBLIC_KEY_FILE")"
  local_port="$(read_value "$WG_LOCAL_PORT_FILE")"
  private="$(read_value "$WG_PRIVATE_KEY_FILE")"

  ensure_wg_conf_is_owned
  {
    printf '[Interface]\nAddress = %s\nPrivateKey = %s\nTable = off\nMTU = 1280\n' "$entry_addr" "$private"
    printf 'PostUp = ip rule add priority %s fwmark %s table main 2>/dev/null || true; ip rule add fwmark %s table %s 2>/dev/null || true; ip route replace default dev %s table %s; ip route replace %s dev %s table %s; ' "$CARRIER_RULE_PRIORITY" "$CARRIER_MARK" "$FW_MARK" "$ROUTE_TABLE_ID" "$WG_IF" "$ROUTE_TABLE_ID" "${exit_addr%%/*}" "$WG_IF" "$ROUTE_TABLE_ID"
    printf 'iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n' "$WG_IF" "$WG_IF"
    printf 'PostDown = ip rule del priority %s fwmark %s table main 2>/dev/null || true; ip rule del fwmark %s table %s 2>/dev/null || true; ip route flush table %s 2>/dev/null || true; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true\n' "$CARRIER_RULE_PRIORITY" "$CARRIER_MARK" "$FW_MARK" "$ROUTE_TABLE_ID" "$ROUTE_TABLE_ID" "$WG_IF"
    printf '\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%s\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 20\n' "$exit_pub" "$local_port"
  } > "$WG_CONFIG"
  chmod 600 "$WG_CONFIG"
}

write_exit_xray_config() {
  local port uuid private dest server_name short_id wg_port
  port="$(read_value "$REALITY_PORT_FILE")"; uuid="$(read_value "$UUID_FILE")"
  private="$(read_value "$REALITY_PRIVATE_KEY_FILE")"; dest="$(read_value "$REALITY_DEST_FILE")"
  server_name="$(read_value "$SERVER_NAME_FILE")"; short_id="$(read_value "$SHORT_ID_FILE")"
  wg_port="$(read_value "$WG_LISTEN_PORT_FILE")"
  cat > "$XRAY_ROLE_CONFIG_FILE" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "reality-in",
    "listen": "0.0.0.0",
    "port": ${port},
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "${uuid}", "flow": "xtls-rprx-vision", "email": "wg-reality"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "${dest}",
        "xver": 0,
        "serverNames": ["${server_name}"],
        "privateKey": "${private}",
        "shortIds": ["${short_id}"]
      }
    },
    "packetEncoding": "xudp"
  }],
  "outbounds": [
    {"tag": "to-wg", "protocol": "freedom", "settings": {"domainStrategy": "AsIs", "redirect": "127.0.0.1:${wg_port:-$DEFAULT_WG_LISTEN_PORT}"}},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["reality-in"], "outboundTag": "to-wg"}]}
}
EOF
}

write_entry_xray_config() {
  local host port uuid public_key short_id server_name local_port wg_port
  host="$(read_value "$REMOTE_HOST_FILE")"; port="$(read_value "$REMOTE_PORT_FILE")"
  uuid="$(read_value "$UUID_FILE")"; public_key="$(read_value "$REALITY_PUBLIC_KEY_FILE")"
  short_id="$(read_value "$SHORT_ID_FILE")"; server_name="$(read_value "$SERVER_NAME_FILE")"
  local_port="$(read_value "$WG_LOCAL_PORT_FILE")"
  wg_port="$(read_value "$WG_LISTEN_PORT_FILE")"
  cat > "$XRAY_ROLE_CONFIG_FILE" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "tag": "wg-udp-in",
    "listen": "127.0.0.1",
    "port": ${local_port},
    "protocol": "dokodemo-door",
    "settings": {"address": "127.0.0.1", "port": ${wg_port:-$DEFAULT_WG_LISTEN_PORT}, "network": "udp", "followRedirect": false}
  }],
  "outbounds": [{
    "tag": "reality-out",
    "protocol": "vless",
    "settings": {
      "vnext": [{"address": "${host}", "port": ${port}, "users": [{"id": "${uuid}", "encryption": "none", "flow": "xtls-rprx-vision"}]}]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {"serverName": "${server_name}", "publicKey": "${public_key}", "shortId": "${short_id}", "fingerprint": "chrome", "spiderX": "/"},
      "sockopt": {"mark": ${CARRIER_MARK_DEC}, "tcpFastOpen": true}
    },
    "packetEncoding": "xudp"
  }],
  "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["wg-udp-in"], "outboundTag": "reality-out"}]}
}
EOF
}

write_service() {
  local service="$1"
  cat > "/etc/systemd/system/${service}" <<EOF
[Unit]
Description=WireGuard over VLESS REALITY (${service})
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${XRAY_BIN} run -config ${XRAY_ROLE_CONFIG_FILE}
Restart=always
RestartSec=2
User=root
LimitNOFILE=1048576
UMask=0077
TimeoutStopSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$service" >/dev/null 2>&1 || true
}

test_xray_config() {
  "$XRAY_BIN" run -test -config "$XRAY_ROLE_CONFIG_FILE"
}

restart_service() {
  local service="$1"
  systemctl daemon-reload
  systemctl enable "$service" >/dev/null 2>&1 || true
  systemctl restart "$service"
}

start_wg() {
  local current_role current_mode
  current_role="$(get_role)"
  print_block "⏳ 正在启动"
  ensure_ip_forward
  if [[ "$current_role" == exit ]]; then
    setup_host_firewall
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    wg-quick up "$WG_IF" 2>/dev/null || true
    systemctl restart "$XRAY_EXIT_SERVICE" 2>/dev/null || true
    print_ok "出口已启动"
  elif [[ "$current_role" == entry ]]; then
    setup_host_firewall
    systemctl restart "$XRAY_ENTRY_SERVICE" 2>/dev/null || true
    systemctl enable "wg-quick@${WG_IF}.service" >/dev/null 2>&1 || true
    wg-quick up "$WG_IF" 2>/dev/null || true
    current_mode="$(get_current_mode)"
    case "$current_mode" in
      global) enable_global_mode ;;
      nyanpass) enable_nyanpass_mode ;;
      *) enable_split_mode ;;
    esac
    print_ok "入口已启动"
  else
    print_err "还未配置角色"
  fi
}

stop_wg() {
  local current_role
  current_role="$(get_role)"
  print_block "⏳ 正在停止"
  if [[ "$current_role" == exit ]]; then
    systemctl stop "$XRAY_EXIT_SERVICE" 2>/dev/null || true
  elif [[ "$current_role" == entry ]]; then
    systemctl stop "$XRAY_ENTRY_SERVICE" 2>/dev/null || true
  fi
  clear_script_nyanpass_routing_rules
  clear_script_owned_entry_forward_rules
  clear_legacy_output_rules
  clear_host_firewall
  wg-quick down "$WG_IF" 2>/dev/null || true
  ip route flush table "$ROUTE_TABLE_ID" 2>/dev/null || true
  ip rule del fwmark "$FW_MARK" table "$ROUTE_TABLE_ID" 2>/dev/null || true
  clear_carrier_policy_rule
  print_ok "已停止"
}

restart_wg() {
  print_block "⏳ 正在重启"
  stop_wg
  start_wg
  print_ok "重启完成"
}

get_current_mode() { mode; }
set_mode_flag() { write_value "$MODE_FILE" "$1"; }
get_mode_label() {
  case "${1:-$(get_current_mode)}" in
    global) printf '全局模式\n' ;;
    split) printf '分流模式\n' ;;
    nyanpass) printf 'NyanPass 转发模式\n' ;;
    *) printf '未知模式\n' ;;
  esac
}

setup_mangle_chain() {
  local chain="$1" hook="$2"
  iptables -t mangle -N "$chain" 2>/dev/null || true
  iptables -t mangle -F "$chain"
  iptables -t mangle -C "$hook" -j "$chain" 2>/dev/null || iptables -t mangle -I "$hook" 1 -j "$chain"
}

clear_mangle_chains() {
  local chain hook
  for chain in "$MANGLE_OUT_CHAIN" "$MANGLE_PRE_CHAIN"; do
    for hook in OUTPUT PREROUTING; do
      while iptables -t mangle -C "$hook" -j "$chain" 2>/dev/null; do
        iptables -t mangle -D "$hook" -j "$chain" >/dev/null 2>&1 || true
      done
    done
    iptables -t mangle -F "$chain" >/dev/null 2>&1 || true
    iptables -t mangle -X "$chain" >/dev/null 2>&1 || true
  done
}

clear_host_firewall() {
  while iptables -C INPUT -j "$INPUT_CHAIN" 2>/dev/null; do
    iptables -D INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
  done
  iptables -F "$INPUT_CHAIN" 2>/dev/null || true
  iptables -X "$INPUT_CHAIN" 2>/dev/null || true
  if command -v ip6tables >/dev/null 2>&1; then
    while ip6tables -C INPUT -j "$IP6_INPUT_CHAIN" 2>/dev/null; do
      ip6tables -D INPUT -j "$IP6_INPUT_CHAIN" 2>/dev/null || true
    done
    ip6tables -F "$IP6_INPUT_CHAIN" 2>/dev/null || true
    ip6tables -X "$IP6_INPUT_CHAIN" 2>/dev/null || true
  fi
}

setup_host_firewall() {
  local current_role reality_port wg_port local_port
  current_role="$(get_role)"
  reality_port="$(read_value "$REALITY_PORT_FILE")"
  wg_port="$(read_value "$WG_LISTEN_PORT_FILE")"
  local_port="$(read_value "$WG_LOCAL_PORT_FILE")"

  clear_host_firewall
  iptables -N "$INPUT_CHAIN"
  iptables -A "$INPUT_CHAIN" -i lo -j ACCEPT
  iptables -A "$INPUT_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  if [[ "$current_role" == exit ]]; then
    [[ -n "$reality_port" ]] && iptables -A "$INPUT_CHAIN" -p tcp --dport "$reality_port" -j ACCEPT
    [[ -n "$wg_port" ]] && iptables -A "$INPUT_CHAIN" ! -i lo -p udp --dport "$wg_port" -j DROP
  elif [[ "$current_role" == entry ]]; then
    [[ -n "$local_port" ]] && iptables -A "$INPUT_CHAIN" ! -i lo -p udp --dport "$local_port" -j DROP
    [[ -n "$wg_port" ]] && iptables -A "$INPUT_CHAIN" ! -i lo -p udp --dport "$wg_port" -j DROP
  fi

  iptables -A "$INPUT_CHAIN" -j RETURN
  iptables -I INPUT 1 -j "$INPUT_CHAIN"

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N "$IP6_INPUT_CHAIN"
    ip6tables -A "$IP6_INPUT_CHAIN" -i lo -j ACCEPT
    ip6tables -A "$IP6_INPUT_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    if [[ "$current_role" == exit && -n "$wg_port" ]]; then
      ip6tables -A "$IP6_INPUT_CHAIN" ! -i lo -p udp --dport "$wg_port" -j DROP
    elif [[ "$current_role" == entry ]]; then
      [[ -n "$local_port" ]] && ip6tables -A "$IP6_INPUT_CHAIN" ! -i lo -p udp --dport "$local_port" -j DROP
      [[ -n "$wg_port" ]] && ip6tables -A "$IP6_INPUT_CHAIN" ! -i lo -p udp --dport "$wg_port" -j DROP
    fi
    ip6tables -A "$IP6_INPUT_CHAIN" -j RETURN
    ip6tables -I INPUT 1 -j "$IP6_INPUT_CHAIN"
  fi
}

clear_entry_forward_rules() {
  local wan_if exit_ip port
  [[ "$(role)" == entry ]] || return 0
  wan_if="$(read_value "$WAN_IF_FILE")"
  exit_ip="$(read_value "$PEER_ADDRESS_FILE")"
  exit_ip="${exit_ip%%/*}"
  [[ -n "$wan_if" && -n "$exit_ip" ]] || return 0

  if [[ -f "${STATE_DIR}/ports" ]]; then
    while read -r port; do
      [[ "$port" =~ ^[0-9]+$ ]] || continue
      iptables -t nat -D PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
      iptables -D FORWARD -i "$wan_if" -o "$WG_IF" -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -i "$WG_IF" -o "$wan_if" -p tcp --sport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
      iptables -t nat -D PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
      iptables -D FORWARD -i "$wan_if" -o "$WG_IF" -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -i "$WG_IF" -o "$wan_if" -p udp --sport "$port" -j ACCEPT 2>/dev/null || true
    done < "${STATE_DIR}/ports"
  fi

  iptables -t nat -D PREROUTING -i "$wan_if" -p tcp ! --dport 22 -j DNAT --to-destination "$exit_ip" 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$wan_if" -p udp ! --dport 22 -j DNAT --to-destination "$exit_ip" 2>/dev/null || true
  iptables -D FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
}

apply_entry_forward_rules() {
  local wan_if exit_ip port
  [[ "$(role)" == entry ]] || return 0
  wan_if="$(read_value "$WAN_IF_FILE")"
  exit_ip="$(read_value "$PEER_ADDRESS_FILE")"
  exit_ip="${exit_ip%%/*}"
  [[ -n "$wan_if" && -n "$exit_ip" ]] || return 0
  clear_entry_forward_rules

  if [[ "$(mode)" == global ]]; then
    iptables -t nat -C PREROUTING -i "$wan_if" -p tcp ! --dport 22 -j DNAT --to-destination "$exit_ip" 2>/dev/null || iptables -t nat -A PREROUTING -i "$wan_if" -p tcp ! --dport 22 -j DNAT --to-destination "$exit_ip"
    iptables -t nat -C PREROUTING -i "$wan_if" -p udp ! --dport 22 -j DNAT --to-destination "$exit_ip" 2>/dev/null || iptables -t nat -A PREROUTING -i "$wan_if" -p udp ! --dport 22 -j DNAT --to-destination "$exit_ip"
    iptables -C FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -C FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE
    return 0
  fi

  [[ -f "${STATE_DIR}/ports" ]] || return 0
  while read -r port; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    [[ "$port" == 22 ]] && continue
    iptables -t nat -C PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || iptables -t nat -A PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}"
    iptables -C FORWARD -i "$wan_if" -o "$WG_IF" -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -C FORWARD -i "$WG_IF" -o "$wan_if" -p tcp --sport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -p tcp --sport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -C PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || iptables -t nat -A PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}"
    iptables -C FORWARD -i "$wan_if" -o "$WG_IF" -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -p udp --dport "$port" -j ACCEPT
    iptables -C FORWARD -i "$WG_IF" -o "$wan_if" -p udp --sport "$port" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -p udp --sport "$port" -j ACCEPT
  done < "${STATE_DIR}/ports"
  iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE
}

ensure_policy_route() {
  if ! ip link show "$WG_IF" >/dev/null 2>&1; then
    warn 'WireGuard 尚未启动，先保存路由模式；启动 WireGuard 后会自动补齐策略路由。'
    return 0
  fi
  ensure_carrier_policy_rule
  if ! fw_policy_rule_exists; then
    ip rule add fwmark "$FW_MARK" table "$ROUTE_TABLE_ID" 2>/dev/null || true
    fw_policy_rule_exists || { err 'WireGuard 策略路由规则创建失败'; return 1; }
  fi
  ip route replace default dev "$WG_IF" table "$ROUTE_TABLE_ID"
  iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE
}

apply_routing_mode() {
  local current="$(role)" wan_if remote_host remote_port remote_ip p
  [[ "$current" == entry ]] || return 0
  if [[ "$(mode)" == nyanpass ]]; then
    enable_nyanpass_mode
    return 0
  fi
  wan_if="$(read_value "$WAN_IF_FILE")"; remote_host="$(read_value "$REMOTE_HOST_FILE")"; remote_port="$(read_value "$REMOTE_PORT_FILE")"
  ensure_policy_route
  clear_script_nyanpass_routing_rules
  apply_entry_forward_rules
  clear_mangle_chains
  setup_mangle_chain "$MANGLE_OUT_CHAIN" OUTPUT
  setup_mangle_chain "$MANGLE_PRE_CHAIN" PREROUTING

  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -o lo -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p tcp --dport 22 -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p udp --dport 53 -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p tcp --dport 53 -j RETURN
  while read -r remote_ip; do
    [[ -n "$remote_ip" ]] || continue
    iptables -t mangle -A "$MANGLE_OUT_CHAIN" -d "${remote_ip}/32" -p tcp --dport "$remote_port" -j RETURN
  done < <(resolve_ipv4s "$remote_host")

  if [[ "$(mode)" == global ]]; then
    iptables -t mangle -A "$MANGLE_OUT_CHAIN" -j MARK --set-mark "$FW_MARK"
    iptables -t mangle -A "$MANGLE_PRE_CHAIN" -i "$wan_if" -p tcp --dport 22 -j RETURN
    iptables -t mangle -A "$MANGLE_PRE_CHAIN" -i "$wan_if" -j MARK --set-mark "$FW_MARK"
  elif [[ -f "${STATE_DIR}/ports" ]]; then
    while read -r p; do
      [[ "$p" =~ ^[0-9]+$ ]] || continue
      iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p tcp --dport "$p" -j MARK --set-mark "$FW_MARK"
      iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p udp --dport "$p" -j MARK --set-mark "$FW_MARK"
      iptables -t mangle -A "$MANGLE_PRE_CHAIN" -p tcp --dport "$p" -j MARK --set-mark "$FW_MARK"
      iptables -t mangle -A "$MANGLE_PRE_CHAIN" -p udp --dport "$p" -j MARK --set-mark "$FW_MARK"
    done < "${STATE_DIR}/ports"
  fi
  write_value "$MODE_FILE" "$(mode)"
}

set_mode() {
  local requested="${1:-split}"
  [[ "$requested" == global || "$requested" == split ]] || { err '模式只能是 global 或 split'; return 1; }
  write_value "$MODE_FILE" "$requested"
  apply_routing_mode
  ok "已切换到 $( [[ "$requested" == global ]] && printf '全局' || printf '分流' )模式"
}

enable_global_mode() { set_mode global; }
enable_split_mode() { set_mode split; }
enable_nyanpass_mode() {
  local wan_if remote_host remote_port remote_ip dns_ip
  local -a remote_ips=()
  [[ "$(get_role)" == entry ]] || { err '当前机器不是入口服务器'; return 1; }
  wan_if="$(read_value "$WAN_IF_FILE")"
  remote_host="$(read_value "$REMOTE_HOST_FILE")"
  remote_port="$(read_value "$REMOTE_PORT_FILE")"
  [[ -n "$wan_if" && -n "$remote_host" ]] && valid_port "$remote_port" || {
    err 'Reality 远端地址、端口或入口网卡未配置，无法启用 NyanPass 转发模式'
    return 1
  }

  while read -r remote_ip; do
    [[ -n "$remote_ip" ]] && remote_ips+=("$remote_ip")
  done < <(resolve_ipv4s "$remote_host")
  if [[ ${#remote_ips[@]} -eq 0 ]]; then
    err "无法解析 Reality 远端 IPv4: ${remote_host}"
    return 1
  fi

  ensure_policy_route
  clear_entry_forward_rules
  clear_mangle_chains
  clear_script_nyanpass_routing_rules

  iptables -t mangle -N "$NYANPASS_IN_CHAIN" 2>/dev/null || true
  iptables -t mangle -N "$NYANPASS_OUT_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$NYANPASS_IN_CHAIN"
  iptables -t mangle -F "$NYANPASS_OUT_CHAIN"

  # Public inbound connections stay local to NyanPass. Their replies retain
  # connmark 0x2 and therefore continue through the entry server's main route.
  iptables -t mangle -A "$NYANPASS_IN_CHAIN" -i "$wan_if" -m addrtype --dst-type LOCAL -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x2

  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -o lo -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p tcp --sport 22 -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p tcp --dport 22 -j RETURN
  for remote_ip in "${remote_ips[@]}"; do
    iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -d "${remote_ip}/32" -p tcp --dport "$remote_port" -j RETURN
  done
  while read -r dns_ip; do
    [[ "$dns_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
    iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -d "${dns_ip}/32" -p udp --dport 53 -j RETURN
    iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -d "${dns_ip}/32" -p tcp --dport 53 -j RETURN
  done < <(awk '$1 == "nameserver" {print $2}' /etc/resolv.conf 2>/dev/null | sort -u)

  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -j CONNMARK --restore-mark
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark 0x2 -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark "$FW_MARK" -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m conntrack --ctstate NEW -j MARK --set-mark "$FW_MARK"
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark "$FW_MARK" -j CONNMARK --save-mark

  iptables -t mangle -C PREROUTING -j "$NYANPASS_IN_CHAIN" 2>/dev/null || iptables -t mangle -I PREROUTING 1 -j "$NYANPASS_IN_CHAIN"
  iptables -t mangle -C OUTPUT -j "$NYANPASS_OUT_CHAIN" 2>/dev/null || iptables -t mangle -I OUTPUT 1 -j "$NYANPASS_OUT_CHAIN"
  ip link set dev "$WG_IF" mtu 1280 2>/dev/null || true
  write_value "$MODE_FILE" nyanpass
  warn '已建立连接不会自动迁移；请重启 NyanPass 服务或等待连接重新建立。'
}

add_port() {
  local port="$1"
  valid_port "$port" || { err '端口无效'; return 1; }
  touch "${STATE_DIR}/ports"; chmod 600 "${STATE_DIR}/ports"
  grep -qxF "$port" "${STATE_DIR}/ports" || printf '%s\n' "$port" >> "${STATE_DIR}/ports"
  apply_routing_mode
}

add_port_to_list() { add_port "$1"; }
remove_port_from_list() {
  local port="$1"
  remove_port "$port"
}
apply_port_rules_from_file() { apply_routing_mode; }
remove_port_iptables_rules() { apply_routing_mode; }
add_forward_port_mapping() { apply_entry_forward_rules; }
remove_forward_port_mapping() { apply_entry_forward_rules; }
clear_script_owned_entry_forward_rules() { clear_entry_forward_rules; }
clear_script_nyanpass_routing_rules() {
  while iptables -t mangle -C OUTPUT -j "$NYANPASS_OUT_CHAIN" 2>/dev/null; do
    iptables -t mangle -D OUTPUT -j "$NYANPASS_OUT_CHAIN" >/dev/null 2>&1 || true
  done
  while iptables -t mangle -C PREROUTING -j "$NYANPASS_IN_CHAIN" 2>/dev/null; do
    iptables -t mangle -D PREROUTING -j "$NYANPASS_IN_CHAIN" >/dev/null 2>&1 || true
  done
  iptables -t mangle -F "$NYANPASS_OUT_CHAIN" >/dev/null 2>&1 || true
  iptables -t mangle -X "$NYANPASS_OUT_CHAIN" >/dev/null 2>&1 || true
  iptables -t mangle -F "$NYANPASS_IN_CHAIN" >/dev/null 2>&1 || true
  iptables -t mangle -X "$NYANPASS_IN_CHAIN" >/dev/null 2>&1 || true
}
clear_legacy_output_rules() { :; }
clear_mark_rules() { :; }

remove_port() {
  local port="$1" tmp
  [[ -f "${STATE_DIR}/ports" ]] || return 0
  tmp="$(mktemp)"
  awk -v p="$port" '$0 != p' "${STATE_DIR}/ports" > "$tmp"
  install -m 600 "$tmp" "${STATE_DIR}/ports"
  rm -f "$tmp"
  apply_routing_mode
}

base64_encode() { base64 2>/dev/null | tr -d '\r\n'; }
base64_decode() { printf '%s' "$1" | base64 -d 2>/dev/null; }

export_exit_code() {
  local host port sni pub uuid short entry_addr exit_addr wg_port wg_pub dest payload
  host="$(read_value "$REMOTE_HOST_FILE")"; port="$(read_value "$REALITY_PORT_FILE")"
  sni="$(read_value "$SERVER_NAME_FILE")"; pub="$(read_value "$REALITY_PUBLIC_KEY_FILE")"
  uuid="$(read_value "$UUID_FILE")"; short="$(read_value "$SHORT_ID_FILE")"
  entry_addr="$(read_value "$PEER_ADDRESS_FILE")"; exit_addr="$(read_value "$WG_ADDRESS_FILE")"
  wg_port="$(read_value "$WG_LISTEN_PORT_FILE")"; wg_pub="$(read_value "$WG_PUBLIC_KEY_FILE")"
  dest="$(read_value "$REALITY_DEST_FILE")"
  payload="${host}|${port}|${sni}|${pub}|${uuid}|${short}|${entry_addr}|${exit_addr}|${wg_port}|${wg_pub}|${dest}"
  printf 'WGR1:%s\n' "$(printf '%s' "$payload" | base64_encode)"
}

import_exit_code() {
  local code encoded payload host port sni pub uuid short entry_addr exit_addr wg_port exit_wg_pub ignored
  code="${1:-}"
  [[ "$code" == WGR1:* ]] || { err '连接码前缀无效，应为 WGR1:'; return 1; }
  encoded="${code#WGR1:}"
  payload="$(base64_decode "$encoded")" || { err '连接码 Base64 解码失败'; return 1; }
  IFS='|' read -r host port sni pub uuid short entry_addr exit_addr wg_port exit_wg_pub ignored <<< "$payload"
  host="$(normalize_pathless_host "$host")"
  [[ -n "$host" && -n "$sni" && -n "$pub" && -n "$uuid" && -n "$short" ]] || { err '连接码字段不完整'; return 1; }
  valid_host "$host" || { err '连接码中的出口地址无效'; return 1; }
  valid_host "$sni" || { err '连接码中的 SNI 无效'; return 1; }
  valid_port "$port" || { err '连接码中的 Reality 端口无效'; return 1; }
  valid_uuid "$uuid" || { err '连接码中的 UUID 无效'; return 1; }
  valid_short_id "$short" || { err '连接码中的 Short ID 无效'; return 1; }
  valid_wg_key "$exit_wg_pub" || { err '连接码中的出口 WireGuard 公钥无效'; return 1; }
  write_value "$REMOTE_HOST_FILE" "$host"; write_value "$REMOTE_PORT_FILE" "$port"
  write_value "$SERVER_NAME_FILE" "$sni"; write_value "$REALITY_PUBLIC_KEY_FILE" "$pub"
  write_value "$UUID_FILE" "$uuid"; write_value "$SHORT_ID_FILE" "$short"
  write_value "$WG_ADDRESS_FILE" "$entry_addr"; write_value "$PEER_ADDRESS_FILE" "$exit_addr"
  write_value "$WG_LISTEN_PORT_FILE" "$wg_port"; write_value "$PEER_PUBLIC_KEY_FILE" "$exit_wg_pub"; write_value "$WAN_IF_FILE" "$(get_wan_if)"
  ok '已导入出口连接码'
}

configure_exit() {
  set_role "exit"
  ensure_dirs

  print_block "⏳ 开始配置出口服务器"
  install_packages
  install_xray

  print_block "🔑 配置出口 WireGuard 身份"
  echo "回车将自动生成或复用现有私钥"
  ensure_local_wg_identity "出口服务器"
  local exit_public_key entry_public_key
  exit_public_key="$(read_value "$WG_PUBLIC_KEY_FILE")"

  print_block "【出口服务器公钥（配置入口时填写）】"
  echo "$exit_public_key"
  prompt_peer_public_key "入口服务器" "$PEER_PUBLIC_KEY_FILE"
  entry_public_key="$(read_value "$PEER_PUBLIC_KEY_FILE")"

  generate_reality_identity
  generate_uuid_and_short_id
  local host port sni dest wg_addr entry_wg_ip out_if default_if wg_udp_port
  while true; do
    read -rp "出口服务器公网 IP / 域名: " host
    host="$(normalize_pathless_host "${host:-}")"
    if valid_host "$host"; then break; fi
    print_err "出口地址无效"
  done
  read -rp "Reality 对外端口 (默认 443): " port
  port="${port:-443}"
  valid_port "$port" || { print_err "端口不合法"; return 1; }
  while true; do
    select_reality_target
    sni="$REALITY_PROMPT_SNI"
    dest="$REALITY_PROMPT_DEST"
    if test_reality_target "$sni" "$dest"; then
      break
    fi
    local continue_target
    read -rp "预检失败，仍然使用该目标？[y/N，回车重新选择]: " continue_target
    [[ "$continue_target" =~ ^[Yy]$ ]] && break
  done

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/24): " wg_addr
  wg_addr="${wg_addr:-10.0.0.1/24}"
  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/32): " entry_wg_ip
  entry_wg_ip="${entry_wg_ip:-10.0.0.2/32}"
  default_if="$(get_wan_if)"
  read -rp "出口服务器对外网卡名(默认 ${default_if:-eth0}): " out_if
  out_if="${out_if:-${default_if:-eth0}}"
  read -rp "出口服务器 WG 真正监听 UDP 端口 (默认 ${DEFAULT_WG_LISTEN_PORT}): " wg_udp_port
  wg_udp_port="${wg_udp_port:-$DEFAULT_WG_LISTEN_PORT}"
  valid_port "$wg_udp_port" || { print_err "WireGuard 端口不合法"; return 1; }

  write_value "$REMOTE_HOST_FILE" "$host"
  write_value "$REALITY_PORT_FILE" "$port"
  write_value "$SERVER_NAME_FILE" "$sni"
  write_value "$REALITY_DEST_FILE" "$dest"
  write_value "$WG_ADDRESS_FILE" "$wg_addr"
  write_value "$PEER_ADDRESS_FILE" "$entry_wg_ip"
  write_value "$WG_LISTEN_PORT_FILE" "$wg_udp_port"
  write_value "$WAN_IF_FILE" "$out_if"
  ensure_ip_forward

  print_step "Reality" "写入 VLESS + REALITY 服务端配置..."
  write_exit_xray_config
  test_xray_config
  write_service "$XRAY_EXIT_SERVICE"
  print_step "WG" "配置出口 WireGuard..."
  write_exit_wg_config
  start_wg
  restart_service "$XRAY_EXIT_SERVICE"

  print_block "✅ 出口配置完成"
  echo "Reality 地址: ${host}:${port}"
  echo "Reality SNI: ${sni}"
  echo "Reality 公钥: $(read_value "$REALITY_PUBLIC_KEY_FILE")"
  echo "UUID: $(read_value "$UUID_FILE")"
  echo "Short ID: $(read_value "$SHORT_ID_FILE")"
  echo "WG UDP端口: ${wg_udp_port}"
  echo
  echo "【请复制给入口机的 Reality 参数】"
  echo "出口地址: ${host}"
  echo "Reality端口: ${port}"
  echo "SNI: ${sni}"
  echo "reality公钥: $(read_value "$REALITY_PUBLIC_KEY_FILE")"
  echo "UUID: $(read_value "$UUID_FILE")"
  echo "Short ID: $(read_value "$SHORT_ID_FILE")"
  echo "出口WG公钥: ${exit_public_key}"
  echo "入口WG公钥已配置: ${entry_public_key}"
}

configure_entry() {
  set_role "entry"
  ensure_dirs
  print_block "⏳ 开始配置入口服务器"
  install_packages
  install_xray

  print_block "🔑 配置入口 WireGuard 身份"
  echo "回车将自动生成或复用现有私钥"
  ensure_local_wg_identity "入口服务器"
  local entry_public_key exit_public_key
  entry_public_key="$(read_value "$WG_PUBLIC_KEY_FILE")"
  print_block "【入口服务器公钥（配置出口时填写）】"
  echo "$entry_public_key"
  prompt_peer_public_key "出口服务器" "$PEER_PUBLIC_KEY_FILE"
  exit_public_key="$(read_value "$PEER_PUBLIC_KEY_FILE")"

  local wg_addr exit_wg_ip host port sni public_key uuid short_id local_udp_port remote_wg_udp_port
  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/24): " wg_addr
  wg_addr="${wg_addr:-10.0.0.2/24}"
  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/32): " exit_wg_ip
  exit_wg_ip="${exit_wg_ip:-10.0.0.1/32}"
  read -rp "出口服务器域名/IP: " host
  host="$(normalize_pathless_host "${host:-$(read_value "$REMOTE_HOST_FILE")}")"
  [[ -n "$host" ]] || { print_err "出口地址不能为空"; return 1; }
  read -rp "Reality 端口 (默认 443): " port
  port="${port:-443}"
  select_reality_target
  sni="$REALITY_PROMPT_SNI"
  local dest="$REALITY_PROMPT_DEST"
  read -rp "Reality 公钥: " public_key
  public_key="${public_key:-$(read_value "$REALITY_PUBLIC_KEY_FILE")}" 
  read -rp "Reality UUID: " uuid
  uuid="${uuid:-$(read_value "$UUID_FILE")}" 
  read -rp "Reality Short ID: " short_id
  short_id="${short_id:-$(read_value "$SHORT_ID_FILE")}" 
  read -rp "入口本地 Reality UDP 监听端口 (默认 ${DEFAULT_WG_LOCAL_PORT}): " local_udp_port
  local_udp_port="${local_udp_port:-$DEFAULT_WG_LOCAL_PORT}"
  read -rp "远端出口 WG UDP 端口 (默认 ${DEFAULT_WG_LISTEN_PORT}): " remote_wg_udp_port
  remote_wg_udp_port="${remote_wg_udp_port:-$DEFAULT_WG_LISTEN_PORT}"

  valid_port "$port" && valid_wg_key "$exit_public_key" && valid_uuid "$uuid" && valid_short_id "$short_id" || { print_err "Reality/WireGuard 参数格式无效"; return 1; }
  write_value "$REMOTE_HOST_FILE" "$host"; write_value "$REMOTE_PORT_FILE" "$port"
  write_value "$SERVER_NAME_FILE" "$sni"; write_value "$REALITY_DEST_FILE" "$dest"; write_value "$REALITY_PUBLIC_KEY_FILE" "$public_key"
  write_value "$UUID_FILE" "$uuid"; write_value "$SHORT_ID_FILE" "$short_id"
  write_value "$WG_ADDRESS_FILE" "$wg_addr"; write_value "$PEER_ADDRESS_FILE" "$exit_wg_ip"
  write_value "$WG_LOCAL_PORT_FILE" "$local_udp_port"; write_value "$WG_LISTEN_PORT_FILE" "$remote_wg_udp_port"
  write_value "$WAN_IF_FILE" "$(get_wan_if)"; set_mode_flag split

  print_step "Reality" "配置入口 VLESS + REALITY 客户端..."
  write_entry_xray_config
  test_xray_config
  write_service "$XRAY_ENTRY_SERVICE"
  print_step "WG" "配置入口 WireGuard..."
  write_entry_wg_config
  start_wg
  restart_service "$XRAY_ENTRY_SERVICE"
  apply_routing_mode

  print_block "✅ 入口配置完成"
  echo "出口地址: ${host}:${port}"
  echo "Reality SNI: ${sni}"
  echo "本地 UDP 监听: ${local_udp_port}"
  echo "远端 WG UDP: ${remote_wg_udp_port}"
}

update_exit_peer() {
  [[ "$(role)" == exit ]] || { err '当前不是出口机'; return 1; }
  local key
  printf '入口 WireGuard 公钥: '; IFS= read -r key || true
  valid_wg_key "$key" || { err '公钥格式无效'; return 1; }
  write_value "$PEER_PUBLIC_KEY_FILE" "$key"
  write_exit_wg_config
  start_wg
  ok '出口 WireGuard 对端已更新'
}

socket_port_is_bound() {
  local protocol="$1" port="$2"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  if [[ "$protocol" == tcp ]]; then
    ss -H -lnt 2>/dev/null
  else
    ss -H -aun 2>/dev/null
  fi | awk -v port="$port" '
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ (":" port "$")) found = 1
      }
    }
    END { exit(found ? 0 : 1) }
  '
}

show_health_summary() {
  local current_role service port handshake now age recent_handshake='n'
  current_role="$(get_role)"
  if [[ "$current_role" == exit ]]; then
    service="$XRAY_EXIT_SERVICE"
    port="$(read_value "$REALITY_PORT_FILE")"
  else
    service="$XRAY_ENTRY_SERVICE"
    port="$(read_value "$WG_LOCAL_PORT_FILE")"
  fi

  handshake="$(wg show "$WG_IF" latest-handshakes 2>/dev/null | awk 'BEGIN{max=0} $2>max{max=$2} END{print max}' || true)"
  now="$(date +%s)"
  if [[ "$handshake" =~ ^[0-9]+$ ]] && ((handshake > 0 && now - handshake <= 180)); then
    recent_handshake='y'
  fi

  echo "健康检查:"
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    echo "  ✅ Xray 服务: active"
  else
    echo "  ❌ Xray 服务: inactive"
  fi
  if [[ "$current_role" == exit ]] && socket_port_is_bound tcp "$port"; then
    echo "  ✅ Reality TCP ${port}: 正在监听"
  elif [[ "$current_role" == entry ]] && socket_port_is_bound udp "$port"; then
    echo "  ✅ 本地 Xray UDP ${port}: 正在监听"
  elif [[ "$current_role" == entry && "$recent_handshake" == y ]]; then
    echo "  ⚠️  ss 未显示 UDP ${port}，但 WireGuard 存在近期有效握手"
  else
    echo "  ❌ 期望端口 ${port:-未配置}: 未监听"
  fi

  if [[ "$current_role" == entry ]]; then
    if fw_policy_rule_exists && ip route show table "$ROUTE_TABLE_ID" 2>/dev/null | grep -Eq "^default .*dev ${WG_IF}([[:space:]]|$)"; then
      echo "  ✅ WireGuard 策略路由: 正常"
    else
      echo "  ❌ WireGuard 策略路由: 缺失"
    fi
    if iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null; then
      echo "  ✅ WireGuard 出口 NAT: 正常"
    else
      echo "  ❌ WireGuard 出口 NAT: 缺失"
    fi
  fi

  if [[ "$handshake" =~ ^[0-9]+$ ]] && ((handshake > 0)); then
    age=$((now - handshake))
    if ((age <= 180)); then
      echo "  ✅ WireGuard 最近握手: ${age} 秒前"
    else
      echo "  ⚠️  WireGuard 最近握手: ${age} 秒前"
    fi
  else
    echo "  ❌ WireGuard: 尚无有效握手"
  fi
}

show_status() {
  print_block "📊 当前链路状态"
  echo "角色: $(get_role)"
  echo "模式: $(get_mode_label)"
  [[ -f "$REMOTE_HOST_FILE" ]] && echo "远端主机: $(read_value "$REMOTE_HOST_FILE")"
  [[ -f "$REALITY_PORT_FILE" ]] && echo "Reality端口: $(read_value "$REALITY_PORT_FILE")"
  [[ -f "$SERVER_NAME_FILE" ]] && echo "Reality SNI: $(read_value "$SERVER_NAME_FILE")"
  [[ -f "$REALITY_PUBLIC_KEY_FILE" ]] && echo "Reality公钥: $(read_value "$REALITY_PUBLIC_KEY_FILE")"
  [[ -f "$UUID_FILE" ]] && echo "Reality UUID: $(read_value "$UUID_FILE")"
  [[ -f "$SHORT_ID_FILE" ]] && echo "Reality Short ID: $(read_value "$SHORT_ID_FILE")"
  [[ -f "$WG_LISTEN_PORT_FILE" ]] && echo "WG UDP端口: $(read_value "$WG_LISTEN_PORT_FILE")"
  [[ -f "$WG_LOCAL_PORT_FILE" ]] && echo "本地Reality UDP端口: $(read_value "$WG_LOCAL_PORT_FILE")"
  echo
  show_health_summary
  echo
  wg show || true
  echo
  systemctl --no-pager --full status "$XRAY_EXIT_SERVICE" 2>/dev/null | sed -n '1,10p' || true
  echo
  systemctl --no-pager --full status "$XRAY_ENTRY_SERVICE" 2>/dev/null | sed -n '1,10p' || true
}

start_all() {
  [[ -s "$ROLE_FILE" ]] || { err '尚未配置角色'; return 1; }
  start_wg
  if [[ "$(role)" == entry ]]; then restart_service "$XRAY_ENTRY_SERVICE"; else restart_service "$XRAY_EXIT_SERVICE"; fi
  [[ "$(role)" == entry ]] && apply_routing_mode
  ok '服务已启动'
}

stop_all() {
  systemctl stop "$XRAY_ENTRY_SERVICE" "$XRAY_EXIT_SERVICE" 2>/dev/null || true
  stop_wg
  clear_entry_forward_rules
  clear_mangle_chains
  ip route flush table "$ROUTE_TABLE_ID" 2>/dev/null || true
  ip rule del fwmark "$FW_MARK" table "$ROUTE_TABLE_ID" 2>/dev/null || true
  ok '服务已停止'
}

uninstall_all() {
  local remove_xray='n' managed_sysctl xray_was_managed='n'
  print_block '卸载 wg-reality'
  printf '确认卸载并删除本脚本配置？[y/N]: '
  local answer; IFS= read -r answer || true
  [[ "$answer" =~ ^[Yy]$ ]] || { info '已取消'; return 0; }
  [[ -f "$XRAY_MANAGED_FILE" ]] && xray_was_managed='y'
  stop_all
  systemctl disable "$XRAY_ENTRY_SERVICE" "$XRAY_EXIT_SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/${XRAY_ENTRY_SERVICE}" "/etc/systemd/system/${XRAY_EXIT_SERVICE}"
  systemctl daemon-reload
  rm -f "$WG_CONFIG" "$WG_MARKER"
  rm -rf "$BASE_DIR" "$XRAY_DIR"
  [[ "$xray_was_managed" == y ]] && remove_xray='y'
  [[ "$remove_xray" == y ]] && rm -f "$XRAY_BIN"
  managed_sysctl="$(grep -n -B1 -A1 "# ${APP_NAME}" /etc/sysctl.conf 2>/dev/null || true)"
  if [[ -n "$managed_sysctl" ]]; then
    sed -i "/# ${APP_NAME}/,+1d" /etc/sysctl.conf 2>/dev/null || true
    sysctl -p >/dev/null 2>&1 || true
  fi
  ok '已卸载本脚本创建的服务、WireGuard 配置、Xray 配置和防火墙规则'
}

uninstall_wg() { uninstall_all; }

manage_entry_ports() {
  [[ "$(get_role)" == entry ]] || { print_err "当前机器不是入口服务器"; return 1; }
  local current_mode sub new_port del_port
  current_mode="$(get_current_mode)"
  while true; do
    print_block "入口端口分流管理"
    echo "1) 查看当前分流端口"
    echo "2) 添加分流端口"
    echo "3) 删除分流端口"
    echo "0) 返回上一级"
    read -rp "请选择: " sub
    case "$sub" in
      1)
        if [[ -s "${STATE_DIR}/ports" ]]; then cat "${STATE_DIR}/ports"; else print_warn "当前没有分流端口"; fi
        ;;
      2)
        read -rp "端口: " new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && ((10#$new_port >= 1 && 10#$new_port <= 65535)) && [[ "$new_port" != 22 ]]; then
          add_port_to_list "$new_port"
          print_ok "已添加并应用端口: $new_port"
        else
          print_err "端口不合法"
        fi
        ;;
      3)
        read -rp "要删除的端口: " del_port
        if [[ "$del_port" =~ ^[0-9]+$ ]]; then
          remove_port_from_list "$del_port"
          print_ok "已删除并撤销端口: $del_port"
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
  [[ "$(get_role)" == entry ]] || { print_err "当前机器不是入口服务器"; return 1; }
  local sub current_mode
  while true; do
    current_mode="$(get_current_mode)"
    print_block "入口模式管理"
    echo "当前模式: $(get_mode_label "$current_mode")"
    echo "1) 切换为 全局模式"
    echo "2) 切换为 分流模式"
    echo "3) 切换为 NyanPass 转发模式"
    echo "0) 返回上一级"
    read -rp "请选择: " sub
    case "$sub" in
      1) enable_global_mode; print_ok "已切换为全局模式" ;;
      2) enable_split_mode; print_ok "已切换为分流模式" ;;
      3) enable_nyanpass_mode; print_ok "已切换为 NyanPass 转发模式" ;;
      0) break ;;
      *) print_err "无效选择" ;;
    esac
  done
}

update_reality_entry_remote_ip() {
  [[ "$(get_role)" == entry ]] || { print_err "当前机器不是入口服务器"; return 1; }
  local saved_host saved_port new_host new_port sni public_key uuid short_id
  saved_host="$(read_value "$REMOTE_HOST_FILE")"; saved_port="$(read_value "$REMOTE_PORT_FILE")"
  read -rp "新出口域名 / IP (默认 ${saved_host}): " new_host
  new_host="$(normalize_pathless_host "${new_host:-$saved_host}")"
  [[ -n "$new_host" ]] || { print_err "出口地址不能为空"; return 1; }
  read -rp "Reality 端口 (默认 ${saved_port:-443}): " new_port
  new_port="${new_port:-${saved_port:-443}}"
  read -rp "Reality SNI (默认 $(read_value "$SERVER_NAME_FILE")): " sni
  sni="${sni:-$(read_value "$SERVER_NAME_FILE")}"
  read -rp "Reality 公钥 (回车保留): " public_key; public_key="${public_key:-$(read_value "$REALITY_PUBLIC_KEY_FILE")}"
  read -rp "Reality UUID (回车保留): " uuid; uuid="${uuid:-$(read_value "$UUID_FILE")}"
  read -rp "Reality Short ID (回车保留): " short_id; short_id="${short_id:-$(read_value "$SHORT_ID_FILE")}"
  valid_port "$new_port" && valid_host "$sni" && valid_wg_key "$public_key" && valid_uuid "$uuid" && valid_short_id "$short_id" || { print_err "Reality 参数无效"; return 1; }
  write_value "$REMOTE_HOST_FILE" "$new_host"; write_value "$REMOTE_PORT_FILE" "$new_port"
  write_value "$SERVER_NAME_FILE" "$sni"; write_value "$REALITY_PUBLIC_KEY_FILE" "$public_key"
  write_value "$UUID_FILE" "$uuid"; write_value "$SHORT_ID_FILE" "$short_id"
  write_entry_xray_config; test_xray_config; restart_service "$XRAY_ENTRY_SERVICE"; apply_routing_mode
  print_block "✅ 出口地址已更新"
  echo "新地址: ${new_host}:${new_port}"
  echo "新 SNI: ${sni}"
}

# Keep the original wg-ws.sh function name as a compatibility alias for the
# unchanged menu numbering and any operator muscle memory.
update_wstunnel_entry_remote_ip() { update_reality_entry_remote_ip; }

manage_exit_node() {
  [[ "$(get_role)" == exit ]] || { print_err "该功能仅限在【出口服务器】上使用"; return; }
  local sub port sni dest
  while true; do
    print_block "出口高级管理 (Reality 参数 / 密钥 / 端口)"
    echo "当前 Reality 地址: $(read_value "$REMOTE_HOST_FILE"):$(read_value "$REALITY_PORT_FILE")"
    echo "------------------------------------------------"
    echo "1) 查看 Reality 参数"
    echo "2) 修改 Reality 监听端口"
    echo "3) 修改 Reality SNI / 目标"
    echo "4) 重新生成 Reality 密钥"
    echo "5) 重新生成 UUID / Short ID"
    echo "0) 返回上一级"
    read -rp "请选择高级操作: " sub
    case "$sub" in
      1) show_status ;;
      2)
        read -rp "新的 Reality 端口: " port
        valid_port "$port" || { print_err "端口不合法"; continue; }
        write_value "$REALITY_PORT_FILE" "$port"; write_exit_xray_config; test_xray_config; setup_host_firewall; restart_service "$XRAY_EXIT_SERVICE"; print_ok "Reality 端口已更新" ;;
      3)
        select_reality_target
        sni="$REALITY_PROMPT_SNI"
        dest="$REALITY_PROMPT_DEST"
        test_reality_target "$sni" "$dest" || { print_err "目标预检未通过，未修改当前配置"; continue; }
        write_value "$SERVER_NAME_FILE" "$sni"; write_value "$REALITY_DEST_FILE" "$dest"; write_exit_xray_config; test_xray_config; restart_service "$XRAY_EXIT_SERVICE"; print_ok "Reality 伪装参数已更新" ;;
      4) rm -f "$REALITY_PRIVATE_KEY_FILE" "$REALITY_PUBLIC_KEY_FILE"; generate_reality_identity; write_exit_xray_config; test_xray_config; restart_service "$XRAY_EXIT_SERVICE"; print_ok "Reality 密钥已重新生成，请同步入口" ;;
      5) rm -f "$UUID_FILE" "$SHORT_ID_FILE"; generate_uuid_and_short_id; write_exit_xray_config; test_xray_config; restart_service "$XRAY_EXIT_SERVICE"; print_ok "UUID / Short ID 已重新生成，请同步入口" ;;
      0) break ;;
      *) print_err "无效选择" ;;
    esac
  done
}

menu() {
  local choice
  while true; do
    echo
    echo "================ 📡 WG + VLESS + REALITY 高级链路 ================"
    echo "1) 配置为 出口服务器"
    echo "2) 配置为 入口服务器"
    echo "3) 查看链路状态"
    echo "4) 启动"
    echo "5) 停止"
    echo "6) 重启"
    echo "7) 卸载并清理"
    echo "8) 管理入口端口分流"
    echo "9) 管理入口模式"
    echo "10) 修改出口 IP / 域名（仅入口使用）"
    echo "11) 出口高级管理 (Reality 参数 / 密钥 / 端口)"
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
      10) update_reality_entry_remote_ip ;;
      11) manage_exit_node ;;
      0) return 0 ;;
      *) print_err '无效选择' ;;
    esac
  done
}

usage() {
  cat <<EOF
用法：sudo bash $0 [选项]

不带选项进入交互菜单。
  --entry       配置入口机
  --exit        配置出口机
  --status      查看状态
  --start       启动服务
  --stop        停止服务
  --uninstall   卸载本脚本内容
  --help        显示帮助
EOF
}

main() {
  case "${1:-}" in
    --entry) configure_entry ;;
    --exit) configure_exit ;;
    --status) show_status ;;
    --start) start_all ;;
    --stop) stop_all ;;
    --uninstall) uninstall_all ;;
    --help|-h) usage ;;
    '') menu ;;
    *) usage; return 1 ;;
  esac
}

main "$@"
