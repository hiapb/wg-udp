#!/usr/bin/env bash
set -euo pipefail

NEXUS_DIR="/etc/darknexus"
BIN_PATH="/usr/local/bin/darknexus"
SVC_PATH="/etc/systemd/system/darknexus.service"
SRC_PATH="/usr/local/src/darknexus.go"
PORT_LIST_FILE="${NEXUS_DIR}/.wg_ports"
MODE_FILE="${NEXUS_DIR}/.wg_mode"
ROLE_FILE="${NEXUS_DIR}/.wg_role"
EXIT_WG_IP_FILE="${NEXUS_DIR}/.exit_wg_ip"

if [[ $EUID -ne 0 ]]; then
  echo "❌ 请用 root 运行"
  exit 1
fi

print_block() { echo; echo "=================================================="; echo "$1"; echo "=================================================="; }
print_step() { echo "[$1] $2"; }
print_ok() { echo "✅ $1"; }
print_warn() { echo "⚠️  $1"; }
print_err() { echo "❌ $1"; }

get_role() { [[ -f "$ROLE_FILE" ]] && cat "$ROLE_FILE" 2>/dev/null || echo "unknown"; }
set_role() { mkdir -p "$(dirname "$ROLE_FILE")"; echo "$1" > "$ROLE_FILE"; }
get_current_mode() { [[ -f "$MODE_FILE" ]] && cat "$MODE_FILE" 2>/dev/null || echo "split"; }
set_mode_flag() { echo "$1" > "$MODE_FILE"; }

# 剥离：仅针对出口的纯净依赖安装（绝不触碰内核参数）
install_base_deps_only() {
  print_step "1/2" "仅安装基础依赖 (跳过系统内核调优)..."
  export DEBIAN_FRONTEND=noninteractive
  apt update -y >/dev/null 2>&1 || true
  apt install -y curl tar ca-certificates iproute2 iptables golang-go git openssl coreutils >/dev/null 2>&1
  print_ok "基础依赖安装完成，已完整保留您的自定义内核配置"
}

# 剥离：针对入口的激进调优与依赖安装
install_deps_and_tune() {
  print_step "1/2" "安装基础依赖并执行入口内核并发调优..."
  export DEBIAN_FRONTEND=noninteractive
  apt update -y >/dev/null 2>&1 || true
  apt install -y curl tar ca-certificates iproute2 iptables golang-go git openssl coreutils >/dev/null 2>&1
  
  cat << 'EOF' > /etc/sysctl.d/99-nexus.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
net.core.netdev_max_backlog=250000
net.ipv4.ip_forward=1
EOF
  sysctl -p /etc/sysctl.d/99-nexus.conf >/dev/null 2>&1 || true
  print_ok "基础依赖与入口内核参数配置完成"
}

install_core_engine() {
  print_step "2/2" "编译高熵抗 DPI 底层引擎..."
  mkdir -p /usr/local/src
  cat << 'EOF' > $SRC_PATH
package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
	"golang.org/x/crypto/chacha20poly1305"
)

const SO_ORIGINAL_DST = 80

var (
	bufPool     = sync.Pool{New: func() interface{} { return make([]byte, 32768) }}
	payloadPool = sync.Pool{New: func() interface{} { return make([]byte, 65536) }}
)

func init() {
	mathrand.Seed(time.Now().UnixNano())
}

func main() {
	isServer := flag.Bool("s", false, "")
	lAddr := flag.String("l", ":443", "")
	tAddr := flag.String("t", ":1081", "")
	rAddr := flag.String("r", "127.0.0.1:8081", "")
	keyStr := flag.String("k", "default", "")
	flag.Parse()

	keyHash := sha256.Sum256([]byte(*keyStr))
	aead, _ := chacha20poly1305.New(keyHash[:])

	if *isServer {
		listener, _ := net.Listen("tcp", *lAddr)
		for {
			conn, _ := listener.Accept()
			go handleServer(conn, aead)
		}
	} else {
		go startTransparent(*tAddr, *rAddr, aead)
		listener, _ := net.Listen("tcp", *lAddr)
		for {
			conn, _ := listener.Accept()
			go handleClientSocks(conn, *rAddr, aead)
		}
	}
}

func getOriginalDst(conn *net.TCPConn) (string, error) {
	file, err := conn.File()
	if err != nil { return "", err }
	defer file.Close()
	addr, err := syscall.GetsockoptIPv4(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil { return "", err }
	ip := net.IPv4(addr.Multiaddr[4], addr.Multiaddr[5], addr.Multiaddr[6], addr.Multiaddr[7])
	port := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])
	return fmt.Sprintf("%s:%d", ip, port), nil
}

func writeObfs(dst net.Conn, pt []byte, aead cipher.AEAD) error {
	dataLen := len(pt)
	padLen := 0

	if dataLen == 0 {
		padLen = 256 + mathrand.Intn(512)
	} else if dataLen < 256 {
		padLen = 512 - dataLen + mathrand.Intn(64)
	} else if dataLen < 1000 {
		padLen = 1350 - dataLen
	} else {
		padLen = mathrand.Intn(32)
	}

	payload := payloadPool.Get().([]byte)[: 2+dataLen+padLen ]
	defer payloadPool.Put(payload[:65536])

	binary.BigEndian.PutUint16(payload[:2], uint16(dataLen))
	if dataLen > 0 { copy(payload[2:], pt) }
	if padLen > 0 { io.ReadFull(rand.Reader, payload[2+dataLen:]) }

	nonce := make([]byte, aead.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ct := aead.Seal(nil, nonce, payload, nil)

	length := uint32(len(nonce) + len(ct))
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, length)

	_, err := dst.Write(append(lenBuf, append(nonce, ct...)...))
	return err
}

func readObfs(src net.Conn, aead cipher.AEAD) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(src, lenBuf); err != nil { return nil, err }
	length := binary.BigEndian.Uint32(lenBuf)
	if length > 131072 { return nil, fmt.Errorf("oversized") }

	dataBuf := payloadPool.Get().([]byte)[:length]
	defer payloadPool.Put(dataBuf[:65536])

	if _, err := io.ReadFull(src, dataBuf); err != nil { return nil, err }

	nonce := dataBuf[:aead.NonceSize()]
	msg := dataBuf[aead.NonceSize():]
	
	pt, err := aead.Open(dataBuf[:0], nonce, msg, nil)
	if err != nil { return nil, err }

	if len(pt) < 2 { return nil, fmt.Errorf("invalid") }
	validLen := int(binary.BigEndian.Uint16(pt[:2]))
	
	if validLen == 0 { return nil, nil }
	if 2+validLen > len(pt) { return nil, fmt.Errorf("corrupted") }

	out := make([]byte, validLen)
	copy(out, pt[2:2+validLen])
	return out, nil
}

func startTransparent(addr string, rAddr string, aead cipher.AEAD) {
	listener, _ := net.Listen("tcp", addr)
	for {
		conn, _ := listener.Accept()
		go func(c net.Conn) {
			defer c.Close()
			tcpConn := c.(*net.TCPConn)
			target, _ := getOriginalDst(tcpConn)
			remoteConn, _ := net.Dial("tcp", rAddr)
			defer remoteConn.Close()
			writeObfs(remoteConn, nil, aead)
			writeObfs(remoteConn, []byte(target), aead)
			go decodeAndWrite(remoteConn, c, aead)
			encodeAndWrite(c, remoteConn, aead)
		}(conn)
	}
}

func handleClientSocks(localConn net.Conn, rAddr string, aead cipher.AEAD) {
	defer localConn.Close()
	target, _ := handleSocks5(localConn)
	remoteConn, _ := net.Dial("tcp", rAddr)
	defer remoteConn.Close()
	writeObfs(remoteConn, nil, aead)
	writeObfs(remoteConn, []byte(target), aead)
	go decodeAndWrite(remoteConn, localConn, aead)
	encodeAndWrite(localConn, remoteConn, aead)
}

func handleServer(localConn net.Conn, aead cipher.AEAD) {
	defer localConn.Close()
	writeObfs(localConn, nil, aead)
	var target string
	for {
		tBuf, _ := readObfs(localConn, aead)
		if len(tBuf) > 0 {
			target = string(tBuf)
			break
		}
	}
	remoteConn, _ := net.Dial("tcp", target)
	defer remoteConn.Close()
	go decodeAndWrite(localConn, remoteConn, aead)
	encodeAndWrite(remoteConn, localConn, aead)
}

func handleSocks5(conn net.Conn) (string, error) {
	buf := make([]byte, 256)
	io.ReadFull(conn, buf[:2])
	io.ReadFull(conn, buf[:buf[1]])
	conn.Write([]byte{5, 0})
	io.ReadFull(conn, buf[:4])
	var target string
	switch buf[3] {
	case 1:
		io.ReadFull(conn, buf[4:10])
		target = net.IP(buf[4:8]).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(buf[8:10])))
	case 3:
		io.ReadFull(conn, buf[4:5])
		dLen := int(buf[4])
		io.ReadFull(conn, buf[5:5+dLen+2])
		target = string(buf[5:5+dLen]) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(buf[5+dLen:5+dLen+2])))
	}
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return target, nil
}

func encodeAndWrite(src net.Conn, dst net.Conn, aead cipher.AEAD) {
	buf := bufPool.Get().([]byte); defer bufPool.Put(buf)
	for {
		n, err := src.Read(buf)
		if n > 0 { writeObfs(dst, buf[:n], aead) }
		if err != nil { return }
	}
}

func decodeAndWrite(src net.Conn, dst net.Conn, aead cipher.AEAD) {
	for {
		pt, err := readObfs(src, aead)
		if err != nil { return }
		if len(pt) > 0 { dst.Write(pt) }
	}
}
EOF
  cd /usr/local/src
  
  if ! go mod init darknexus >/dev/null 2>&1; then true; fi
  if ! go get golang.org/x/crypto/chacha20poly1305 >/dev/null 2>&1; then
      print_err "依赖拉取失败，请检查网络连通性或 DNS。"
      exit 1
  fi
  
  if ! go build -o $BIN_PATH darknexus.go; then
      print_err "编译失败！系统环境或 Golang 版本存在异常。"
      exit 1
  fi
  
  print_ok "核心引擎编译完成"
}

clear_mark_rules() {
  iptables -t nat -D PREROUTING -p tcp -j NEXUS_ROUTE 2>/dev/null || true
  iptables -t nat -D OUTPUT -p tcp -j NEXUS_ROUTE 2>/dev/null || true
  iptables -t nat -F NEXUS_ROUTE 2>/dev/null || true
  iptables -t nat -X NEXUS_ROUTE 2>/dev/null || true
}

enable_split_mode() {
  clear_mark_rules
  iptables -t nat -N NEXUS_ROUTE
  
  if [[ -f "$PORT_LIST_FILE" ]]; then
    while read -r p; do
      [[ -z "$p" ]] && continue
      iptables -t nat -A NEXUS_ROUTE -p tcp --dport "$p" -j REDIRECT --to-ports 1081
    done < "$PORT_LIST_FILE" || true
  fi
  
  iptables -t nat -A PREROUTING -p tcp -j NEXUS_ROUTE
  iptables -t nat -A OUTPUT -p tcp -j NEXUS_ROUTE
  set_mode_flag "split"
}

enable_global_mode() {
  clear_mark_rules
  iptables -t nat -N NEXUS_ROUTE
  
  local remote_ip=""
  if [[ -f "$EXIT_WG_IP_FILE" ]]; then
    local r_full=$(cat "$EXIT_WG_IP_FILE")
    local r_host="${r_full%:*}"
    remote_ip=$(getent ahostsv4 "$r_host" | awk 'NR==1{print $1}' || true)
  fi

  iptables -t nat -A NEXUS_ROUTE -d 0.0.0.0/8 -j RETURN
  iptables -t nat -A NEXUS_ROUTE -d 10.0.0.0/8 -j RETURN
  iptables -t nat -A NEXUS_ROUTE -d 127.0.0.0/8 -j RETURN
  iptables -t nat -A NEXUS_ROUTE -d 169.254.0.0/16 -j RETURN
  iptables -t nat -A NEXUS_ROUTE -d 172.16.0.0/12 -j RETURN
  iptables -t nat -A NEXUS_ROUTE -d 192.168.0.0/16 -j RETURN
  iptables -t nat -A NEXUS_ROUTE -d 224.0.0.0/4 -j RETURN
  iptables -t nat -A NEXUS_ROUTE -d 240.0.0.0/4 -j RETURN
  [[ -n "$remote_ip" ]] && iptables -t nat -A NEXUS_ROUTE -d "$remote_ip" -j RETURN
  iptables -t nat -A NEXUS_ROUTE -p tcp --dport 22 -j RETURN

  iptables -t nat -A NEXUS_ROUTE -p tcp -j REDIRECT --to-ports 1081
  
  iptables -t nat -A PREROUTING -p tcp -j NEXUS_ROUTE
  iptables -t nat -A OUTPUT -p tcp -j NEXUS_ROUTE
  set_mode_flag "global"
}

configure_exit() {
  set_role "exit"
  print_block "⏳ 开始配置出口服务器"
  
  # 调用无内核修改的纯净依赖安装
  install_base_deps_only
  install_core_engine

  read -rp "监听密文端口 (推荐 443 伪装效果最佳): " l_port
  l_port="${l_port:-443}"
  
  local rand_key
  rand_key=$(head -c 32 /dev/urandom | sha256sum | head -c 32)
  read -rp "隧道加密密钥 (默认生成: ${rand_key}): " s_key
  s_key="${s_key:-$rand_key}"

  cat << EOF > $SVC_PATH
[Unit]
After=network.target
[Service]
ExecStart=$BIN_PATH -s -l :${l_port} -k "${s_key}"
Restart=always
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable darknexus.service >/dev/null 2>&1 || true
  systemctl restart darknexus.service
  
  print_block "✅ 出口配置完成"
  echo "监听端口: ${l_port}"
  echo "加密密钥: ${s_key} (请复制此密钥在入口端使用)"
}

configure_entry() {
  set_role "entry"
  print_block "⏳ 开始配置入口服务器"
  
  # 调用包含系统调优的入口依赖安装
  install_deps_and_tune
  install_core_engine

  read -rp "出口服务器 IP / 域名: " r_host
  read -rp "出口服务器密文端口 (默认 443): " r_port
  r_port="${r_port:-443}"
  
  local s_key=""
  while [[ -z "$s_key" ]]; do
    read -rp "隧道加密密钥 (需填入出口服务器生成的密钥): " s_key
  done

  cat << EOF > $SVC_PATH
[Unit]
After=network.target
[Service]
ExecStart=$BIN_PATH -l :1080 -t :1081 -r ${r_host}:${r_port} -k "${s_key}"
Restart=always
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable darknexus.service >/dev/null 2>&1 || true
  systemctl restart darknexus.service
  
  echo "${r_host}:${r_port}" > "$EXIT_WG_IP_FILE"
  echo "${s_key}" > "${NEXUS_DIR}/.secret"
  set_mode_flag "split"
  enable_split_mode
  
  print_block "✅ 入口配置完成"
  echo "出口地址: ${r_host}:${r_port}"
}

show_status() {
  print_block "📊 当前链路状态"
  echo "角色: $(get_role)"
  echo "模式: $(get_current_mode)"
  [[ -f "$EXIT_WG_IP_FILE" ]] && echo "远端出口: $(cat "$EXIT_WG_IP_FILE" 2>/dev/null || true)"
  echo
  systemctl --no-pager --full status darknexus.service 2>/dev/null | sed -n '1,10p' || true
}

start_wg() {
  print_block "⏳ 正在启动"
  systemctl start darknexus.service 2>/dev/null || true
  if [[ "$(get_role)" == "entry" ]]; then
    [[ "$(get_current_mode)" == "global" ]] && enable_global_mode || enable_split_mode
  fi
  print_ok "已启动"
}

stop_wg() {
  print_block "⏳ 正在停止"
  systemctl stop darknexus.service 2>/dev/null || true
  clear_mark_rules
  print_ok "已停止"
}

restart_wg() {
  print_block "⏳ 正在重启"
  stop_wg
  start_wg
  print_ok "重启完成"
}

uninstall_wg() {
  print_block "⏳ 开始彻底卸载并清理"
  systemctl stop darknexus.service 2>/dev/null || true
  systemctl disable darknexus.service 2>/dev/null || true
  rm -f "$SVC_PATH"
  
  clear_mark_rules
  
  # 仅在发现内核调整文件存在时，才执行逆向清理
  if [[ -f /etc/sysctl.d/99-nexus.conf ]]; then
      rm -f /etc/sysctl.d/99-nexus.conf
      sysctl --system >/dev/null 2>&1 || true
  fi
  
  rm -f "$BIN_PATH"
  rm -rf "$NEXUS_DIR"
  rm -rf /usr/local/src/darknexus*
  
  systemctl daemon-reload
  print_ok "✅ 已彻底清理完成 (服务、配置及所有残留文件已销毁)"
}

manage_entry_ports() {
  [[ "$(get_role)" == "entry" ]] || { print_err "当前机器不是入口服务器"; return 1; }

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
        if [[ "$new_port" =~ ^[0-9]+$ ]]; then
          echo "$new_port" >> "$PORT_LIST_FILE"
          [[ "$(get_current_mode)" == "split" ]] && enable_split_mode
          print_ok "已添加端口: $new_port"
        else
          print_err "端口不合法"
        fi
        ;;
      3)
        read -rp "要删除的端口: " del_port
        if [[ "$del_port" =~ ^[0-9]+$ ]]; then
          sed -i "\|^$del_port$|d" "$PORT_LIST_FILE"
          [[ "$(get_current_mode)" == "split" ]] && enable_split_mode
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

update_exit_ip() {
  [[ "$(get_role)" == "entry" ]] || { print_err "当前机器不是入口服务器"; return 1; }
  
  read -rp "新出口 IP / 域名: " new_host
  read -rp "新出口 端口 (默认 443): " new_port
  new_port="${new_port:-443}"
  
  local s_key="default"
  [[ -f "${NEXUS_DIR}/.secret" ]] && s_key=$(cat "${NEXUS_DIR}/.secret")
  
  cat << EOF > $SVC_PATH
[Unit]
After=network.target
[Service]
ExecStart=$BIN_PATH -l :1080 -t :1081 -r ${new_host}:${new_port} -k "${s_key}"
Restart=always
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl restart darknexus.service
  
  echo "${new_host}:${new_port}" > "$EXIT_WG_IP_FILE"
  print_ok "出口 IP / 端口已修改并生效"
}

while true; do
  echo
  echo "================ 📡 DarkNexus 高级链路 ================"
  echo "1) 配置为 出口服务器"
  echo "2) 配置为 入口服务器"
  echo "3) 查看链路状态"
  echo "4) 启动"
  echo "5) 停止"
  echo "6) 重启"
  echo "7) 卸载并清理"
  echo "8) 管理入口端口分流"
  echo "9) 管理入口模式（全局 / 分流）"
  echo "10) 修改出口 IP / 端口（仅入口使用）"
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
    10) update_exit_ip ;;
    0) exit 0 ;;
    *) print_err "无效选择" ;;
  esac
done
