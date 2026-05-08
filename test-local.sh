#!/bin/bash
# 本地端到端测试：验证 ISN 随机化 + 数据通路正常
# 需要 root、tun 内核模块、iptables、tcpdump、socat
# 用法：sudo ./test-local.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$REPO_DIR/target/debug"
CLIENT_BIN="$BIN_DIR/client"
SERVER_BIN="$BIN_DIR/server"

# 端口分配
PHANTUN_PORT=14567       # Phantun Server 监听 fake-TCP
WG_PORT=15820            # 模拟 WireGuard UDP 端口（socat echo）
CLIENT_UDP=14568         # Phantun Client 监听 UDP

# TUN 地址（与 Phantun 默认一致）
CLIENT_TUN_LOCAL=192.168.200.1
CLIENT_TUN_PEER=192.168.200.2
SERVER_TUN_LOCAL=192.168.201.1
SERVER_TUN_PEER=192.168.201.2

PCAP_FILE="/tmp/phantun-test-$$.pcap"
PASS=0
FAIL=0

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { log "PASS: $*"; ((PASS++)); }
fail() { log "FAIL: $*"; ((FAIL++)); }

cleanup() {
    log "清理..."
    kill "$SERVER_PID" "$CLIENT_PID" "$ECHO_PID" "$TCPDUMP_PID" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$CLIENT_TUN_PEER" -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport "$PHANTUN_PORT" \
        -j DNAT --to-destination "$SERVER_TUN_PEER" 2>/dev/null || true
    iptables -D FORWARD -j ACCEPT 2>/dev/null || true
    sysctl -w net.ipv4.conf.all.route_localnet=0 >/dev/null 2>&1 || true
    rm -f "$PCAP_FILE"
    log "结果: PASS=$PASS  FAIL=$FAIL"
    [[ $FAIL -eq 0 ]]
}
trap cleanup EXIT

# ── 前置检查 ──────────────────────────────────────────────
[[ $EUID -eq 0 ]] || { echo "需要 root 权限，请用 sudo 运行"; exit 1; }
for cmd in iptables tcpdump socat tshark; do
    command -v "$cmd" >/dev/null || { echo "缺少依赖: $cmd"; exit 1; }
done
[[ -x "$CLIENT_BIN" && -x "$SERVER_BIN" ]] || {
    echo "二进制不存在，请先 cargo build"
    echo "  cd $REPO_DIR && cargo build"
    exit 1
}

# ── iptables 设置 ─────────────────────────────────────────
log "配置 iptables..."
# 允许 loopback 路由（PREROUTING 作用于本机目的地）
sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null

# Server 侧：将到 PHANTUN_PORT 的 TCP 流量 DNAT 到 Phantun Server TUN peer
iptables -t nat -A PREROUTING -p tcp --dport "$PHANTUN_PORT" \
    -j DNAT --to-destination "$SERVER_TUN_PEER"
iptables -A FORWARD -j ACCEPT

# Client 侧：SNAT Phantun Client TUN peer → 本机 IP
iptables -t nat -A POSTROUTING -s "$CLIENT_TUN_PEER" -j MASQUERADE

# ── 启动 UDP echo 服务（模拟 WireGuard） ──────────────────
log "启动 UDP echo server (port $WG_PORT)..."
socat UDP-LISTEN:$WG_PORT,fork PIPE &
ECHO_PID=$!
sleep 0.3

# ── 启动 Phantun Server ───────────────────────────────────
log "启动 Phantun Server (fake-TCP :$PHANTUN_PORT → UDP 127.0.0.1:$WG_PORT)..."
RUST_LOG=info "$SERVER_BIN" \
    --local "$PHANTUN_PORT" \
    --remote "127.0.0.1:$WG_PORT" \
    --tun-local "$SERVER_TUN_LOCAL" \
    --tun-peer  "$SERVER_TUN_PEER" \
    --ipv4-only &
SERVER_PID=$!
sleep 1

# ── 启动 tcpdump 捕获 SYN 包 ──────────────────────────────
log "启动 tcpdump 捕获 SYN 包..."
tcpdump -i any -nn -c 3 \
    "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and port $PHANTUN_PORT" \
    -w "$PCAP_FILE" 2>/dev/null &
TCPDUMP_PID=$!
sleep 0.3

# ── 启动 Phantun Client ───────────────────────────────────
log "启动 Phantun Client (UDP 127.0.0.1:$CLIENT_UDP → fake-TCP 127.0.0.1:$PHANTUN_PORT)..."
RUST_LOG=info "$CLIENT_BIN" \
    --local  "127.0.0.1:$CLIENT_UDP" \
    --remote "127.0.0.1:$PHANTUN_PORT" \
    --tun-local "$CLIENT_TUN_LOCAL" \
    --tun-peer  "$CLIENT_TUN_PEER" \
    --ipv4-only &
CLIENT_PID=$!
sleep 1

# ── 测试 1：数据通路 ──────────────────────────────────────
log "=== 测试 1: 数据通路 ==="
TEST_MSG="PHANTUN_ISN_TEST_$(date +%s)"
RECV=$(echo "$TEST_MSG" | socat - UDP:127.0.0.1:$CLIENT_UDP,shut-none 2>/dev/null || true)

if [[ "$RECV" == "$TEST_MSG" ]]; then
    pass "数据往返正常 (发送='$TEST_MSG' 收到='$RECV')"
else
    fail "数据往返异常 (发送='$TEST_MSG' 收到='$RECV')"
fi

# ── 测试 2：ISN 随机化 ────────────────────────────────────
log "=== 测试 2: ISN 随机化 ==="
sleep 1  # 等待 tcpdump 捕获完成
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

if [[ ! -f "$PCAP_FILE" ]]; then
    fail "未捕获到 pcap 文件"
else
    # 提取所有 SYN 包的 seq 值
    SEQS=$(tshark -r "$PCAP_FILE" \
        -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
        -T fields -e tcp.seq 2>/dev/null || true)

    if [[ -z "$SEQS" ]]; then
        fail "未捕获到 SYN 包（可能连接未建立）"
    else
        log "捕获到 SYN 包 seq 值: $(echo $SEQS | tr '\n' ' ')"
        FOUND_ZERO=0
        for seq in $SEQS; do
            [[ "$seq" == "0" ]] && FOUND_ZERO=1
        done

        if [[ $FOUND_ZERO -eq 1 ]]; then
            fail "存在 seq=0 的 SYN 包，ISN 随机化未生效"
        else
            pass "所有 SYN 包 seq 均非零，ISN 随机化正常"
        fi

        # 检查多次连接时 ISN 是否不同（随机性验证）
        UNIQUE=$(echo "$SEQS" | sort -u | wc -l)
        TOTAL=$(echo "$SEQS" | wc -l)
        if [[ $TOTAL -gt 1 && $UNIQUE -lt $TOTAL ]]; then
            fail "多次连接出现相同 ISN，随机性不足"
        else
            pass "ISN 值均唯一（共 $TOTAL 个 SYN 包）"
        fi
    fi
fi
