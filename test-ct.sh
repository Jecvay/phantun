#!/bin/bash
set -euo pipefail

BIN_DIR=/root
CLIENT_BIN="$BIN_DIR/client"
SERVER_BIN="$BIN_DIR/server"
NFT=/sbin/nft

PHANTUN_PORT=14567
WG_PORT=15820
CLIENT_UDP=14568
CLIENT_TUN_LOCAL=192.168.200.1
CLIENT_TUN_PEER=192.168.200.2   # client fake-TCP 源 IP
SERVER_TUN_LOCAL=192.168.201.1
SERVER_TUN_PEER=192.168.201.2   # client 直接连这个地址，无需 DNAT
PCAP_FILE=/tmp/phantun-test.pcap
SERVER_PID=; CLIENT_PID=; ECHO_PID=; TCPDUMP_PID=
PASS=0; FAIL=0

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { log "PASS: $*"; PASS=$((PASS+1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL+1)); }

cleanup() {
    log "清理..."
    kill "$SERVER_PID" "$CLIENT_PID" "$ECHO_PID" "$TCPDUMP_PID" 2>/dev/null || true
    $NFT delete table ip phantun_test 2>/dev/null || true
    rm -f "$PCAP_FILE"
    log "结果: PASS=$PASS  FAIL=$FAIL"
    [[ $FAIL -eq 0 ]]
}
trap cleanup EXIT

for cmd in tcpdump socat tshark; do
    command -v "$cmd" >/dev/null || { echo "缺少: $cmd"; exit 1; }
done
[[ -x /sbin/nft ]] || { echo "缺少: nft"; exit 1; }
[[ -x "$CLIENT_BIN" && -x "$SERVER_BIN" ]] || { echo "缺少二进制"; exit 1; }

echo 1 > /proc/sys/net/ipv4/ip_forward

# 只需要允许 FORWARD，不需要 DNAT/MASQUERADE
# client TUN(192.168.200.x) → server TUN(192.168.201.x) 通过内核路由直连
log "配置 nftables FORWARD..."
$NFT add table ip phantun_test
$NFT add chain ip phantun_test forward '{ type filter hook forward priority 0; policy accept; }'

log "启动 UDP echo (port $WG_PORT)..."
socat UDP-LISTEN:$WG_PORT,fork PIPE &
ECHO_PID=$!
sleep 0.3

log "启动 Phantun Server (TUN peer=$SERVER_TUN_PEER)..."
RUST_LOG=info "$SERVER_BIN" \
    --local $PHANTUN_PORT \
    --remote 127.0.0.1:$WG_PORT \
    --tun-local $SERVER_TUN_LOCAL \
    --tun-peer  $SERVER_TUN_PEER \
    --ipv4-only &
SERVER_PID=$!
sleep 1

log "启动 tcpdump 捕获 SYN (port $PHANTUN_PORT)..."
tcpdump -i any -nn -c 5 \
    "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and port $PHANTUN_PORT" \
    -w "$PCAP_FILE" 2>/dev/null &
TCPDUMP_PID=$!
sleep 0.3

# client 直接连 SERVER_TUN_PEER:PHANTUN_PORT，绕过 DNAT 复杂性
log "启动 Phantun Client (remote=$SERVER_TUN_PEER:$PHANTUN_PORT)..."
RUST_LOG=info "$CLIENT_BIN" \
    --local  127.0.0.1:$CLIENT_UDP \
    --remote $SERVER_TUN_PEER:$PHANTUN_PORT \
    --tun-local $CLIENT_TUN_LOCAL \
    --tun-peer  $CLIENT_TUN_PEER \
    --ipv4-only &
CLIENT_PID=$!
sleep 1

log "=== 测试 1: 数据通路 ==="
TEST_MSG="PHANTUN_ISN_TEST_$(date +%s)"
RECV=$(echo "$TEST_MSG" | timeout 5 socat - UDP:127.0.0.1:$CLIENT_UDP 2>/dev/null || true)
if [[ "$RECV" == "$TEST_MSG" ]]; then
    pass "数据往返正常"
else
    fail "数据往返异常 (发='$TEST_MSG' 收='$RECV')"
fi

log "=== 测试 2: ISN 随机化 ==="
sleep 2
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

SEQS=$(tshark -r "$PCAP_FILE" \
    -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e tcp.seq_raw 2>/dev/null || true)

if [[ -z "$SEQS" ]]; then
    fail "未捕获到 SYN 包"
else
    log "捕获到 SYN seq 值: $(echo $SEQS | tr '\n' ' ')"
    FOUND_ZERO=0
    for seq in $SEQS; do [[ "$seq" == "0" ]] && FOUND_ZERO=1; done
    if [[ $FOUND_ZERO -eq 1 ]]; then
        fail "存在 seq=0，ISN 随机化未生效"
    else
        pass "所有 SYN seq 非零，ISN 随机化正常"
    fi
fi
