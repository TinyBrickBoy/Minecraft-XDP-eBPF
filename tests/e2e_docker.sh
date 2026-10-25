#!/bin/bash
# End-to-end test of the filter with auto detection, run inside a privileged
# docker container so every interface and namespace stays in the container:
#
#   docker run --rm --privileged -v "$PWD:/src" -w /src xdp-build:local tests/e2e_docker.sh
#
# Topology (all inside the container):
#   ns cl (clients, 10.99.0.2) --veth c1/c0--> container (XDP on c0)
#   container --veth s0/s1--> ns sv (remote servers, 10.99.1.2, "tunnel")
#   container dummy0 10.99.2.1: local java server, detected via /proc
set -u
cd "$(dirname "$0")/.."
BIN=${BIN:-target/release/xdp-loader}
T=$(mktemp -d)
MC="python3 tests/e2e_mc.py"
FAILS=0
pass() { echo "  ok    $1"; }
fail() { echo "  FAIL  $1"; FAILS=$((FAILS + 1)); }
check() { local name=$1; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
cl() { ip netns exec cl "$@"; }
metric() { curl -s 127.0.0.1:1999/metrics | awk -v m="$1" '$1==m{print $2}'; }

ip netns add cl; ip netns add sv
ip link add c0 type veth peer name c1; ip link set c1 netns cl
ip link add s0 type veth peer name s1; ip link set s1 netns sv
ip addr add 10.99.0.1/24 dev c0; ip link set c0 up
ip addr add 10.99.1.1/24 dev s0; ip link set s0 up
ip link add dummy0 type dummy; ip addr add 10.99.2.1/32 dev dummy0; ip link set dummy0 up
for ns in cl sv; do ip -n $ns link set lo up; done
ip -n cl addr add 10.99.0.2/24 dev c1; ip -n cl link set c1 up; ip -n cl route add default via 10.99.0.1
ip -n sv addr add 10.99.1.2/24 dev s1; ip -n sv link set s1 up; ip -n sv route add default via 10.99.1.1
sysctl -qw net.ipv4.ip_forward=1
# veth + generic XDP: keep segments MTU sized like a real NIC would
for dev in c0 s0; do ethtool -K $dev gro off gso off tso off >/dev/null 2>&1; done
ip netns exec cl ethtool -K c1 gso off tso off >/dev/null 2>&1
ip netns exec sv ethtool -K s1 gso off tso off >/dev/null 2>&1

ip netns exec sv $MC java-server 0.0.0.0 25565 & 
ip netns exec sv $MC bedrock-server 0.0.0.0 19132 &
ip netns exec sv $MC echo-server 0.0.0.0 8000 &
$MC java-server 10.99.2.1 25570 &
sleep 1

echo "== sessions established before the filter starts"
cl $MC player 10.99.1.2 25565 45 & PLAYER=$!
cl $MC bedrock-session 10.99.1.2 19132 45 & BEDROCK=$!
sleep 2

cat > $T/config.toml <<CONF
[filter]
start_port = 0
end_port = 0
adopt_grace_secs = 15
online_names = false
[autodetect]
enabled = true
networks = ["10.99.1.0/24", "10.99.2.0/24"]
sniff_interfaces = ["s0"]
probe_interval_secs = 10
state_file = "$T/targets.json"
[xdp]
mode = "skb"
[metrics]
enabled = true
addr = "127.0.0.1:1999"
poll_secs = 1
[logging]
level = "info"
CONF
start_loader() { (cd $T && exec "$OLDPWD/$BIN" --config $T/config.toml c0 >> $T/loader.log 2>&1) & LOADER=$!; }
start_loader

echo "== detection"
# server list pings make the remote servers answer through the "tunnel";
# paced below the per ip throttle (hit_count 10 per 3 s)
for i in $(seq 1 12); do
    cl $MC status 10.99.1.2 25565 >/dev/null; cl $MC bedrock-ping 10.99.1.2 19132 >/dev/null; sleep 0.4
done
cl $MC echo 10.99.1.2 8000 >/dev/null
for i in $(seq 1 30); do
    n=$(curl -s 127.0.0.1:1999/metrics | grep -c '^minecraft_target_protected{')
    [ "$n" -ge 3 ] && break; sleep 1
done
curl -s 127.0.0.1:1999/metrics | grep '^minecraft_target_protected{' | sed 's/^/        /'
check "remote java detected"   grep -q 'Target 10.99.1.2:25565/tcp: java (auto)' $T/loader.log
check "remote bedrock detected" grep -q 'Target 10.99.1.2:19132/udp: bedrock (auto)' $T/loader.log
check "local java detected"    grep -q 'Target 10.99.2.1:25570/tcp: java (auto)' $T/loader.log
check "echo service not protected" bash -c "! grep -q '10.99.1.2:8000' $T/loader.log"

echo "== waiting for the grace window to end"
sleep 17
check "java status works"           cl $MC status 10.99.1.2 25565
check "java local status works"     cl $MC status 10.99.2.1 25570
check "java new player works"       cl $MC player 10.99.1.2 25565 3
check "java garbage dropped"        cl $MC garbage 10.99.1.2 25565
check "java local garbage dropped"  cl $MC garbage 10.99.2.1 25570
check "unprotected service works"   cl $MC echo 10.99.1.2 8000
check "bedrock ping works"          cl $MC bedrock-ping 10.99.1.2 19132
check "bedrock new session works"   cl $MC bedrock-session 10.99.1.2 19132 3
check "bedrock garbage dropped"     cl $MC bedrock-garbage 10.99.1.2 19132
check "old java player survived"    wait $PLAYER
check "old bedrock session survived" wait $BEDROCK
adopted=$(metric minecraft_adopted_connections)
check "connections adopted (${adopted:-0})" test "${adopted:-0}" -ge 2

echo "== restart with running sessions"
cl $MC player 10.99.1.2 25565 20 & PLAYER=$!
cl $MC bedrock-session 10.99.1.2 19132 20 & BEDROCK=$!
sleep 3
kill $LOADER; wait $LOADER 2>/dev/null
check "filter detached on stop" bash -c "! ip link show c0 | grep -q xdp"
start_loader
sleep 3
check "targets restored from state" grep -q 'Restored 3 detected server' $T/loader.log
check "java player survived restart"    wait $PLAYER
check "bedrock session survived restart" wait $BEDROCK
sleep 13
check "garbage dropped after restart" cl $MC garbage 10.99.1.2 25565

kill $LOADER; wait $LOADER 2>/dev/null
grep -E 'WARN|ERROR' $T/loader.log | sed 's/^/        /'
echo "== $FAILS failure(s)"
kill $(jobs -p) 2>/dev/null
exit $((FAILS > 0))
