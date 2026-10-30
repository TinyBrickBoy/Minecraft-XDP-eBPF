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
ip -n cl addr add 10.99.0.2/24 dev c1; ip -n cl addr add 10.99.0.3/24 dev c1; ip -n cl addr add 10.99.0.4/24 dev c1; ip -n cl addr add 10.99.0.5/24 dev c1; ip -n cl addr add 10.99.0.6/24 dev c1; ip -n cl addr add 10.99.0.7/24 dev c1; ip -n cl addr add 10.99.0.8/24 dev c1; ip -n cl addr add 10.99.0.9/24 dev c1; ip -n cl link set c1 up; ip -n cl route add default via 10.99.0.1
ip -n sv addr add 10.99.1.2/24 dev s1; ip -n sv link set s1 up; ip -n sv route add default via 10.99.1.1
sysctl -qw net.ipv4.ip_forward=1
# upstream DDoS protection: a GRE tunnel (no link layer header) that delivers
# traffic of the client 10.99.6.2
ip link add gre-t type gre local 10.99.0.1 remote 10.99.0.2; ip addr add 100.64.0.5/31 dev gre-t; ip link set gre-t up
ip route add 10.99.6.0/24 dev gre-t; sysctl -qw net.ipv4.conf.gre-t.rp_filter=0 net.ipv4.conf.all.rp_filter=0
ip -n cl link add gre-t type gre local 10.99.0.2 remote 10.99.0.1; ip -n cl addr add 100.64.0.4/31 dev gre-t; ip -n cl link set gre-t up
ip -n cl addr add 10.99.6.2/32 dev lo; ip -n cl rule add from 10.99.6.2 lookup 100; ip -n cl route add default dev gre-t table 100
# customer prefix like on the router: unreachable /24, one address routed
ip route add unreachable 10.99.3.0/24
ip -n sv addr add 10.99.3.7/32 dev lo
ip route add 10.99.3.7/32 via 10.99.1.2
ip netns exec sv $MC udp-echo-server 10.99.3.7 40001 &
ip netns exec sv $MC udp-echo-server 10.99.3.7 53 &   # "DNS server" (echoes the query id)
# veth + generic XDP: keep segments MTU sized like a real NIC would
for dev in c0 s0; do ethtool -K $dev gro off gso off tso off >/dev/null 2>&1; done
ip netns exec cl ethtool -K c1 gso off tso off >/dev/null 2>&1
ip netns exec sv ethtool -K s1 gso off tso off >/dev/null 2>&1

ip netns exec sv $MC java-server 0.0.0.0 25565 & 
ip netns exec sv $MC java-online-server 0.0.0.0 25575 &
ip netns exec sv $MC bedrock-server 0.0.0.0 19132 &
ip netns exec sv $MC echo-server 0.0.0.0 8000 &
ip netns exec sv $MC udp-echo-server 0.0.0.0 40000 &
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=e2e -days 1 -keyout $T/key.pem -out $T/cert.pem 2>/dev/null
ip netns exec sv $MC http-server 0.0.0.0 8081 &
ip netns exec sv $MC http-server 0.0.0.0 80 &
ip netns exec sv $MC https-server 0.0.0.0 8443 $T/cert.pem $T/key.pem &
# "internet" side: a resolver and a udp service the customers talk to
ip netns exec cl $MC udp-echo-server 10.99.0.2 53 &
ip netns exec cl $MC udp-echo-server 10.99.0.2 7000 &
$MC java-server 10.99.2.1 25570 &
$MC udp-echo-server 10.99.0.1 40100 &   # a service on the router itself
sleep 1

echo "== sessions established before the filter starts"
cl $MC player 10.99.1.2 25565 45 & PLAYER=$!
cl $MC bedrock-session 10.99.1.2 19132 45 & BEDROCK=$!
cl $MC http-keepalive 10.99.1.2 8081 45 & KEEPALIVE=$!
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
[reflection]
mode = "enforce"
networks = ["10.99.1.0/24", "10.99.2.0/24"]
reply_window_secs = 5
[blocklist]
file = "$T/blocklist.txt"
reload_secs = 1
auto_after_bans = 2
auto_window_secs = 600
auto_duration_secs = 120
auto_idle_secs = 12
auto_state_file = "$T/auto-blocklist.json"
whitelist_file = "$T/whitelist.txt"
dns_recheck_secs = 30
[ratelimit]
mode = "enforce"
networks = ["10.99.1.0/24", "10.99.3.0/24"]
pps = 1000
ban_secs = 5
allow = ["10.99.0.4/32"]
strikes = 20
strike_window_secs = 10
[unused]
enabled = true
networks = ["10.99.3.0/24"]
[xdp]
mode = "skb"
extra_interfaces = ["gre-t", "gre-missing"]
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
    cl $MC status 10.99.1.2 25565 >/dev/null; cl $MC bedrock-ping 10.99.1.2 19132 >/dev/null
    cl $MC http-get 10.99.1.2 8081 >/dev/null; cl $MC http-get 10.99.1.2 80 >/dev/null; cl $MC https-get 10.99.1.2 8443 >/dev/null
    sleep 0.4
done
cl $MC echo 10.99.1.2 8000 >/dev/null
# probes run one after another (unreachable candidates cost a timeout each),
# so wait for every expected target instead of a fixed time
for i in $(seq 1 60); do
    # the sniffer samples 1 in 4 server replies: keep the traffic coming
    cl $MC http-get 10.99.1.2 8081 >/dev/null; cl $MC http-get 10.99.1.2 80 >/dev/null
    cl $MC https-get 10.99.1.2 8443 >/dev/null; cl $MC status 10.99.1.2 25565 >/dev/null
    cl $MC bedrock-ping 10.99.1.2 19132 >/dev/null; cl $MC status 10.99.1.2 25575 >/dev/null
    n=0
    for t in 10.99.1.2:25565/tcp 10.99.1.2:19132/udp 10.99.2.1:25570/tcp 10.99.1.2:25575/tcp; do
        grep -q "Target $t: " $T/loader.log && n=$((n+1))
    done
    [ $n -ge 4 ] && break; sleep 1
done
curl -s 127.0.0.1:1999/metrics | grep '^minecraft_target_protected{' | sed 's/^/        /'
check "remote java detected"   grep -q 'Target 10.99.1.2:25565/tcp: java (auto)' $T/loader.log
check "remote bedrock detected" grep -q 'Target 10.99.1.2:19132/udp: bedrock (auto)' $T/loader.log
check "local java detected"    grep -q 'Target 10.99.2.1:25570/tcp: java (auto)' $T/loader.log
check "echo service not protected" bash -c "! grep -q '10.99.1.2:8000' $T/loader.log"
check "web servers not protected" bash -c "! grep -qE 'Target 10.99.1.2:(8081|80|8443)/tcp' $T/loader.log"

echo "== waiting for the grace window to end"
sleep 17
check "java status works"           cl $MC status 10.99.1.2 25565
check "java local status works"     cl $MC status 10.99.2.1 25570
check "java new player works"       cl $MC player 10.99.1.2 25565 3
check "java garbage dropped"        cl $MC garbage 10.99.1.2 25565
G="env E2E_BIND=10.99.6.2"
check "filter attached to the gre tunnel" grep -q 'Filter attached to gre-t in skb mode (xdp.*no link layer header' $T/loader.log
check "missing extra interface skipped" grep -q 'Interface gre-missing does not exist yet' $T/loader.log
check "java status through the gre tunnel" cl $G $MC status 10.99.1.2 25565
check "java garbage through the gre tunnel dropped" cl $G $MC garbage 10.99.1.2 25565
check "java local garbage dropped"  cl $MC garbage 10.99.2.1 25570
check "unprotected service works"   cl $MC echo 10.99.1.2 8000
check "bedrock ping works"          cl $MC bedrock-ping 10.99.1.2 19132
check "bedrock new session works"   cl $MC bedrock-session 10.99.1.2 19132 3
check "bedrock garbage dropped"     cl $MC bedrock-garbage 10.99.1.2 19132
check "old java player survived"    wait $PLAYER
check "old bedrock session survived" wait $BEDROCK
check "old http keep-alive survived" wait $KEEPALIVE

echo "== online mode"
check "offline uuid ok before online mode is known" cl $MC login-uuid 10.99.1.2 25575 3
check "premium login gets encryption request"      cl $MC login-uuid 10.99.1.2 25575 4
sleep 2
check "server detected as online mode"             grep -q 'Target 10.99.1.2:25575/tcp: online mode' $T/loader.log
check "offline uuid rejected on online server"     cl $MC login-uuid-rejected 10.99.1.2 25575 3
check "premium login still works"                  cl $MC login-uuid 10.99.1.2 25575 4
check "floodgate-style uuid (v0) still works"      cl $MC login-uuid 10.99.1.2 25575 0
check "offline uuid fine on offline server"        cl $MC login-uuid 10.99.1.2 25565 3
check "rejections counted"                         bash -c "curl -s 127.0.0.1:1999/metrics | awk '\$1==\"minecraft_offline_rejected\"{exit !(\$2>=1)}'"

echo "== web (not filtered)"
check "http request works"        cl $MC http-get 10.99.1.2 8081
check "http on port 80 works"     cl $MC http-get 10.99.1.2 80
check "https request works"       cl $MC https-get 10.99.1.2 8443
check "http junk reaches the server" bash -c "! ip netns exec cl $MC tcp-junk 10.99.1.2 8081"
check "new http keep-alive works" cl $MC http-keepalive 10.99.1.2 8081 3

echo "== udp reflection protection"
check "recorder attached"              grep -q 'reflection protection: enforcing' $T/loader.log
check "customer dns query answered"    ip netns exec sv $MC udp-echo 10.99.0.2 53
check "customer udp traffic works"     ip netns exec sv $MC udp-echo 10.99.0.2 7000
check "inbound udp works"              cl $MC udp-echo 10.99.1.2 40000 5000
# the "reflector" sends from its own address, 10.99.0.2:53 is the resolver
check "unsolicited dns answer dropped" cl env E2E_BIND=10.99.0.3 $MC udp-no-echo 10.99.1.2 40000 53
check "unsolicited ntp answer dropped" cl env E2E_BIND=10.99.0.3 $MC udp-no-echo 10.99.1.2 40000 123
check "fragmented flood dropped"       cl $MC udp-no-echo 10.99.1.2 40000 5001 3000
check "big answer to own query passes" ip netns exec sv $MC udp-echo 10.99.0.2 7000 0 1400
sleep 2
dns=$(curl -s 127.0.0.1:1999/metrics | awk '/^xdp_reflection_packets\{.*service="dns"/{s+=$2} END{print s+0}')
frag=$(curl -s 127.0.0.1:1999/metrics | awk '/^xdp_reflection_packets\{.*service="fragment"/{s+=$2} END{print s+0}')
check "reflection metrics (dns $dns, fragments $frag)" test "$dns" -ge 1 -a "$frag" -ge 1

echo "== unused addresses"
check "routed customer address works"  cl $MC udp-echo 10.99.3.7 40001
check "unused address dropped"         cl $MC udp-no-echo 10.99.3.5 40000
cl $MC garbage 10.99.3.9 25565 >/dev/null
sleep 2
unused=$(curl -s 127.0.0.1:1999/metrics | awk '/^xdp_unused_packets\{dst_ip="10.99.3.(5|9)"/{s+=$2} END{print s+0}')
check "unused drops counted ($unused)" test "$unused" -ge 2
check "routed address not counted" bash -c "! curl -s 127.0.0.1:1999/metrics | grep -q 'xdp_unused_packets{dst_ip=\"10.99.3.7\"'"

echo "== blocklist"
B="env E2E_BIND=10.99.0.3"
check "unblocked source works"        cl $B $MC udp-echo 10.99.1.2 40000 5002
echo "10.99.0.3   # e2e" > $T/blocklist.txt; sleep 3
check "blocklisted source dropped"    cl $B $MC udp-no-echo 10.99.1.2 40000 5002
check "other source still works"      cl $MC udp-echo 10.99.1.2 40000 5003
check "blocklist hits per source"     bash -c "curl -s 127.0.0.1:1999/metrics | grep -q 'xdp_blocklist_source_packets{src_ip=\"10.99.0.3\"}'"
: > $T/blocklist.txt; sleep 3
check "removed entry works again"     cl $B $MC udp-echo 10.99.1.2 40000 5002
echo "10.99.0.5   # e2e" > $T/blocklist.txt; echo "10.99.0.5   # whitelisted" > $T/whitelist.txt; sleep 3
check "whitelist gets past the blocklist" cl env E2E_BIND=10.99.0.5 $MC udp-echo 10.99.1.2 40000 5012
cl env E2E_BIND=10.99.0.5 $MC udp-flood 10.99.1.2 40000 4000
check "whitelisted source never banned" cl env E2E_BIND=10.99.0.5 $MC udp-echo 10.99.1.2 40000 5013
: > $T/whitelist.txt; sleep 3
check "without whitelist it is blocked" cl env E2E_BIND=10.99.0.5 $MC udp-no-echo 10.99.1.2 40000 5014
: > $T/blocklist.txt; sleep 3

echo "== rate limit"
cl $B $MC udp-flood 10.99.1.2 40000 4000
check "flooding source banned"        cl $B $MC udp-no-echo 10.99.1.2 40000 5004
check "other source not affected"     cl $MC udp-echo 10.99.1.2 40000 5005
cl env E2E_BIND=10.99.0.4 $MC udp-flood 10.99.1.2 40000 4000
check "allowlisted source not banned" cl env E2E_BIND=10.99.0.4 $MC udp-echo 10.99.1.2 40000 5006
# a download the server started itself (QUIC to port 443): the answer is fast
ip netns exec sv $MC dns-answer 10.99.0.9 443 0
cl env E2E_BIND=10.99.0.9 $MC udp-flood 10.99.1.2 40000 4000
check "outbound recorder attached"  bash -c "! grep -q 'outbound recorder failed' $T/loader.log"
check "answers to the server's own traffic not banned" cl env E2E_BIND=10.99.0.9 $MC udp-echo 10.99.1.2 40000 5007
sleep 3
bans=$(metric xdp_ratelimit_bans)
check "ban counted and logged ($bans)" bash -c "test '${bans:-0}' -ge 1 && grep -q 'Rate limit: banned 10.99.0.3' $T/loader.log"
sleep 3
check "ban expires"                   cl $B $MC udp-echo 10.99.1.2 40000 5007

echo "== violations (scanner)"
S5="env E2E_BIND=10.99.0.5"
check "scanner works before"          cl $S5 $MC udp-echo 10.99.1.2 40000 5010
SCAN=""; for i in $(seq 1 30); do cl $S5 $MC udp-echo 10.99.3.$((i+20)) 40000 5011 >/dev/null 2>&1 & SCAN="$SCAN $!"; done
wait $SCAN  # only the scanner probes, not the background servers
sleep 2
check "scanner banned (violations)"   cl $S5 $MC udp-no-echo 10.99.1.2 40000 5012
check "logged as violations"          grep -q 'banned 10.99.0.5 .*violations' $T/loader.log
check "banned source still reaches the router itself" cl $S5 $MC udp-echo 10.99.0.1 40100 5013

echo "== penalty box"
P7="env E2E_BIND=10.99.0.7"; P8="env E2E_BIND=10.99.0.8"
check "redirect rules installed"      bash -c "nft list table ip xdp_penalty | grep -q 'dnat to 10.99.0.1:25599'"
check "real client: server list ping" cl $P7 $MC status 10.99.1.2 25565
cl $P7 $MC connect-spam 10.99.1.2 25565 15
check "throttled real client gets the please-wait message" cl $P7 $MC penalty-message 10.99.1.2 25565
cl $P8 $MC connect-spam 10.99.1.2 25565 15
check "unknown (spoofable) source is just dropped"         cl $P8 $MC no-penalty-message 10.99.1.2 25565
sleep 11
check "after the penalty the real server works again"     cl $P7 $MC status 10.99.1.2 25565

echo "== DNS scanners"
D6="env E2E_BIND=10.99.0.6"; D7="env E2E_BIND=10.99.0.7"
check "dns scanner works before"      cl $D6 $MC udp-echo 10.99.1.2 40000 5020
cl $D6 $MC udp-echo 10.99.1.2 53 5021 >/dev/null 2>&1   # query where no DNS server runs
cl $D7 $MC udp-echo 10.99.3.7 53 5022 >/dev/null 2>&1   # query to a real DNS server
cl $P8 $MC dns-answer 10.99.1.2 53 53       # reflected answers (attack on us)
cl $P8 $MC dns-answer 10.99.1.2 53 40053
sleep 5
grep "^10.99.0.8 " $T/blocklist.txt; check "reflected dns answers don't blocklist the resolver" bash -c "! grep -q '^10.99.0.8 .*dns-scan' $T/blocklist.txt"
check "dns scanner blocklisted"       grep -q '^10.99.0.6 .*dns-scan' $T/blocklist.txt
check "dns scanner dropped"           cl $D6 $MC udp-no-echo 10.99.1.2 40000 5023
check "dns scanner reaches the router" cl $D6 $MC udp-echo 10.99.0.1 40100 5024
check "legit dns client not blocked"  bash -c "! grep -q '^10.99.0.7 ' $T/blocklist.txt"
check "dns server answers its client" cl $D7 $MC udp-echo 10.99.3.7 53 5025
check "dns entry expires like the other auto entries" grep -q '^10.99.0.6 .*auto until=.*dns-scan' $T/blocklist.txt

echo "== automatic blocklist"
check "1st ban not yet blocklisted"   bash -c "! grep -q 'auto until=.*rate limit bans' $T/blocklist.txt"
cl $B $MC udp-flood 10.99.1.2 40000 4000; sleep 3
check "2nd ban writes auto entry"     grep -q '^10.99.0.3 .*auto until=' $T/blocklist.txt
sleep 4
check "still dropped after the ban"   cl $B $MC udp-no-echo 10.99.1.2 40000 5008
check "auto entries counted"          bash -c "test \"\$(curl -s 127.0.0.1:1999/metrics | awk '\$1==\"xdp_blocklist_auto_entries\"{print \$2}')\" -ge 1"
check "logged"                        grep -q 'Auto blocklist: 10.99.0.3 banned 2 times' $T/loader.log
# the source stays silent now: removed after auto_idle_secs, long before auto_duration_secs
for i in $(seq 1 40); do grep -q 'auto until=.*rate limit bans' $T/blocklist.txt || break; sleep 1; done
check "idle auto entry removed"       bash -c "! grep -q 'auto until=.*rate limit bans' $T/blocklist.txt && grep -q 'Auto blocklist: 10.99.0.3 sent nothing' $T/loader.log"
sleep 2
check "works again after expiry"      cl $B $MC udp-echo 10.99.1.2 40000 5009

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
check "targets restored from state" grep -q 'Restored 4 detected server' $T/loader.log
check "java player survived restart"    wait $PLAYER
check "bedrock session survived restart" wait $BEDROCK
sleep 13
check "garbage dropped after restart" cl $MC garbage 10.99.1.2 25565

kill $LOADER; wait $LOADER 2>/dev/null
grep -E 'WARN|ERROR' $T/loader.log | sed 's/^/        /'
echo "== $FAILS failure(s)"
kill $(jobs -p) 2>/dev/null
exit $((FAILS > 0))
