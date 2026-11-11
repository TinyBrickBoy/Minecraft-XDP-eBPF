#!/bin/bash
# End-to-end test of the filter with auto detection, run inside a privileged
# docker container so every interface and namespace stays in the container:
#
#   docker run --rm --privileged -v "$PWD:/src" -w /src xdp-build:local tests/e2e_docker.sh
#
# Topology (all inside the container), dual-stack:
#   ns cl (clients, 10.99.0.2 / fd99::2) --veth c1/c0--> container (XDP on c0)
#   container --veth s0/s1--> ns sv (remote servers, 10.99.1.2 / fd99:1::2, "tunnel")
#   container dummy0 10.99.2.1 / fd99:2::1: local java server, detected via /proc
# Every IPv4 scenario also runs over IPv6; the IPv6 client sources
# fd99:0:0:N::2 mirror 10.99.0.N, each in its own /64 (sources are counted
# per /64).
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
# docker disables IPv6 in containers without an IPv6 network
for ns in "" "ip netns exec cl" "ip netns exec sv"; do
    $ns sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
done
ip link add c0 type veth peer name c1; ip link set c1 netns cl
ip link add s0 type veth peer name s1; ip link set s1 netns sv
ip addr add 10.99.0.1/24 dev c0; ip link set c0 up
ip addr add 10.99.1.1/24 dev s0; ip link set s0 up
ip link add dummy0 type dummy; ip addr add 10.99.2.1/32 dev dummy0; ip link set dummy0 up
for ns in cl sv; do ip -n $ns link set lo up; done
ip -n cl addr add 10.99.0.2/24 dev c1; ip -n cl addr add 10.99.0.3/24 dev c1; ip -n cl addr add 10.99.0.4/24 dev c1; ip -n cl addr add 10.99.0.5/24 dev c1; ip -n cl addr add 10.99.0.6/24 dev c1; ip -n cl addr add 10.99.0.7/24 dev c1; ip -n cl addr add 10.99.0.8/24 dev c1; ip -n cl addr add 10.99.0.9/24 dev c1; ip -n cl link set c1 up; ip -n cl route add default via 10.99.0.1
ip -n sv addr add 10.99.1.2/24 dev s1; ip -n sv link set s1 up; ip -n sv route add default via 10.99.1.1
sysctl -qw net.ipv4.ip_forward=1
# IPv6 (ULA fd99::/16): every extra client source in its own /64; they are
# deprecated (preferred_lft 0) so only an explicit bind uses them, like the
# secondary IPv4 addresses
sysctl -qw net.ipv6.conf.all.forwarding=1
ip -6 addr add fd99:0::1/64 dev c0 nodad
ip -6 route add fd99:0::/48 dev c0
ip -n cl -6 addr add fd99:0::2/64 dev c1 nodad
for n in 3 4 5 6 7 8 9 a b; do ip -n cl -6 addr add fd99:0:0:$n::2/64 dev c1 nodad preferred_lft 0; done
ip -n cl -6 addr add fd99:0:0:a::3/64 dev c1 nodad preferred_lft 0
ip -n cl -6 route add default via fd99:0::1
ip -6 addr add fd99:1::1/64 dev s0 nodad
ip -n sv -6 addr add fd99:1::2/64 dev s1 nodad
ip -n sv -6 route add default via fd99:1::1
ip -6 addr add fd99:2::1/128 dev dummy0 nodad
# upstream DDoS protection: a GRE tunnel (no link layer header) that delivers
# traffic of the client 10.99.6.2
ip link add gre-t type gre local 10.99.0.1 remote 10.99.0.2; ip addr add 100.64.0.5/31 dev gre-t; ip link set gre-t up
ip route add 10.99.6.0/24 dev gre-t; sysctl -qw net.ipv4.conf.gre-t.rp_filter=0 net.ipv4.conf.all.rp_filter=0
ip -n cl link add gre-t type gre local 10.99.0.2 remote 10.99.0.1; ip -n cl addr add 100.64.0.4/31 dev gre-t; ip -n cl link set gre-t up
ip -n cl addr add 10.99.6.2/32 dev lo; ip -n cl rule add from 10.99.6.2 lookup 100; ip -n cl route add default dev gre-t table 100
# customer prefix like on the router: unreachable /24 (/64), one address routed
ip route add unreachable 10.99.3.0/24
ip -n sv addr add 10.99.3.7/32 dev lo
ip route add 10.99.3.7/32 via 10.99.1.2
ip -6 route add unreachable fd99:3::/64
ip -n sv -6 addr add fd99:3::7/128 dev lo nodad
ip -6 route add fd99:3::7/128 via fd99:1::2
ip netns exec sv $MC udp-echo-server 10.99.3.7 40001 &
ip netns exec sv $MC udp-echo-server 10.99.3.7 53 &   # "DNS server" (echoes the query id)
ip netns exec sv $MC udp-echo-server fd99:3::7 40001 &
ip netns exec sv $MC udp-echo-server fd99:3::7 53 &
# veth + generic XDP: keep segments MTU sized like a real NIC would
for dev in c0 s0; do ethtool -K $dev gro off gso off tso off >/dev/null 2>&1; done
ip netns exec cl ethtool -K c1 gso off tso off >/dev/null 2>&1
ip netns exec sv ethtool -K s1 gso off tso off >/dev/null 2>&1

# "::" serves both families
ip netns exec sv $MC java-server :: 25565 &
ip netns exec sv $MC java-online-server :: 25575 &
ip netns exec sv $MC bedrock-server :: 19132 &
ip netns exec sv $MC echo-server :: 8000 &
ip netns exec sv $MC udp-echo-server :: 40000 &
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=e2e -days 1 -keyout $T/key.pem -out $T/cert.pem 2>/dev/null
ip netns exec sv $MC http-server :: 8081 &
ip netns exec sv $MC http-server :: 80 &
ip netns exec sv $MC https-server :: 8443 $T/cert.pem $T/key.pem &
# "internet" side: a resolver and a udp service the customers talk to
ip netns exec cl $MC udp-echo-server 10.99.0.2 53 &
ip netns exec cl $MC udp-echo-server 10.99.0.2 7000 &
ip netns exec cl $MC udp-echo-server fd99::2 53 &
ip netns exec cl $MC udp-echo-server fd99::2 7000 &
$MC java-server 10.99.2.1 25570 &
$MC java-server fd99:2::1 25570 &
$MC udp-echo-server 10.99.0.1 40100 &   # a service on the router itself
$MC udp-echo-server fd99::1 40100 &
sleep 1

echo "== raw IPv6 helpers without the filter"
# the drop checks further down only mean something if linux itself delivers
# these packets
check "v6 2 ext headers answered unfiltered"   cl $MC v6-ext-chain fd99:1::2 19132 2
check "v6 5 ext headers answered unfiltered"   cl $MC v6-ext-chain fd99:1::2 19132 5
check "v6 atomic fragment answered unfiltered" cl $MC v6-fragment fd99:1::2 19132

echo "== sessions established before the filter starts"
cl $MC player 10.99.1.2 25565 45 & PLAYER=$!
cl $MC bedrock-session 10.99.1.2 19132 45 & BEDROCK=$!
cl $MC http-keepalive 10.99.1.2 8081 45 & KEEPALIVE=$!
cl $MC player fd99:1::2 25565 45 & PLAYER6=$!
cl $MC bedrock-session fd99:1::2 19132 45 & BEDROCK6=$!
cl $MC http-keepalive fd99:1::2 8081 45 & KEEPALIVE6=$!
sleep 2

cat > $T/config.toml <<CONF
[filter]
start_port = 0
end_port = 0
adopt_grace_secs = 15
online_names = false
[autodetect]
enabled = true
networks = ["10.99.1.0/24", "10.99.2.0/24", "fd99:1::/64", "fd99:2::/64"]
sniff_interfaces = ["s0"]
probe_interval_secs = 10
state_file = "$T/targets.json"
[reflection]
mode = "enforce"
networks = ["10.99.1.0/24", "10.99.2.0/24", "fd99:1::/64", "fd99:2::/64"]
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
networks = ["10.99.1.0/24", "10.99.3.0/24", "fd99:1::/64", "fd99:3::/64"]
pps = 1000
ban_secs = 5
allow = ["10.99.0.4/32", "fd99:0:0:4::/64"]
strikes = 20
strike_window_secs = 10
[unused]
enabled = true
networks = ["10.99.3.0/24", "fd99:3::/64"]
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
    for h in 10.99.1.2 fd99:1::2; do
        cl $MC status $h 25565 >/dev/null; cl $MC bedrock-ping $h 19132 >/dev/null
        cl $MC http-get $h 8081 >/dev/null; cl $MC http-get $h 80 >/dev/null; cl $MC https-get $h 8443 >/dev/null
    done
    sleep 0.4
done
cl $MC echo 10.99.1.2 8000 >/dev/null
cl $MC echo fd99:1::2 8000 >/dev/null
# probes run one after another (unreachable candidates cost a timeout each),
# so wait for every expected target instead of a fixed time
TARGETS="10.99.1.2:25565/tcp 10.99.1.2:19132/udp 10.99.2.1:25570/tcp 10.99.1.2:25575/tcp
         [fd99:1::2]:25565/tcp [fd99:1::2]:19132/udp [fd99:2::1]:25570/tcp [fd99:1::2]:25575/tcp"
for i in $(seq 1 60); do
    # the sniffer samples 1 in 4 server replies: keep the traffic coming
    for h in 10.99.1.2 fd99:1::2; do
        cl $MC http-get $h 8081 >/dev/null; cl $MC http-get $h 80 >/dev/null
        cl $MC https-get $h 8443 >/dev/null; cl $MC status $h 25565 >/dev/null
        cl $MC bedrock-ping $h 19132 >/dev/null; cl $MC status $h 25575 >/dev/null
    done
    n=0
    for t in $TARGETS; do
        grep -qF "Target $t: " $T/loader.log && n=$((n+1))
    done
    [ $n -ge 8 ] && break; sleep 1
done
curl -s 127.0.0.1:1999/metrics | grep '^minecraft_target_protected{' | sed 's/^/        /'
check "remote java detected"   grep -q 'Target 10.99.1.2:25565/tcp: java (auto)' $T/loader.log
check "v6 remote java detected" grep -qF 'Target [fd99:1::2]:25565/tcp: java (auto)' $T/loader.log
check "remote bedrock detected" grep -q 'Target 10.99.1.2:19132/udp: bedrock (auto)' $T/loader.log
check "v6 remote bedrock detected" grep -qF 'Target [fd99:1::2]:19132/udp: bedrock (auto)' $T/loader.log
check "local java detected"    grep -q 'Target 10.99.2.1:25570/tcp: java (auto)' $T/loader.log
check "v6 local java detected" grep -qF 'Target [fd99:2::1]:25570/tcp: java (auto)' $T/loader.log
check "echo service not protected" bash -c "! grep -qE '10.99.1.2:8000|\[fd99:1::2\]:8000' $T/loader.log"
check "web servers not protected" bash -c "! grep -qE 'Target (10.99.1.2|\[fd99:1::2\]):(8081|80|8443)/tcp' $T/loader.log"

echo "== waiting for the grace window to end"
sleep 17
check "java status works"           cl $MC status 10.99.1.2 25565
check "v6 java status works"        cl $MC status fd99:1::2 25565
check "java local status works"     cl $MC status 10.99.2.1 25570
check "v6 java local status works"  cl $MC status fd99:2::1 25570
check "java new player works"       cl $MC player 10.99.1.2 25565 3
check "v6 java new player works"    cl $MC player fd99:1::2 25565 3
check "java garbage dropped"        cl $MC garbage 10.99.1.2 25565
check "v6 java garbage dropped"     cl $MC garbage fd99:1::2 25565
G="env E2E_BIND=10.99.6.2"
check "filter attached to the gre tunnel" grep -q 'Filter attached to gre-t in skb mode (xdp.*no link layer header' $T/loader.log
check "missing extra interface skipped" grep -q 'Interface gre-missing does not exist yet' $T/loader.log
check "java status through the gre tunnel" cl $G $MC status 10.99.1.2 25565
check "java garbage through the gre tunnel dropped" cl $G $MC garbage 10.99.1.2 25565
check "java local garbage dropped"  cl $MC garbage 10.99.2.1 25570
check "v6 java local garbage dropped" cl $MC garbage fd99:2::1 25570
check "unprotected service works"   cl $MC echo 10.99.1.2 8000
check "v6 unprotected service works" cl $MC echo fd99:1::2 8000
check "bedrock ping works"          cl $MC bedrock-ping 10.99.1.2 19132
check "v6 bedrock ping works"       cl $MC bedrock-ping fd99:1::2 19132
check "bedrock new session works"   cl $MC bedrock-session 10.99.1.2 19132 3
check "v6 bedrock new session works" cl $MC bedrock-session fd99:1::2 19132 3
check "bedrock garbage dropped"     cl $MC bedrock-garbage 10.99.1.2 19132
check "v6 bedrock garbage dropped"  cl $MC bedrock-garbage fd99:1::2 19132
check "old java player survived"    wait $PLAYER
check "v6 old java player survived" wait $PLAYER6
check "old bedrock session survived" wait $BEDROCK
check "v6 old bedrock session survived" wait $BEDROCK6
check "old http keep-alive survived" wait $KEEPALIVE
check "v6 old http keep-alive survived" wait $KEEPALIVE6

echo "== ipv6: extension headers and fragments to a protected target"
check "v6 ping without ext headers"          cl $MC v6-ext-chain fd99:1::2 19132 0
check "v6 2 ext headers to target pass"      cl $MC v6-ext-chain fd99:1::2 19132 2
check "v6 5 ext headers to target dropped"   bash -c "! ip netns exec cl $MC v6-ext-chain fd99:1::2 19132 5"
check "v6 atomic fragment to target dropped" bash -c "! ip netns exec cl $MC v6-fragment fd99:1::2 19132"

echo "== ipv6: connection throttle per /64"
# a burst from one /64 exceeds hit_count (10 per 3 s): another address of
# the same /64 is throttled too, a source in another /64 still gets through
cl env E2E_BIND=fd99:0:0:a::2 $MC connect-spam fd99:1::2 25565 15
check "v6 same /64 throttled"     cl env E2E_BIND=fd99:0:0:a::3 $MC syn-dropped fd99:1::2 25565
check "v6 other /64 unaffected"   cl env E2E_BIND=fd99:0:0:b::2 $MC status fd99:1::2 25565

echo "== online mode"
check "offline uuid ok before online mode is known" cl $MC login-uuid 10.99.1.2 25575 3
check "v6 offline uuid ok before online mode is known" cl $MC login-uuid fd99:1::2 25575 3
check "premium login gets encryption request"      cl $MC login-uuid 10.99.1.2 25575 4
check "v6 premium login gets encryption request"   cl $MC login-uuid fd99:1::2 25575 4
sleep 2
check "server detected as online mode"             grep -q 'Target 10.99.1.2:25575/tcp: online mode' $T/loader.log
check "v6 server detected as online mode"          grep -qF 'Target [fd99:1::2]:25575/tcp: online mode' $T/loader.log
check "offline uuid rejected on online server"     cl $MC login-uuid-rejected 10.99.1.2 25575 3
check "v6 offline uuid rejected on online server"  cl $MC login-uuid-rejected fd99:1::2 25575 3
check "premium login still works"                  cl $MC login-uuid 10.99.1.2 25575 4
check "v6 premium login still works"               cl $MC login-uuid fd99:1::2 25575 4
check "floodgate-style uuid (v0) still works"      cl $MC login-uuid 10.99.1.2 25575 0
check "v6 floodgate-style uuid (v0) still works"   cl $MC login-uuid fd99:1::2 25575 0
check "offline uuid fine on offline server"        cl $MC login-uuid 10.99.1.2 25565 3
check "v6 offline uuid fine on offline server"     cl $MC login-uuid fd99:1::2 25565 3
check "rejections counted"                         bash -c "curl -s 127.0.0.1:1999/metrics | awk '\$1==\"minecraft_offline_rejected\"{exit !(\$2>=2)}'"

echo "== web (not filtered)"
check "http request works"        cl $MC http-get 10.99.1.2 8081
check "v6 http request works"     cl $MC http-get fd99:1::2 8081
check "http on port 80 works"     cl $MC http-get 10.99.1.2 80
check "v6 http on port 80 works"  cl $MC http-get fd99:1::2 80
check "https request works"       cl $MC https-get 10.99.1.2 8443
check "v6 https request works"    cl $MC https-get fd99:1::2 8443
check "http junk reaches the server" bash -c "! ip netns exec cl $MC tcp-junk 10.99.1.2 8081"
check "v6 http junk reaches the server" bash -c "! ip netns exec cl $MC tcp-junk fd99:1::2 8081"
check "new http keep-alive works" cl $MC http-keepalive 10.99.1.2 8081 3
check "v6 new http keep-alive works" cl $MC http-keepalive fd99:1::2 8081 3

echo "== udp reflection protection"
check "recorder attached"              grep -q 'reflection protection: enforcing' $T/loader.log
check "customer dns query answered"    ip netns exec sv $MC udp-echo 10.99.0.2 53
check "v6 customer dns query answered" ip netns exec sv $MC udp-echo fd99::2 53
check "customer udp traffic works"     ip netns exec sv $MC udp-echo 10.99.0.2 7000
check "v6 customer udp traffic works"  ip netns exec sv $MC udp-echo fd99::2 7000
check "inbound udp works"              cl $MC udp-echo 10.99.1.2 40000 5000
check "v6 inbound udp works"           cl $MC udp-echo fd99:1::2 40000 5000
# the "reflector" sends from its own address, 10.99.0.2:53 is the resolver
check "unsolicited dns answer dropped" cl env E2E_BIND=10.99.0.3 $MC udp-no-echo 10.99.1.2 40000 53
check "v6 unsolicited dns answer dropped" cl env E2E_BIND=fd99:0:0:3::2 $MC udp-no-echo fd99:1::2 40000 53
check "unsolicited ntp answer dropped" cl env E2E_BIND=10.99.0.3 $MC udp-no-echo 10.99.1.2 40000 123
check "v6 unsolicited ntp answer dropped" cl env E2E_BIND=fd99:0:0:3::2 $MC udp-no-echo fd99:1::2 40000 123
check "fragmented flood dropped"       cl $MC udp-no-echo 10.99.1.2 40000 5001 3000
check "v6 fragmented flood dropped"    cl $MC udp-no-echo fd99:1::2 40000 5001 3000
check "big answer to own query passes" ip netns exec sv $MC udp-echo 10.99.0.2 7000 0 1400
check "v6 big answer to own query passes" ip netns exec sv $MC udp-echo fd99::2 7000 0 1400
sleep 2
refl() { curl -s 127.0.0.1:1999/metrics | awk -v ip="$1" -v svc="$2" 'index($0, "xdp_reflection_packets{dst_ip=\"" ip "\"") == 1 && index($0, "service=\"" svc "\"") {s+=$2} END{print s+0}'; }
dns=$(refl 10.99.1.2 dns); frag=$(refl 10.99.1.2 fragment)
check "reflection metrics (dns $dns, fragments $frag)" test "$dns" -ge 1 -a "$frag" -ge 1
dns=$(refl fd99:1::2 dns); frag=$(refl fd99:1::2 fragment)
check "v6 reflection metrics (dns $dns, fragments $frag)" test "$dns" -ge 1 -a "$frag" -ge 1

echo "== unused addresses"
check "routed customer address works"  cl $MC udp-echo 10.99.3.7 40001
check "v6 routed customer address works" cl $MC udp-echo fd99:3::7 40001
check "unused address dropped"         cl $MC udp-no-echo 10.99.3.5 40000
check "v6 unused address dropped"      cl $MC udp-no-echo fd99:3::5 40000
cl $MC garbage 10.99.3.9 25565 >/dev/null
cl $MC garbage fd99:3::9 25565 >/dev/null
sleep 2
unused=$(curl -s 127.0.0.1:1999/metrics | awk '/^xdp_unused_packets\{dst_ip="10.99.3.(5|9)"/{s+=$2} END{print s+0}')
check "unused drops counted ($unused)" test "$unused" -ge 2
unused=$(curl -s 127.0.0.1:1999/metrics | awk '/^xdp_unused_packets\{dst_ip="fd99:3::(5|9)"/{s+=$2} END{print s+0}')
check "v6 unused drops counted ($unused)" test "$unused" -ge 2
check "routed address not counted" bash -c "! curl -s 127.0.0.1:1999/metrics | grep -qE 'xdp_unused_packets\{dst_ip=\"(10.99.3.7|fd99:3::7)\"'"

echo "== blocklist"
B="env E2E_BIND=10.99.0.3"; B6="env E2E_BIND=fd99:0:0:3::2"
check "unblocked source works"        cl $B $MC udp-echo 10.99.1.2 40000 5002
check "v6 unblocked source works"     cl $B6 $MC udp-echo fd99:1::2 40000 5002
printf '10.99.0.3   # e2e\nfd99:0:0:3::2   # e2e\n' > $T/blocklist.txt; sleep 3
check "blocklisted source dropped"    cl $B $MC udp-no-echo 10.99.1.2 40000 5002
check "v6 blocklisted source dropped" cl $B6 $MC udp-no-echo fd99:1::2 40000 5002
check "other source still works"      cl $MC udp-echo 10.99.1.2 40000 5003
check "v6 other source still works"   cl $MC udp-echo fd99:1::2 40000 5003
check "blocklist hits per source"     bash -c "curl -s 127.0.0.1:1999/metrics | grep -q 'xdp_blocklist_source_packets{src_ip=\"10.99.0.3\"}'"
check "v6 blocklist hits per source"  bash -c "curl -s 127.0.0.1:1999/metrics | grep -q 'xdp_blocklist_source_packets{src_ip=\"fd99:0:0:3::2\"}'"
: > $T/blocklist.txt; sleep 3
check "removed entry works again"     cl $B $MC udp-echo 10.99.1.2 40000 5002
check "v6 removed entry works again"  cl $B6 $MC udp-echo fd99:1::2 40000 5002
W="env E2E_BIND=10.99.0.5"; W6="env E2E_BIND=fd99:0:0:5::2"
printf '10.99.0.5   # e2e\nfd99:0:0:5::2   # e2e\n' > $T/blocklist.txt
printf '10.99.0.5   # whitelisted\nfd99:0:0:5::2   # whitelisted\n' > $T/whitelist.txt; sleep 3
check "whitelist gets past the blocklist" cl $W $MC udp-echo 10.99.1.2 40000 5012
check "v6 whitelist gets past the blocklist" cl $W6 $MC udp-echo fd99:1::2 40000 5012
cl $W $MC udp-flood 10.99.1.2 40000 4000
cl $W6 $MC udp-flood fd99:1::2 40000 4000
check "whitelisted source never banned" cl $W $MC udp-echo 10.99.1.2 40000 5013
check "v6 whitelisted source never banned" cl $W6 $MC udp-echo fd99:1::2 40000 5013
: > $T/whitelist.txt; sleep 3
check "without whitelist it is blocked" cl $W $MC udp-no-echo 10.99.1.2 40000 5014
check "v6 without whitelist it is blocked" cl $W6 $MC udp-no-echo fd99:1::2 40000 5014
: > $T/blocklist.txt; sleep 3

echo "== ipv6: neighbour discovery with a blocklisted range"
echo "fd99::/16   # e2e" >> $T/blocklist.txt; sleep 3
ip -6 neigh flush dev c0
# any datagram to the client makes the router resolve its address; the
# answer itself is blocklisted, the neighbour advertisement is not
$MC udp-echo fd99::2 7000 >/dev/null
check "v6 ndp passes with blocklist" bash -c "ip -6 neigh show fd99::2 dev c0 | grep -Eq 'REACHABLE|STALE|DELAY'"
check "v6 blocklisted range dropped" cl $MC udp-no-echo fd99:1::2 40000 5015
sed -i '/fd99::\/16/d' $T/blocklist.txt; sleep 3

echo "== rate limit"
cl $B $MC udp-flood 10.99.1.2 40000 4000
cl $B6 $MC udp-flood fd99:1::2 40000 4000
# both families at once: each check waits 2 s for a missing answer, run one
# after the other the second could outlast the 5 s ban
cl $B $MC udp-no-echo 10.99.1.2 40000 5004 & BAN4=$!
cl $B6 $MC udp-no-echo fd99:1::2 40000 5004 & BAN6=$!
check "flooding source banned"        wait $BAN4
check "v6 flooding source banned"     wait $BAN6
check "other source not affected"     cl $MC udp-echo 10.99.1.2 40000 5005
check "v6 other source not affected"  cl $MC udp-echo fd99:1::2 40000 5005
cl env E2E_BIND=10.99.0.4 $MC udp-flood 10.99.1.2 40000 4000
cl env E2E_BIND=fd99:0:0:4::2 $MC udp-flood fd99:1::2 40000 4000
check "allowlisted source not banned" cl env E2E_BIND=10.99.0.4 $MC udp-echo 10.99.1.2 40000 5006
check "v6 allowlisted source not banned" cl env E2E_BIND=fd99:0:0:4::2 $MC udp-echo fd99:1::2 40000 5006
# a download the server started itself (QUIC to port 443): the answer is fast
ip netns exec sv $MC dns-answer 10.99.0.9 443 0
ip netns exec sv $MC dns-answer fd99:0:0:9::2 443 0
cl env E2E_BIND=10.99.0.9 $MC udp-flood 10.99.1.2 40000 4000
cl env E2E_BIND=fd99:0:0:9::2 $MC udp-flood fd99:1::2 40000 4000
check "outbound recorder attached"  bash -c "! grep -q 'outbound recorder failed' $T/loader.log"
check "answers to the server's own traffic not banned" cl env E2E_BIND=10.99.0.9 $MC udp-echo 10.99.1.2 40000 5007
check "v6 answers to the server's own traffic not banned" cl env E2E_BIND=fd99:0:0:9::2 $MC udp-echo fd99:1::2 40000 5007
sleep 3
bans=$(metric xdp_ratelimit_bans)
check "ban counted and logged ($bans)" bash -c "test '${bans:-0}' -ge 2 && grep -q 'Rate limit: banned 10.99.0.3/32' $T/loader.log"
check "v6 ban per /64 logged"         grep -q 'Rate limit: banned fd99:0:0:3::/64' $T/loader.log
sleep 3
check "ban expires"                   cl $B $MC udp-echo 10.99.1.2 40000 5007
check "v6 ban expires"                cl $B6 $MC udp-echo fd99:1::2 40000 5007

echo "== violations (scanner)"
S5="env E2E_BIND=10.99.0.5"; S56="env E2E_BIND=fd99:0:0:5::2"
check "scanner works before"          cl $S5 $MC udp-echo 10.99.1.2 40000 5010
check "v6 scanner works before"       cl $S56 $MC udp-echo fd99:1::2 40000 5010
SCAN=""; for i in $(seq 1 30); do
    cl $S5 $MC udp-echo 10.99.3.$((i+20)) 40000 5011 >/dev/null 2>&1 & SCAN="$SCAN $!"
    cl $S56 $MC udp-echo fd99:3::$((i+20)) 40000 5011 >/dev/null 2>&1 & SCAN="$SCAN $!"
done
wait $SCAN  # only the scanner probes, not the background servers
sleep 2
cl $S5 $MC udp-no-echo 10.99.1.2 40000 5012 & BAN4=$!   # at once, see rate limit
cl $S56 $MC udp-no-echo fd99:1::2 40000 5012 & BAN6=$!
check "scanner banned (violations)"   wait $BAN4
check "v6 scanner banned (violations)" wait $BAN6
check "logged as violations"          grep -q 'banned 10.99.0.5/32 .*violations' $T/loader.log
check "v6 logged as violations"       grep -q 'banned fd99:0:0:5::/64 .*violations' $T/loader.log
check "banned source still reaches the router itself" cl $S5 $MC udp-echo 10.99.0.1 40100 5013
check "v6 banned source still reaches the router itself" cl $S56 $MC udp-echo fd99::1 40100 5013

echo "== penalty box"
P7="env E2E_BIND=10.99.0.7"; P8="env E2E_BIND=10.99.0.8"
P76="env E2E_BIND=fd99:0:0:7::2"; P86="env E2E_BIND=fd99:0:0:8::2"
check "redirect rules installed"      bash -c "nft list table inet xdp_penalty | grep -q 'dnat ip to 10.99.0.1:25599'"
check "v6 redirect rules installed"   bash -c "nft list table inet xdp_penalty | grep -qF 'dnat ip6 to [fd99::1]:25599'"
check "real client: server list ping" cl $P7 $MC status 10.99.1.2 25565
check "v6 real client: server list ping" cl $P76 $MC status fd99:1::2 25565
cl $P7 $MC connect-spam 10.99.1.2 25565 15
check "throttled real client gets the please-wait message" cl $P7 $MC penalty-message 10.99.1.2 25565
cl $P76 $MC connect-spam fd99:1::2 25565 15
check "v6 throttled real client gets the please-wait message" cl $P76 $MC penalty-message fd99:1::2 25565
cl $P8 $MC connect-spam 10.99.1.2 25565 15
check "unknown (spoofable) source is just dropped"         cl $P8 $MC no-penalty-message 10.99.1.2 25565
cl $P86 $MC connect-spam fd99:1::2 25565 15
check "v6 unknown (spoofable) source is just dropped"      cl $P86 $MC no-penalty-message fd99:1::2 25565
sleep 11
check "after the penalty the real server works again"     cl $P7 $MC status 10.99.1.2 25565
check "v6 after the penalty the real server works again"  cl $P76 $MC status fd99:1::2 25565

echo "== DNS scanners"
D6="env E2E_BIND=10.99.0.6"; D7="env E2E_BIND=10.99.0.7"
D66="env E2E_BIND=fd99:0:0:6::2"; D76="env E2E_BIND=fd99:0:0:7::2"
check "dns scanner works before"      cl $D6 $MC udp-echo 10.99.1.2 40000 5020
check "v6 dns scanner works before"   cl $D66 $MC udp-echo fd99:1::2 40000 5020
cl $D6 $MC udp-echo 10.99.1.2 53 5021 >/dev/null 2>&1   # query where no DNS server runs
cl $D66 $MC udp-echo fd99:1::2 53 5021 >/dev/null 2>&1
cl $D7 $MC udp-echo 10.99.3.7 53 5022 >/dev/null 2>&1   # query to a real DNS server
cl $D76 $MC udp-echo fd99:3::7 53 5022 >/dev/null 2>&1
cl $P8 $MC dns-answer 10.99.1.2 53 53       # reflected answers (attack on us)
cl $P8 $MC dns-answer 10.99.1.2 53 40053
cl $P86 $MC dns-answer fd99:1::2 53 53
cl $P86 $MC dns-answer fd99:1::2 53 40053
sleep 5
grep -E "^(10.99.0.8|fd99:0:0:8::2) " $T/blocklist.txt
check "reflected dns answers don't blocklist the resolver" bash -c "! grep -q '^10.99.0.8 .*dns-scan' $T/blocklist.txt"
check "v6 reflected dns answers don't blocklist the resolver" bash -c "! grep -q '^fd99:0:0:8::2 .*dns-scan' $T/blocklist.txt"
check "dns scanner blocklisted"       grep -q '^10.99.0.6 .*dns-scan' $T/blocklist.txt
check "v6 dns scanner blocklisted"    grep -q '^fd99:0:0:6::2 .*dns-scan' $T/blocklist.txt
check "dns scanner dropped"           cl $D6 $MC udp-no-echo 10.99.1.2 40000 5023
check "v6 dns scanner dropped"        cl $D66 $MC udp-no-echo fd99:1::2 40000 5023
check "dns scanner reaches the router" cl $D6 $MC udp-echo 10.99.0.1 40100 5024
check "v6 dns scanner reaches the router" cl $D66 $MC udp-echo fd99::1 40100 5024
check "legit dns client not blocked"  bash -c "! grep -qE '^(10.99.0.7|fd99:0:0:7::2) ' $T/blocklist.txt"
check "dns server answers its client" cl $D7 $MC udp-echo 10.99.3.7 53 5025
check "v6 dns server answers its client" cl $D76 $MC udp-echo fd99:3::7 53 5025
check "dns entry expires like the other auto entries" grep -q '^10.99.0.6 .*auto until=.*dns-scan' $T/blocklist.txt
check "v6 dns entry expires like the other auto entries" grep -q '^fd99:0:0:6::2 .*auto until=.*dns-scan' $T/blocklist.txt

echo "== automatic blocklist"
check "1st ban not yet blocklisted"   bash -c "! grep -q 'auto until=.*rate limit bans' $T/blocklist.txt"
cl $B $MC udp-flood 10.99.1.2 40000 4000
cl $B6 $MC udp-flood fd99:1::2 40000 4000; sleep 3
check "2nd ban writes auto entry"     grep -q '^10.99.0.3/32 .*auto until=' $T/blocklist.txt
check "v6 2nd ban writes auto entry for the /64" grep -q '^fd99:0:0:3::/64 .*auto until=' $T/blocklist.txt
sleep 4
check "still dropped after the ban"   cl $B $MC udp-no-echo 10.99.1.2 40000 5008
check "v6 still dropped after the ban" cl $B6 $MC udp-no-echo fd99:1::2 40000 5008
check "auto entries counted"          bash -c "test \"\$(curl -s 127.0.0.1:1999/metrics | awk '\$1==\"xdp_blocklist_auto_entries\"{print \$2}')\" -ge 2"
check "logged"                        grep -q 'Auto blocklist: 10.99.0.3/32 banned 2 times' $T/loader.log
check "v6 logged"                     grep -q 'Auto blocklist: fd99:0:0:3::/64 banned 2 times' $T/loader.log
# the source stays silent now: removed after auto_idle_secs, long before auto_duration_secs
for i in $(seq 1 40); do grep -q 'auto until=.*rate limit bans' $T/blocklist.txt || break; sleep 1; done
check "idle auto entry removed"       bash -c "! grep -q 'auto until=.*rate limit bans' $T/blocklist.txt && grep -q 'Auto blocklist: 10.99.0.3/32 sent nothing' $T/loader.log"
check "v6 idle auto entry removed"    grep -q 'Auto blocklist: fd99:0:0:3::/64 sent nothing' $T/loader.log
sleep 2
check "works again after expiry"      cl $B $MC udp-echo 10.99.1.2 40000 5009
check "v6 works again after expiry"   cl $B6 $MC udp-echo fd99:1::2 40000 5009

adopted=$(metric minecraft_adopted_connections)
check "connections adopted (${adopted:-0})" test "${adopted:-0}" -ge 4

echo "== restart with running sessions"
cl $MC player 10.99.1.2 25565 20 & PLAYER=$!
cl $MC bedrock-session 10.99.1.2 19132 20 & BEDROCK=$!
cl $MC player fd99:1::2 25565 20 & PLAYER6=$!
cl $MC bedrock-session fd99:1::2 19132 20 & BEDROCK6=$!
sleep 3
kill $LOADER; wait $LOADER 2>/dev/null
check "filter detached on stop" bash -c "! ip link show c0 | grep -q xdp"
start_loader
sleep 3
check "targets restored from state" grep -q 'Restored 8 detected server' $T/loader.log
check "java player survived restart"    wait $PLAYER
check "v6 java player survived restart" wait $PLAYER6
check "bedrock session survived restart" wait $BEDROCK
check "v6 bedrock session survived restart" wait $BEDROCK6
sleep 13
check "garbage dropped after restart" cl $MC garbage 10.99.1.2 25565
check "v6 garbage dropped after restart" cl $MC garbage fd99:1::2 25565

kill $LOADER; wait $LOADER 2>/dev/null
grep -E 'WARN|ERROR' $T/loader.log | sed 's/^/        /'
[ $FAILS -gt 0 ] && cp $T/loader.log "${E2E_LOG:-/dev/null}" 2>/dev/null
echo "== $FAILS failure(s)"
kill $(jobs -p) 2>/dev/null
exit $((FAILS > 0))
