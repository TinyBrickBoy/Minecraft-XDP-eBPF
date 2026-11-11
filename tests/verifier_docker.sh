#!/bin/bash
# Loads every program of the compiled object into the kernel of the docker
# host, which runs the verifier on it:
#   docker run --rm --privileged -v "$PWD:/src" -w /src xdp-build:local tests/verifier_docker.sh
# Two configurations are checked by default:
#   zero   xdp/minecraft_filter.o as built, with the all-zero .rodata config
#          (what loads when the object is used without the loader)
#   knobs  a copy compiled from the same sources with every .rodata knob of
#          xdp/config.h set non-zero, so the verifier also walks every
#          feature branch the loader can switch on (dead code with zeros)
# VERIFIER_MODES="zero" (or "knobs") checks only one of them.
set -eu
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
work=$(mktemp -d /tmp/verifier.XXXX)
dirs=()
cleanup() { rm -rf "$work" "${dirs[@]}"; }
trap cleanup EXIT

# every knob of xdp/config.h with a non-zero value; a knob missing here
# fails the check, so new knobs can not slip past the verifier
knob_values() {
    cat <<'EOF'
PROMETHEUS 1
ONLINE_NAMES 1
START_PORT 25565
END_PORT 25575
STATIC_GRACE_UNTIL_NS 120000000000ULL
UNUSED_DROP 1
BLOCKLIST_ACTIVE 1
RATELIMIT_MODE 2
RATELIMIT_PPS 1000
RATELIMIT_BAN_NS 60000000000ULL
STRIKE_LIMIT 5
STRIKE_WINDOW_NS 10000000000ULL
PENALTY_NS 30000000000ULL
PENALTY_VERIFIED_NS 600000000000ULL
DNS_SCAN 1
DNS_RECHECK_NS 300000000000ULL
L3_INTERFACES 1
IPV6_SOURCE_PREFIX 64
IPV6_AGGREGATE_PREFIX 48
AGG_HIT_COUNT 80
HIT_COUNT 10
HIT_COUNT_RESET_NS 3000000000ULL
PLAYER_IDLE_NS 60000000000ULL
EOF
}

build_knobs() {
    local src=$work/knobs
    mkdir -p "$src"
    cp xdp/*.c xdp/*.h "$src/"
    while read -r name value; do
        sed -i "s/^\(volatile const __u[0-9]* $name = \)0;/\1$value;/" "$src/config.h"
    done < <(knob_values)
    if grep -E '^volatile const __u[0-9]+ [A-Z0-9_]+ = 0;' "$src/config.h" >&2; then
        echo "verifier: the knobs above have no non-zero value in tests/verifier_docker.sh" >&2
        exit 1
    fi
    # the flags of build.rs
    (cd "$src" && clang -Wall -Wextra -Wno-language-extension-token -O2 -g -target bpf -mcpu=v3 \
        -c minecraft_filter.c -o minecraft_filter.o >&2)
}

verify() {
    local mode=$1 object=$2
    # bpffs rejects names containing '.' and holds no regular files: the log
    # goes to the work dir
    local dir log=$work/$mode.log
    dir=$(mktemp -d /sys/fs/bpf/verify_XXXX)
    dirs+=("$dir")
    # program types come from the section names (xdp, classifier = sched_cls)
    bpftool -d prog loadall "$object" "$dir" 2> "$log" || { tail -60 "$log"; echo "verifier ($mode): FAILED"; exit 1; }
    bpftool prog show pinned "$dir/minecraft_filter" >/dev/null
    echo "verifier ($mode): ok ($(ls "$dir" | wc -l) programs)"
}

for mode in ${VERIFIER_MODES:-zero knobs}; do
    case $mode in
        zero) verify zero xdp/minecraft_filter.o ;;
        knobs) build_knobs; verify knobs "$work/knobs/minecraft_filter.o" ;;
        *) echo "unknown mode '$mode' (zero, knobs)" >&2; exit 2 ;;
    esac
done
