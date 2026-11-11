#!/bin/bash
# Loads every program of the compiled object into the kernel of the docker
# host, which runs the verifier on it:
#   docker run --rm --privileged -v "$PWD:/src" -w /src xdp-build:local tests/verifier_docker.sh
set -eu
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
# bpffs rejects names containing '.' and holds no regular files: the log
# goes to /tmp
dir=$(mktemp -d /sys/fs/bpf/verify_XXXX)
log=$(mktemp /tmp/verifier.XXXX)
trap 'rm -rf "$dir" "$log"' EXIT
# program types come from the section names (xdp, classifier = sched_cls)
bpftool -d prog loadall xdp/minecraft_filter.o "$dir" 2> "$log" || { tail -60 "$log"; exit 1; }
bpftool prog show pinned "$dir/minecraft_filter" >/dev/null
echo "verifier: ok ($(ls "$dir" | wc -l) programs)"
