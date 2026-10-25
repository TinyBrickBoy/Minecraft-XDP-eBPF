#!/bin/bash
# Safe update of an installed filter without kicking players:
#   build in docker -> unit tests -> end-to-end test in a privileged container
#   -> config check with the new binary -> atomic install -> restart
#   -> health check -> automatic rollback on failure.
#
# Players stay connected because the new loader adopts every established
# connection during [filter] adopt_grace_secs after its start.
#
# Usage: contrib/update.sh [--skip-e2e] [--pull]
# Env:   INSTALL_DIR (/opt/minecraft-xdp), SERVICE (minecraft-xdp),
#        INTERFACE (eth0), METRICS (http://127.0.0.1:1999/metrics),
#        HEALTH_CMD (extra check after the restart, e.g. "birdc show protocols | grep -q Established")
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=$PWD
INSTALL_DIR=${INSTALL_DIR:-/opt/minecraft-xdp}
SERVICE=${SERVICE:-minecraft-xdp}
INTERFACE=${INTERFACE:-eth0}
METRICS=${METRICS:-http://127.0.0.1:1999/metrics}
HEALTH_CMD=${HEALTH_CMD:-true}
IMAGE=xdp-build:local
E2E=1
for arg in "$@"; do
    case $arg in
        --skip-e2e) E2E=0 ;;
        --pull) git pull --ff-only ;;
        *) echo "unknown option $arg" >&2; exit 2 ;;
    esac
done
step() { echo; echo "== $*"; }

step "build image"
docker image inspect $IMAGE >/dev/null 2>&1 || docker build -q -t $IMAGE -f contrib/Dockerfile.build contrib

step "build + unit tests"
docker run --rm -v "$SRC:/src" -v xdp-cargo-cache:/usr/local/cargo/registry -w /src $IMAGE \
    bash -c 'cargo build --release && cargo test --release'

if [ $E2E = 1 ]; then
    step "end-to-end test (isolated container network)"
    docker run --rm --privileged --network none -v "$SRC:/src" -w /src $IMAGE tests/e2e_docker.sh
fi

step "config check with the new binary"
NEW=$INSTALL_DIR/xdp-loader.new
install -m 755 target/release/xdp-loader "$NEW"
"$NEW" --check-config --config "$INSTALL_DIR/config.toml"

step "install"
cp -p "$INSTALL_DIR/xdp-loader" "$INSTALL_DIR/xdp-loader.prev"
mv -f "$NEW" "$INSTALL_DIR/xdp-loader"   # atomic rename

healthy() {
    for _ in $(seq 1 20); do
        if systemctl is-active -q "$SERVICE" \
            && ip link show "$INTERFACE" | grep -q 'prog/xdp' \
            && curl -sf "$METRICS" | grep -q '^minecraft_' \
            && bash -c "$HEALTH_CMD"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

step "restart (players are adopted)"
systemctl restart "$SERVICE"
if healthy; then
    echo "update ok: $("$INSTALL_DIR/xdp-loader" --version)"
    exit 0
fi

step "health check failed, rolling back"
journalctl -u "$SERVICE" -n 20 --no-pager || true
mv -f "$INSTALL_DIR/xdp-loader.prev" "$INSTALL_DIR/xdp-loader"
systemctl restart "$SERVICE"
healthy && echo "rolled back to the previous version" || echo "ROLLBACK UNHEALTHY, check the service" >&2
exit 1
