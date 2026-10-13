#!/usr/bin/env bash
export PATH="/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH"

DEV_NAME="${dev:-$1}"
IDX="${WORKER_IDX:-}"
if [ -z "$IDX" ]; then
    IDX=$(echo "$DEV_NAME" | sed 's/[^0-9]*//g')
fi
if [ -z "$IDX" ]; then
    IDX=1
fi

SOCKS_PORT="${WORKER_PORT:-$((10800 + IDX))}"
RUNTIME_DIR="${RUNTIME_DIR:-/var/run/vg2resin}"

TABLE_ID=$((100 + IDX))
PRIO=$((1000 + IDX))
GW="${route_vpn_gateway:-$ifconfig_remote}"

sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.${dev}.rp_filter=0" >/dev/null 2>&1 || true

ip route flush table "$TABLE_ID" 2>/dev/null || true
if [ -n "$GW" ]; then
    ip route replace default via "$GW" dev "$dev" table "$TABLE_ID"
else
    ip route replace default dev "$dev" table "$TABLE_ID"
fi

while ip rule del priority "$PRIO" 2>/dev/null; do :; done
ip rule add from "${ifconfig_local}/32" table "$TABLE_ID" priority "$PRIO"

pkill -9 -f "microsocks -i 0.0.0.0 -p ${SOCKS_PORT} " 2>/dev/null || true
nohup microsocks -i 0.0.0.0 -p "$SOCKS_PORT" -b "$ifconfig_local" >"${RUNTIME_DIR}/ms_${IDX}.log" 2>&1 &
MS_PID=$!

cat > "${RUNTIME_DIR}/worker_${IDX}.json" <<EOF
{"idx": ${IDX}, "dev": "${dev}", "local_ip": "${ifconfig_local}", "gw": "${GW}", "port": ${SOCKS_PORT}, "ms_pid": ${MS_PID}}
EOF
