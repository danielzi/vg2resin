#!/usr/bin/env bash
set -e

if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

mkdir -p /var/run/vg2resin
exec python3 -u /app/app.py
