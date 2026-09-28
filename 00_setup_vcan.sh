#!/usr/bin/env bash
# Phase 1 - Task 1.1: virtual CAN interface on Arch Linux ARM
# Run:  sudo ./00_setup_vcan.sh
set -euo pipefail

if ! modinfo -n vcan >/dev/null 2>&1 && ! ls /lib/modules/"$(uname -r)"/kernel/drivers/net/can/vcan.ko* >/dev/null 2>&1; then
    echo "WARN: vcan module not found for kernel $(uname -r)."
    echo "      Check: zgrep CONFIG_CAN_VCAN /proc/config.gz  (need =m or =y)"
fi

sudo modprobe vcan || echo "WARN: modprobe vcan failed - continuing anyway"

if ! ip link show vcan0 >/dev/null 2>&1; then
    sudo ip link add dev vcan0 type vcan
fi
sudo ip link set up vcan0

# vcan1 = trusted segment for gateway_bridge.py / gateway_test.py
if ! ip link show vcan1 >/dev/null 2>&1; then
    sudo ip link add dev vcan1 type vcan
fi
sudo ip link set up vcan1

echo "--- vcan0 (untrusted) + vcan1 (trusted) ready ---"
ip -details link show vcan0
ip -details link show vcan1
