#!/usr/bin/env python3
"""Node A (Victim): broadcast benign J1939-style telemetry on vcan0.

IDs use the J1939 29-bit shape (priority | PGN 0xFF01 proprietary B | source),
so the lab resembles tractor/bus telemetry without needing a real ECU.
Run:  python 01_make_traffic.py            (keep it running while you sniff/attack)
"""
import argparse
import can
import math
import struct
import time

BARO_ID = 0x10040405  # DroneCAN barometer node (see 06/07 attack scripts)

# (arbitration_id, period_seconds, payload_builder(t) -> bytes)
SENSORS = [
    (0x18FF1101, 0.10, lambda t: struct.pack(">ff", 52.2297 + 0.0001 * t, 21.0122)),        # GPS lat/lon
    (0x18FF1201, 0.05, lambda t: struct.pack(">Hf", 0, 8.0 + 2.0 * math.sin(t / 5.0))),      # speed m/s
    (0x18FF1301, 0.20, lambda t: struct.pack(">HH", 1200 + int(50 * math.sin(t / 3.0)), 75)),  # rpm / load %
    # DroneCAN barometer node: prio16 | type 1028 StaticPressure | node 5.
    # float32 Pa (LE) + float16 variance + UAVCAN tail byte; ±24 Pa ~ ±2 m wobble.
    (BARO_ID, 0.02, lambda t: struct.pack("<fH", 101325.0 + 24.0 * math.sin(t / 7.0), 4) + b"\xc0"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--channel", default="vcan0")
    ap.add_argument("--no-baro", action="store_true",
                    help="silent barometer (lets 07_masquerade.py takeover be the sole baro node)")
    args = ap.parse_args()

    sensors = [s for s in SENSORS if not (args.no_baro and s[0] == BARO_ID)]

    bus = can.interface.Bus(channel=args.channel, interface="socketcan")
    print(f"Broadcasting benign telemetry on {args.channel} - Ctrl+C to stop")

    t0 = time.time()
    next_due = {aid: 0.0 for aid, _, _ in sensors}
    sent = 0
    try:
        while True:
            now = time.time()
            t = now - t0
            for aid, period, build in sensors:
                if t >= next_due[aid]:
                    bus.send(can.Message(arbitration_id=aid, data=build(t), is_extended_id=True))
                    next_due[aid] += period
                    sent += 1
            time.sleep(0.005)
    except KeyboardInterrupt:
        print(f"\nDone - sent {sent} benign frames")


if __name__ == "__main__":
    main()
