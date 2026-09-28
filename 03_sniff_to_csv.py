#!/usr/bin/env python3
"""Capture every frame on vcan0 into a CSV for training data.

Run in a third terminal while 01 (benign) and/or 02 (attack) are running:

  python 03_sniff_to_csv.py --out data/normal.csv      --duration 60   # only 01 running
  python 03_sniff_to_csv.py --out data/attack_dos.csv  --duration 30   # 01 + 02 dos running
  python 03_sniff_to_csv.py --out data/attack_spoof.csv --duration 30  # 01 + 02 spoof running
"""
import argparse
import can
import csv
import time

from features import RAW_COLS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/capture.csv")
    ap.add_argument("--duration", type=float, default=60.0, help="seconds to capture")
    args = ap.parse_args()

    bus = can.interface.Bus(channel="vcan0", interface="socketcan")
    print(f"Capturing {args.duration:.0f}s on vcan0 -> {args.out}")

    count = 0
    deadline = time.time() + args.duration
    with open(args.out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(RAW_COLS)
        while time.time() < deadline:
            msg = bus.recv(timeout=1.0)
            if msg is None or msg.is_error_frame:
                continue
            data = list(msg.data) + [0] * (8 - len(msg.data))  # pad DLC<8 frames
            writer.writerow(
                [f"{msg.timestamp:.6f}", msg.arbitration_id, int(msg.is_extended_id), msg.dlc, *data]
            )
            count += 1
    print(f"Wrote {count} frames -> {args.out}")


if __name__ == "__main__":
    main()
