#!/usr/bin/env python3
"""Phase 1 deliverable: real-time detector on the virtual bus.

  python 05_live_detect.py            # start it, then launch 02_attack_traffic.py dos

Classifies every frame as normal/attack and prints ALERT lines.
This is the software proof - Phase 2 ports the same logic to INT8 C++ on an STM32.
"""
import argparse
import time

import can
import joblib

from features import row_features


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="model.pkl")
    ap.add_argument("--channel", default="vcan0")
    args = ap.parse_args()

    clf = joblib.load(args.model)
    bus = can.interface.Bus(channel=args.channel, interface="socketcan")
    print(f"Watching {args.channel} with {args.model} - Ctrl+C to stop")

    last_ts = None
    frames = alerts = 0
    t_start = time.time()
    try:
        while True:
            msg = bus.recv(timeout=1.0)
            if msg is None or msg.is_error_frame:
                continue
            now = msg.timestamp
            dt = (now - last_ts) if last_ts is not None else 1.0
            last_ts = now
            data8 = list(msg.data) + [0] * (8 - len(msg.data))

            t0 = time.perf_counter()
            pred = clf.predict(
                row_features(msg.arbitration_id, int(msg.is_extended_id), msg.dlc, data8, dt)
            )[0]
            infer_us = (time.perf_counter() - t0) * 1e6

            frames += 1
            if pred == 1:
                alerts += 1
                print(
                    f"ALERT #{alerts} id=0x{msg.arbitration_id:X} dlc={msg.dlc} "
                    f"data={msg.data.hex()} inference={infer_us:.0f}us"
                )
    except KeyboardInterrupt:
        elapsed = time.time() - t_start
        print(
            f"\nDone - {frames} frames, {alerts} alerts "
            f"({alerts / max(frames, 1) * 100:.2f}%) in {elapsed:.0f}s"
        )


if __name__ == "__main__":
    main()
