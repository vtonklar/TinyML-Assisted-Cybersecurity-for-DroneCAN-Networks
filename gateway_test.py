"""Traffic generator for testing gateway_bridge.py (sends on vcan0).

Usage:
    python gateway_test.py benign                 # 0x100 @ 20 Hz, valid payloads
    python gateway_test.py attack unauth          # unauthorized CAN ID 0x3FF
    python gateway_test.py attack bad-dlc         # valid ID, wrong DLC
    python gateway_test.py attack flood           # valid frames, way over rate limit
    python gateway_test.py attack masquerade      # valid ID/DLC/timing, payload out of range
"""
import argparse
import random
import time

import can

GPS_ID = 0x100


def benign(args):
    bus = can.interface.Bus(channel=args.channel, interface="socketcan")
    alt = 100
    print(f"[*] Benign GPS/baro telemetry: ID 0x{GPS_ID:X}, 20 Hz, Ctrl-C to stop")
    try:
        while True:
            data = alt.to_bytes(2, "big") + b"\x00" * 6
            bus.send(can.Message(arbitration_id=GPS_ID, data=data))
            alt = max(0, min(999, alt + random.randint(-1, 2)))
            time.sleep(0.05)
    finally:
        bus.shutdown()


def attack(args):
    bus = can.interface.Bus(channel=args.channel, interface="socketcan")
    makers = {
        # Unknown ID -> Tier 1 allowlist drop
        "unauth": lambda: can.Message(arbitration_id=0x3FF, data=b"\x00" * 8),
        # Right ID, wrong DLC -> Tier 1 DLC drop
        "bad-dlc": lambda: can.Message(arbitration_id=GPS_ID, data=b"\x01\x02"),
        # Right ID/DLC/payload, absurd rate -> Tier 1 rate drop
        "flood": lambda: can.Message(
            arbitration_id=GPS_ID, data=(150).to_bytes(2, "big") + b"\x00" * 6),
        # Right ID/DLC/rate, payload beyond physical limit -> Tier 2 drop
        "masquerade": lambda: can.Message(
            arbitration_id=GPS_ID, data=(5000).to_bytes(2, "big") + b"\x00" * 6),
    }
    sender = makers[args.attack_mode]
    delay = 0.0 if args.attack_mode == "flood" else 0.1
    print(f"[*] Attack mode '{args.mode}' on {args.channel} "
          f"(gateway should DROP every frame; vcan1 must stay silent)")
    try:
        while True:
            bus.send(sender())
            time.sleep(delay)
    finally:
        bus.shutdown()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["benign", "attack"])
    ap.add_argument("attack_mode", nargs="?",
                    choices=["unauth", "bad-dlc", "flood", "masquerade"])
    ap.add_argument("--channel", default="vcan0")
    args = ap.parse_args()

    if args.mode == "attack" and not args.attack_mode:
        ap.error("attack mode requires one of: unauth, bad-dlc, flood, masquerade")

    try:
        (benign if args.mode == "benign" else attack)(args)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
