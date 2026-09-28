#!/usr/bin/env python3
"""Two-segment CAN safety gateway: rule firewall + 100 ms temporal analysis.

    vcan0 (untrusted) -- Tier 1 rules --> [100 ms window buffer] --> vcan1 (trusted)

Tier 1 (deterministic rules) checks only what a gateway can cheaply check per
frame: ID allowlist, DLC, and a FLOOD-level rate limit (nominal period / 4 - so
a 2x masquerade stream passes by design; a rate limit tight enough to stop it
would false-drop normal jitter). That leaves exactly the masquerade hole:
valid ID, valid cadence, corrupted payload.

Tier 2 (the TinyML phase) buffers every frame Tier 1 forwarded into tumbling
100 ms windows and extracts temporal features (window_features.py): inter-
arrival deviations, payload deltas, cross-message consistency (baro altitude
vs rpm/speed/gps). Those features are what the Random Forest trains on.

Modes:
  python gateway_bridge.py --rules-only              # legacy Tier-1-only gateway.
                                                     # THE masquerade failure-log demo:
                                                     # spike frames print [FORWARDED]
  python gateway_bridge.py --collect data/win_normal.csv --label 0
  python gateway_bridge.py --collect data/win_attack.csv --label 1
                                                     # dump window features for training
  python gateway_bridge.py --model model_window.pkl  # live windowed RF verdicts
"""
import argparse
import csv
import time
from collections import deque

import can

from window_features import WINDOW_COLS, build_window_rows, window_summary

# Real lab traffic (01_make_traffic.py). Rate limit = period / FLOOD_MARGIN:
# deliberately generous - stopping floods is Tier 1's job, not masquerades'.
FLOOD_MARGIN = 4
ALLOWED_IDS = {
    0x10040405: {"name": "baro", "dlc": 7, "period": 0.020},   # f32 Pa + f16 var + tail byte
    0x18FF1201: {"name": "speed", "dlc": 6, "period": 0.050},  # >Hf
    0x18FF1101: {"name": "gps", "dlc": 8, "period": 0.100},    # >ff
    0x18FF1301: {"name": "rpm", "dlc": 4, "period": 0.200},    # >HH
}

last_seen = {}

# Per-frame logging. 12_defense_demo.py sets this False for the scorecard view
# (drops/alerts are summarized there instead of printed 1000x).
VERBOSE = True


def deterministic_rules(msg: can.Message) -> bool:
    """Tier 1: Rule-Based Firewall (ID allowlist, DLC, flood-level rate limit)."""
    spec = ALLOWED_IDS.get(msg.arbitration_id)
    if spec is None:
        if VERBOSE:
            print(f"[DROP - Rule] Unauthorized ID: 0x{msg.arbitration_id:X}")
        return False

    if msg.dlc != spec["dlc"]:
        if VERBOSE:
            print(f"[DROP - Rule] Invalid DLC on 0x{msg.arbitration_id:X}: {msg.dlc}")
        return False

    now = msg.timestamp  # kernel RX timestamp, not host time
    prev = last_seen.get(msg.arbitration_id)
    last_seen[msg.arbitration_id] = now
    if prev is not None:
        delta = now - prev
        if delta < spec["period"] / FLOOD_MARGIN:
            if VERBOSE:
                print(f"[DROP - Rule] Rate violation (burst/flood) 0x{msg.arbitration_id:X}: "
                      f"{delta * 1000:.1f}ms < {spec['period'] / FLOOD_MARGIN * 1000:.0f}ms")
            return False
    return True


class WindowAnalyzer:
    """Tumbling 100 ms windows over the frames the rule engine forwarded."""

    def __init__(self, out_csv=None, label=-1, model=None):
        self.pending = deque()
        self.rows_written = 0
        self.out_csv = out_csv
        self.label = label
        self.model = model
        self._wr = None
        self._f = None
        if out_csv:
            self._f = open(out_csv, "w", newline="")
            self._wr = csv.writer(self._f)
            self._wr.writerow(WINDOW_COLS + ["label"])

    def add(self, msg):
        self.pending.append((msg.timestamp, msg.arbitration_id, bytes(msg.data)))

    def pump(self):
        """Flush every window that has reached its full 100 ms."""
        if not self.pending:
            return
        now = self.pending[-1][0]
        while True:
            first = self.pending[0][0]
            window = [f for f in self.pending if f[0] - first < 0.100]
            if len(window) == len(self.pending) and now - first < 0.100:
                return  # current window not complete yet
            self._flush(window)
            for f in window:
                self.pending.popleft()

    def _flush(self, window):
        rows = build_window_rows(window)
        for row in rows:
            if self._wr:
                self._wr.writerow([row[c] for c in WINDOW_COLS] + [self.label])
            self.rows_written += 1
            verdict = ""
            if self.model is not None:
                x = [[row[c] for c in WINDOW_COLS if c != "t"]]
                pred = int(self.model.predict(x)[0])
                verdict = " -> ALERT (ML: attack window)" if pred else " -> ok (ML: normal)"
            elif not self.out_csv:
                verdict = f" -> {window_summary(row)}"
            tag = "WINDOW" if self.model is None else "TIER2"
            print(f"[{tag}] t={row['t']:.1f}s{verdict}")

    def close(self):
        if self._f:
            self._f.close()
            print(f"Wrote {self.rows_written} window rows -> {self.out_csv}")


def run_bridge(args):
    bus_untrusted = can.interface.Bus(channel="vcan0", interface="socketcan")
    bus_trusted = can.interface.Bus(channel="vcan1", interface="socketcan")

    model = None
    if args.model:
        import joblib
        model = joblib.load(args.model)

    win = None
    if not args.rules_only:
        win = WindowAnalyzer(out_csv=args.collect, label=args.label, model=model)

    mode = "Tier-1 rules only" if args.rules_only else "Tier-1 rules + 100 ms window analysis"
    print(f"[*] Two-Segment CAN Safety Gateway ({mode}). vcan0 -> vcan1 ...")

    try:
        while True:
            msg = bus_untrusted.recv(timeout=1.0)
            if msg is None or msg.is_error_frame:
                continue

            start_t = time.perf_counter()

            if not deterministic_rules(msg):
                continue

            # Tier 1 passed -> forward, and remember what we let through.
            bus_trusted.send(can.Message(arbitration_id=msg.arbitration_id,
                                         data=msg.data, is_extended_id=msg.is_extended_id))
            latency_ms = (time.perf_counter() - start_t) * 1000
            print(f"[FORWARDED] ID: 0x{msg.arbitration_id:X} data={bytes(msg.data).hex().upper()} "
                  f"| Latency: {latency_ms:.3f}ms")

            if win:
                win.add(msg)
                win.pump()

    except KeyboardInterrupt:
        pass
    finally:
        if win:
            win.close()
        print("\nStopping gateway.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rules-only", action="store_true",
                    help="legacy behaviour: forward on Tier 1 alone (masquerade demo)")
    ap.add_argument("--collect", metavar="CSV", help="write one feature row per 100 ms window")
    ap.add_argument("--label", type=int, default=-1, help="label column for --collect (0/1)")
    ap.add_argument("--model", metavar="PKL", help="windowed RF model for live Tier-2 verdicts")
    args = ap.parse_args()
    if args.model and args.collect:
        ap.error("--collect and --model are separate runs")
    run_bridge(args)


if __name__ == "__main__":
    main()
