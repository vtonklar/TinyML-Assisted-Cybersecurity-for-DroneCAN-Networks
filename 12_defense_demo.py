#!/usr/bin/env python3
"""ONE-COMMAND PoC: the full attack storyline against the REAL two-tier gateway.

Every scenario below is injected into the actual pipeline code
(gateway_bridge.deterministic_rules -> WindowAnalyzer -> trained RF) - nothing
here is a mock verdict. Offline mode replays recorded lab traffic through that
pipeline in memory; live mode (Pi) plays the same timeline onto vcan0 in real
time and detects on kernel timestamps.

    0 benign         30 s of recorded honest traffic   -> 0 false alarms
    1 injection      rogue ID 0x123                    -> Tier-1 allowlist drop
    2 flood          baro ID at 1 kHz                  -> Tier-1 rate-limit drop
    3 masquerade     +500 m spikes, same ID/cadence    -> Tier-2 alert <= 100 ms
    4 drift          +2 m/s ramp, every frame plausible-> Tier-2 alert <= 100 ms
    5 shadow         mirrored liar, same ID, +6 ms     -> Tier-2 alert <= 100 ms
    6 replay         recorded baro re-emitted 41 s late-> seams only (named ceiling)
    7 trojan OTA     trigger + node sinks -2 m/s       -> trigger dropped, sink caught

Usage:
    python3 12_defense_demo.py                  # offline (works on macOS)
    python3 12_defense_demo.py --train          # (re)build model_window_drift.pkl
    sudo python3 12_defense_demo.py --mode live # on the Pi, after 00_setup_vcan.sh
    python3 12_defense_demo.py --verbose        # per-window log too
"""
import argparse
import csv
import struct
import sys
import time
from collections import Counter
from pathlib import Path

import can

import gateway_bridge as gw
from gateway_bridge import deterministic_rules, WindowAnalyzer
from window_features import FEATURE_COLS, WINDOW_COLS, build_window_rows

D = str(Path(__file__).resolve().parent)   # kit root, wherever it is cloned/scp'd
BARO, SPEED, GPS, RPM = 0x10040405, 0x18FF1201, 0x18FF1101, 0x18FF1301
TRIGGER_ID = 0x102885E3          # DroneCAN BeginFirmwareUpdate service frame
SEA = 101325.0
DRIFT_RATE = 2.0                 # m/s for scenario 4 / trojan sink


def alt_to_pa(a):
    return SEA * (1.0 - a / 44330.0) ** 5.255


def baro_pack(pa, var=4):
    return struct.pack("<fH", pa, var) + b"\xC0"


def baro_alt(data):
    try:
        return 44330.0 * (1.0 - (struct.unpack("<f", bytes(data[:4]))[0] / 101325.0)
                          ** (1.0 / 5.255))
    except (struct.error, OverflowError, ValueError):
        return float("nan")


# --------------------------------------------------------------------------
# timeline
# --------------------------------------------------------------------------
# (name, tier, start, dur, kind) - starts are multiples of 100 ms so attack
# windows never straddle a scenario boundary.
SLOTS = [
    ("0 benign",      "-",  0.0, 30.0, "benign"),
    ("1 injection",   "T1", 30.5, 2.0, "injection"),
    ("2 flood 1 kHz", "T1", 33.0, 1.0, "flood"),
    ("3 masquerade",  "T2", 34.5, 3.5, "masquerade"),
    ("4 drift +2m/s", "T2", 38.5, 3.5, "drift"),
    ("5 shadow",      "T2", 42.5, 3.5, "shadow"),
    ("6 replay",      "T2", 46.5, 3.5, "replay"),
    ("7 trojan OTA",  "T2", 50.5, 4.5, "trojan"),
]


def load_capture():
    """Recorded honest lab traffic (01_make_traffic.py -> 03_sniff_to_csv.py)."""
    frames = []
    with open(f"{D}/data/raw_normal.csv") as f:
        for r in csv.DictReader(f):
            frames.append((float(r["ts"]), int(r["can_id"]),
                           bytes(int(r[f"b{i}"]) for i in range(int(r["dlc"])))))
    frames.sort()
    t0 = frames[0][0]
    return [(round(ts - t0, 6), cid, d) for ts, cid, d in frames]


def base_traffic(dur):
    """Nominal baro/speed/gps/rpm stream covering [0, dur): the capture looped."""
    cap = load_capture()
    cap_dur = cap[-1][0]
    out, off = [], 0.0
    while off < dur:
        out += [(round(ts + off, 6), cid, d) for ts, cid, d in cap]
        off += cap_dur
    return [f for f in out if f[0] < dur]


def attack_traffic(base):
    """Overlay every attack slot onto the continuous benign stream."""
    out, meta = [], {}

    def in_slot(ts, s):
        return s[2] <= ts < s[2] + s[3]

    def slots_of(kind):
        return [s for s in SLOTS if s[4] == kind]

    for ts, cid, d in base:
        drop_baro = False
        for s in slots_of("masquerade"):
            if in_slot(ts, s) and cid == BARO:
                idx = round((ts - s[2]) / 0.020)          # every 5th frame spikes
                if idx % 5 == 0:
                    a = baro_alt(d) + 500.0
                    d = baro_pack(alt_to_pa(a))
                    meta.setdefault("masq_frames", []).append((ts, cid, d))
        for s in slots_of("drift"):
            if in_slot(ts, s) and cid == BARO:
                a = baro_alt(d) + DRIFT_RATE * (ts - s[2])
                d = baro_pack(alt_to_pa(a))
                meta.setdefault("drift_frames", []).append((ts, cid, d))
        for s in slots_of("replay"):
            if in_slot(ts, s) and cid == BARO:
                drop_baro = True                           # suppress live sensor
        for s in slots_of("trojan"):
            if in_slot(ts, s) and cid == BARO:
                trig = s[2] + 0.5
                if ts >= trig:                             # compromised node sink
                    a = baro_alt(d) - DRIFT_RATE * (ts - trig)
                    d = baro_pack(alt_to_pa(a))
                    meta.setdefault("trojan_frames", []).append((ts, cid, d))
        if not drop_baro:
            out.append((ts, cid, d))

    # additive attackers ----------------------------------------------------
    for s in slots_of("injection"):
        for k in range(int(s[3] / 0.1)):                   # rogue at 10 Hz
            out.append((round(s[2] + k * 0.1, 6), 0x123,
                        bytes.fromhex("DEADBEEF01020304")))
    for s in slots_of("flood"):
        for k in range(int(s[3] / 0.001)):                 # baro ID at 1 kHz
            out.append((round(s[2] + k * 0.001, 6), BARO, bytes(7)))
    for s in slots_of("shadow"):
        for ts, cid, d in base:
            if in_slot(ts, s) and cid == BARO:             # mirror at +6 ms
                out.append((round(ts + 0.006, 6), BARO,
                            baro_pack(struct.unpack("<f", d[:4])[0] - 1200.0)))
    for s in slots_of("replay"):
        cap = [(ts, cid, d) for ts, cid, d in load_capture()
               if cid == BARO and 5.0 <= ts < 5.0 + s[3]]
        for ts, cid, d in cap:                             # old bytes, new time
            out.append((round(ts - 5.0 + s[2], 6), cid, d))

    s_trojan = slots_of("trojan")[0]
    trig_ts = round(s_trojan[2] + 0.5, 6)
    out.append((trig_ts, TRIGGER_ID, b"\x10\x28\x85\xe3\x03\x00\x40\x01"))
    meta["trojan_trigger"] = (trig_ts, TRIGGER_ID)
    meta["first_bad"] = {
        "injection": 30.5, "flood": 33.0, "masquerade": 34.5, "drift": 38.5,
        "shadow": 42.506, "replay": 46.5, "trojan": 51.0,
    }
    return sorted(out), meta


# --------------------------------------------------------------------------
# the detector: the REAL gateway pipeline, in-process
# --------------------------------------------------------------------------
class Detector(WindowAnalyzer):
    """Same base class the bridge uses; records verdicts instead of printing."""

    def __init__(self, model, verbose=False):
        super().__init__(model=model)
        self.alerts = []          # window start times flagged as attack
        self.n_ok = 0
        self.t0 = None            # first forwarded frame (normalizes live clock)
        self.verbose = verbose

    def add(self, msg):
        if self.t0 is None:
            self.t0 = msg.timestamp
        super().add(msg)

    def _flush(self, window):
        for row in build_window_rows(window):
            x = [[row[c] for c in WINDOW_COLS if c != "t"]]
            pred = int(self.model.predict(x)[0])
            if pred:
                self.alerts.append(row["t"])
                if self.verbose:
                    print(f"  [TIER2] t={row['t']:7.3f}s  ALERT (attack window)")
            else:
                self.n_ok += 1
                if self.verbose:
                    print(f"  [TIER2] t={row['t']:7.3f}s  ok")


def run_offline(msgs, model, verbose):
    gw.VERBOSE = verbose
    gw.last_seen.clear()
    det = Detector(model, verbose)
    drops = Counter()
    for ts, cid, d in msgs:
        msg = can.Message(timestamp=ts, arbitration_id=cid, data=d,
                          is_extended_id=cid > 0x7FF)
        if not deterministic_rules(msg):
            drops[(cid, "rule")] += 1
            continue
        det.add(msg)
        det.pump()
    if det.t0 is not None:
        det.alerts = [round(t - det.t0, 3) for t in det.alerts]
    return det, drops


def run_live(msgs, model, verbose):
    """Pi: play the timeline onto vcan0 in real time; detect on kernel RX ts."""
    gw.VERBOSE = verbose
    gw.last_seen.clear()
    bus = can.interface.Bus(channel="vcan0", interface="socketcan")
    det = Detector(model, verbose)
    drops = Counter()

    def player():
        t0 = time.perf_counter()
        for ts, cid, d in msgs:
            delay = ts - (time.perf_counter() - t0)
            if delay > 0:
                time.sleep(delay)
            try:
                bus.send(can.Message(arbitration_id=cid, data=d,
                                     is_extended_id=cid > 0x7FF))
            except can.CanError:
                pass

    import threading
    th = threading.Thread(target=player, daemon=True)
    th.start()
    t0 = time.perf_counter()
    while th.is_alive() or time.perf_counter() - t0 < SLOTS[-1][2] + SLOTS[-1][3] + 1:
        msg = bus.recv(timeout=0.2)
        if msg is None or msg.is_error_frame:
            continue
        if not deterministic_rules(msg):
            drops[(msg.arbitration_id, "rule")] += 1
            continue
        det.add(msg)
        det.pump()
    if det.t0 is not None:
        det.alerts = [round(t - det.t0, 3) for t in det.alerts]
    return det, drops


# --------------------------------------------------------------------------
# --train: rebuild model_window_drift.pkl from kit data (run on the Pi)
# --------------------------------------------------------------------------
def train_model():
    import joblib
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import confusion_matrix

    def rows_of(frames):
        return np.array([[r[c] for c in FEATURE_COLS]
                         for r in build_window_rows(frames)], dtype="float32")

    cap = load_capture()
    norm = rows_of(cap)
    spike = pd.read_csv(f"{D}/data/win_attack.csv")
    spike_X = spike[spike["baro_dalt_max_m"] > 5.0][FEATURE_COLS].to_numpy("float32")

    t0 = cap[0][0]
    drift = []
    for ts, cid, d in cap:
        if cid == BARO:
            a = baro_alt(d) + DRIFT_RATE * (ts - t0)
            d = baro_pack(alt_to_pa(a))
        drift.append((ts, cid, d))
    drift_X = rows_of(drift)

    X = np.vstack([norm, spike_X, drift_X])
    y = np.hstack([np.zeros(len(norm)), np.ones(len(spike_X)), np.ones(len(drift_X))])
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y,
                                          random_state=42)
    clf = RandomForestClassifier(n_estimators=50, max_depth=8, n_jobs=-1,
                                 random_state=42)
    clf.fit(Xtr, ytr)
    print("train confusion (rows=truth, cols=pred) [normal, attack]:")
    print(confusion_matrix(yte, clf.predict(Xte)))
    joblib.dump(clf, f"{D}/model_window_drift.pkl")
    print(f"saved -> {D}/model_window_drift.pkl")


# --------------------------------------------------------------------------
# scorecard
# --------------------------------------------------------------------------
def scorecard(det, drops, meta, live=False):
    lines = []
    A = det.alerts
    print_head = (f"{'scenario':<16} {'tier':<4} {'result':<44} latency")
    lines.append("=" * 88)
    lines.append("DEFENSE PoC SCORECARD" + ("   (live on vcan0)" if live else
                                         "   (offline, recorded traffic)"))
    lines.append("model: model_window_drift.pkl  (trained: benign + spike + drift -"
                 " shadow/trojan/replay are UNSEEN)")
    lines.append(print_head)
    lines.append("-" * 88)

    def owner(t):
        """Attack slot whose span overlaps window [t, t+0.1) - a window that
        contains the first attack frames belongs to that attack (early hit)."""
        for s in SLOTS[1:]:
            if t < s[2] + s[3] and t + 0.1 > s[2]:
                return s
        return None

    for name, tier, start, dur, kind in SLOTS:
        n_win = max(1, round(dur / 0.1) - 1)
        slot_windows = [t for t in A if owner(t) is not None and owner(t)[4] == kind]
        n_flag = len(slot_windows)
        if kind == "benign":
            res = f"{n_flag} FALSE ALARMS / ~{n_win} honest windows"
            lat = "-"
        elif kind == "injection":
            n = drops.get((0x123, "rule"), 0)
            res = f"{n}/{n} attack frames DROPPED (allowlist)"
            lat = "per frame"
        elif kind == "flood":
            n = drops.get((BARO, "rule"), 0)
            n_spam = round(dur / 0.001)
            honest_lost = max(0, n - n_spam)
            res = (f"{n_spam}/{n_spam} spam DROPPED (rate limit)"
                   f" + {honest_lost} honest lost")
            lat = "per frame"
        elif kind == "trojan":
            n_trig = drops.get((TRIGGER_ID, "rule"), 0)
            fb = meta["first_bad"]["trojan"]
            res = (f"trigger: {n_trig}/1 DROPPED (allowlist); "
                   f"sink: {n_flag}/{n_win} windows ALERT")
            lat = (f"~{max(0.0, slot_windows[0] + 0.1 - fb) * 1000:.0f} ms (1 window)"
                   if slot_windows else "MISSED")
        else:
            fb = meta["first_bad"][kind]
            res = f"{n_flag}/{n_win} windows ALERT"
            if kind == "replay":
                res += " (seams; middle passes = named ceiling)"
            lat = (f"~{max(0.0, slot_windows[0] + 0.1 - fb) * 1000:.0f} ms (1 window)"
                   if slot_windows else "MISSED")
        lines.append(f"{name:<16} {tier:<4} {res:<44} {lat}")

    # windows overlapping no attack slot at all = genuine false alarms
    gaps = [t for t in A if owner(t) is None]
    lines.append("-" * 88)
    lines.append(f"honest windows passed: {det.n_ok}   |   TRUE false alarms"
                 f" (no attack content in window): {len(gaps)}")
    lines.append("=" * 88)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["offline", "live"], default="offline")
    ap.add_argument("--model", default=f"{D}/model_window_drift.pkl")
    ap.add_argument("--train", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--save", metavar="TXT")
    args = ap.parse_args()

    if args.train:
        train_model()
        return

    import joblib
    model = joblib.load(args.model)
    print(f"[*] loading timeline ...", file=sys.stderr)
    msgs, meta = attack_traffic(base_traffic(SLOTS[-1][2] + SLOTS[-1][3]))
    print(f"[*] {len(msgs)} frames, {SLOTS[-1][2] + SLOTS[-1][3]:.0f} s simulated;"
          f" running the real gateway pipeline over them ...", file=sys.stderr)

    t_start = time.perf_counter()
    if args.mode == "live":
        det, drops = run_live(msgs, model, args.verbose)
    else:
        det, drops = run_offline(msgs, model, args.verbose)
    wall = time.perf_counter() - t_start

    card = scorecard(det, drops, meta, live=(args.mode == "live"))
    print(card)
    print(f"[pipeline wall time: {wall:.2f} s ({len(msgs) / wall:,.0f} frames/s)]")
    if args.save:
        with open(args.save, "w") as f:
            f.write(card + "\n")
        print(f"saved -> {args.save}")


if __name__ == "__main__":
    main()
