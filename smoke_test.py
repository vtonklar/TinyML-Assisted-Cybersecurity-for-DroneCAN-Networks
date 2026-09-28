#!/usr/bin/env python3
"""End-to-end smoke test on python-can's in-process virtual bus - no vcan, no sudo.

Wires the REAL attack frame builder (07_masquerade.frame), the REAL gateway
Tier-1 rules (gateway_bridge.deterministic_rules) and the REAL 100 ms window
features (window_features) over one virtual channel, then verifies the whole
masquerade story in a few seconds:

  1. benign traffic only          -> Tier 1 forwards, model stays silent (FPR side)
  2. masquerade takeover          -> Tier 1 still forwards every lie frame (the hole)
  3. event-level windows          -> model flags the lie-carrying windows (the fix)

and prints the detector PAIR: event detection rate + false alarms per benign hour.

Run anywhere the deps exist:   python smoke_test.py
(deps: python-can numpy scikit-learn - no pandas needed)
"""
import importlib.util
import math
import struct
import threading
import time

import can
import numpy as np

import window_features as wf
from gateway_bridge import ALLOWED_IDS, WindowAnalyzer, deterministic_rules

_spec = importlib.util.spec_from_file_location("masq", "07_masquerade.py")
masq_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(masq_mod)  # noqa: F841 - importing registers alt_to_pa/frame

BARO_ID = 0x10040405
EVENT_M = 5.0        # >5 m baro jump per 100 ms window = physically impossible = a lie
BENIGN_S = 3.0
ATTACK_S = 4.0


def train_model():
    """Shallow RF on synthetic windows: normal vs masquerade takeover."""
    def gen(masq):
        frames, due, t, n = [], {c: 0.0 for c in ALLOWED_IDS}, 0.0, 0
        while t < 20.0:
            t += 0.002
            jobs = [(0x18FF1101, 0.10, struct.pack(">ff", 52.0, 21.0)),
                    (0x18FF1201, 0.05, struct.pack(">Hf", 0, 8.0)),
                    (0x18FF1301, 0.20, struct.pack(">HH", 1200, 75))]
            alt = 500.0 if masq and n % 5 == 4 else 2.0 * float(np.sin(t / 7.0))
            jobs.append((BARO_ID, 0.02,
                         struct.pack("<fH", masq_mod.alt_to_pa(alt), 4) + b"\xc0"))
            for cid, per, data in jobs:
                if t >= due[cid]:
                    due[cid] += per
                    frames.append((t, cid, data))
                    n += cid == BARO_ID
        return frames

    rows, labels = [], []
    for masq in (False, True):
        r = wf.build_window_rows(gen(masq))
        rows += r
        labels += [int(masq)] * len(r)
    X = np.array([[r[c] for c in wf.FEATURE_COLS] for r in rows], dtype="float32")
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42).fit(
        X, np.array(labels))


def main():
    model = train_model()
    print("[1] windowed RF trained (50 trees, depth 8)")

    tx = can.Bus(interface="virtual", channel="smoke")   # attackers + sensors
    rx0 = can.Bus(interface="virtual", channel="smoke")  # gateway (untrusted side)
    rx1 = can.Bus(interface="virtual", channel="smoke")  # trusted-side monitor

    stop = threading.Event()
    masq_on = threading.Event()

    def periodic(period, build):
        t0, n = time.time(), 0
        while not stop.is_set():
            tx.send(build(n, time.time() - t0))
            n += 1
            time.sleep(max(0.0, t0 + period * n - time.time()))

    def baro_node(n, t):
        alt = 2.0 * math.sin(t / 7.0)                    # honest wobble
        if masq_on.is_set() and n % 5 == 4:              # takeover: +500 m lie every 5th
            alt += 500.0
        return masq_mod.frame(masq_mod.alt_to_pa(alt))

    def msg(cid, data):
        return can.Message(arbitration_id=cid, data=data, is_extended_id=True)

    threads = [threading.Thread(target=periodic, args=(p, b), daemon=True)
               for p, b in [(0.10, lambda n, t: msg(0x18FF1101, struct.pack(">ff", 52.0 + 0.01 * math.sin(t / 11), 21.0))),
                            (0.05, lambda n, t: msg(0x18FF1201, struct.pack(">Hf", 0, 8.0 + 0.1 * math.sin(t / 5)))),
                            (0.20, lambda n, t: msg(0x18FF1301, struct.pack(">HH", 1200, 75))),
                            (0.02, baro_node)]]
    for th in threads:
        th.start()

    def gateway_run(seconds, tag):
        """Run the gateway loop; return (forwarded, feature rows)."""
        win = WindowAnalyzer()
        forwarded = []
        t_end = time.time() + seconds
        while time.time() < t_end:
            msg = rx0.recv(timeout=0.1)
            if msg is None:
                continue
            if deterministic_rules(msg):
                forwarded.append(msg)
                rx1.send(can.Message(arbitration_id=msg.arbitration_id, data=msg.data,
                                     is_extended_id=msg.is_extended_id))
                win.add(msg)
                win.pump()
        frames = [(m.timestamp, m.arbitration_id, bytes(m.data)) for m in forwarded]
        print(f"[{tag}] forwarded {len(forwarded)} frames "
              f"({sum(1 for m in forwarded if m.arbitration_id == BARO_ID)} baro)")
        return forwarded, wf.build_window_rows(frames)

    def predict(rows):
        return model.predict(np.array([[r[c] for c in wf.FEATURE_COLS]
                                       for r in rows], dtype="float32"))

    print(f"[2a] benign traffic only, {BENIGN_S:.0f} s - measuring false alarms ...")
    _, benign_rows = gateway_run(BENIGN_S, "2a")
    fp = int((predict(benign_rows) == 1).sum())
    n_ben = len(benign_rows)

    print(f"[2b] masquerade takeover, {ATTACK_S:.0f} s - Tier 1 must stay blind ...")
    masq_on.set()
    forwarded, attack_rows = gateway_run(ATTACK_S, "2b")
    stop.set()
    masq_on.clear()

    preds = predict(attack_rows)
    event_idx = [i for i, r in enumerate(attack_rows) if r["baro_dalt_max_m"] > EVENT_M]
    hits = sum(1 for i in event_idx if preds[i] == 1)
    clean = all(r["baro_dalt_max_m"] > 1 for r, p in zip(attack_rows, preds) if p == 1)
    hours = max(n_ben * wf.WINDOW_S / 3600.0, 1e-9)

    print(f"[3] event windows: {len(event_idx)} | caught: {hits} | "
          f"false alarms: {fp}/{n_ben} benign windows")
    print(f"[4] detector pair: event detection {100.0 * hits / max(len(event_idx), 1):.1f}% | "
          f"false alarms {fp / hours:.1f} per benign hour")
    print(f"[5] rules-only baseline: 100% of masquerade frames forwarded "
          f"(the [2b] forward count IS the failure-log fact)")
    assert len(forwarded) > 100, "masquerade must reach and pass the gateway"
    fwd_ids = {m.arbitration_id for m in forwarded}
    assert fwd_ids == set(ALLOWED_IDS), \
        f"all four traffic IDs must flow, got only {sorted(hex(i) for i in fwd_ids)}"
    assert len(event_idx) >= 5, "spike windows must exist in the attack phase"
    assert hits == len(event_idx), "every lie-carrying window must be flagged"
    assert fp == 0, "benign phase must produce zero false alarms"
    assert clean, "alerts must be the windows with impossible altitude deltas"
    print("\nSMOKE TEST PASSED - Tier 1 forwards the masquerade; event windows catch it, "
          "benign traffic stays silent.")
    for b in (tx, rx0, rx1):
        b.shutdown()


if __name__ == "__main__":
    main()
