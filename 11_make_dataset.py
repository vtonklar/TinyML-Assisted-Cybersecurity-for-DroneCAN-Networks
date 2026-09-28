#!/usr/bin/env python3
"""One-command dataset reproduction: raw frame captures + window feature tables.

  python 11_make_dataset.py                 # virtual bus (no vcan/sudo) - works anywhere
  python 11_make_dataset.py --interface socketcan --channel vcan0   # on the Pi

Phase A (benign): 4 telemetry nodes -> data/raw_normal.csv  + data/win_normal.csv
Phase B (masquerade): baro node trojaned, +500 m spike every 10th frame
                  -> data/raw_attack.csv    + data/win_attack.csv

Raw CSVs use the kit's RAW_COLS (features.py) with a label column - the
archival, replayable dataset layer (same shape as 03_sniff_to_csv.py).
Window CSVs are the training tables for 08_train_baseline.py, written through
the REAL gateway path (deterministic_rules -> WindowAnalyzer), so what the
model trains on is byte-identical to what it sees live.

Attack-run window labels are run-level (1); 08 relabels to event-level by
ground truth (baro_dalt_max_m > 5 m per 100 ms).
"""
import argparse
import csv
import math
import struct
import sys
import threading
import time

import can

import window_features as wf
from features import RAW_COLS
from gateway_bridge import WindowAnalyzer, deterministic_rules

import importlib.util
_spec = importlib.util.spec_from_file_location("masq", "07_masquerade.py")
masq_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(masq_mod)

EVENT_M = 5.0   # >5 m baro jump per 100 ms = physically impossible = injected spike


def raw_writer(path, label):
    f = open(path, "w", newline="")
    wr = csv.writer(f)
    wr.writerow(RAW_COLS + ["label"])
    return f, wr


def raw_row(msg, label):
    data = list(msg.data) + [0] * (8 - len(msg.data))
    return [f"{msg.timestamp:.6f}", msg.arbitration_id, int(msg.is_extended_id),
            msg.dlc, *data, label]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interface", default="virtual")
    ap.add_argument("--channel", default="dataset")
    ap.add_argument("--benign-secs", type=float, default=30.0)
    ap.add_argument("--attack-secs", type=float, default=20.0)
    ap.add_argument("--spike-every", type=int, default=10)
    ap.add_argument("--jump", type=float, default=500.0)
    args = ap.parse_args()

    tx = can.Bus(interface=args.interface, channel=args.channel)
    rx = can.Bus(interface=args.interface, channel=args.channel)
    stop = threading.Event()
    masq_on = threading.Event()

    def periodic(period, build):
        t0, n = time.time(), 0
        while not stop.is_set():
            tx.send(build(n, time.time() - t0))
            n += 1
            time.sleep(max(0.0, t0 + period * n - time.time()))

    spikes = []          # frame# that carried the lie, for the raw-capture index

    def baro_node(n, t):
        alt = 2.0 * math.sin(t / 7.0)                       # honest wobble
        if masq_on.is_set() and n % args.spike_every == args.spike_every - 1:
            alt += args.jump                                # the lie
            spikes.append(n)
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

    def capture(seconds, tag, label, raw_path, win_path):
        f, wr = raw_writer(raw_path, label)
        win = WindowAnalyzer(out_csv=win_path, label=label)
        n_frames = 0
        t_end = time.time() + seconds
        while time.time() < t_end:
            m = rx.recv(timeout=0.1)
            if m is None or not deterministic_rules(m):
                continue
            wr.writerow(raw_row(m, label))
            win.add(m)
            win.pump()
            n_frames += 1
        win.close()
        f.close()
        print(f"[{tag}] {n_frames} frames -> {raw_path}")
        return n_frames

    print(f"[1] benign phase {args.benign_secs:.0f}s ...")
    capture(args.benign_secs, "1", 0, "data/raw_normal.csv", "data/win_normal.csv")

    print(f"[2] masquerade phase {args.attack_secs:.0f}s "
          f"(+{args.jump:.0f} m every {args.spike_every}th baro frame) ...")
    masq_on.set()
    capture(args.attack_secs, "2", 1, "data/raw_attack.csv", "data/win_attack.csv")
    stop.set()
    for b in (tx, rx):
        b.shutdown()

    # ---- summary: the dataset, shown ----
    import pandas as pd
    ben, atk = pd.read_csv("data/win_normal.csv"), pd.read_csv("data/win_attack.csv")
    events = int((atk["baro_dalt_max_m"] > EVENT_M).sum())
    print(f"\n[3] dataset summary")
    print(f"    raw_normal.csv : benign frames,  label 0")
    print(f"    raw_attack.csv : masquerade frames, label 1  ({len(spikes)} injected spikes)")
    print(f"    win_normal.csv : {len(ben)} benign windows   (label 0)")
    print(f"    win_attack.csv : {len(atk)} attack-run windows (label 1)")
    print(f"      of which {events} carry an impossible jump (> {EVENT_M:.0f} m per 100 ms)"
          f" -> event ground truth; the other {len(atk) - events} are honest-by-construction")
    print(f"\n[4] train next:  python 08_train_baseline.py")


if __name__ == "__main__":
    main()
