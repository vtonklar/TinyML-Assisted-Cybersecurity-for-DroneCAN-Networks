#!/usr/bin/env python3
"""Train the windowed ML baseline (Tier 2) - shallow Random Forest.

  python 08_train_baseline.py --normal data/win_normal.csv --attack data/win_attack.csv

Input = the 100 ms window features dumped by `gateway_bridge.py --collect`.

Labels are EVENT-level by default (--relabel-threshold M, default 5 m): a
window from the attack run counts as attack only if it actually carries an
impossible baro jump (> M m within one 100 ms window - no quadcopter does
that, so it is safe ground truth for the spikes WE injected). Windows between
spikes are honest by construction and are relabeled 0. With the default spike
cadence only ~1 in 10 windows of an attack run carries a lie, so run-level
labels would train (and score) on ~90% wrong labels.

Reporting follows the detector-pair rule: an event detection rate is only
meaningful next to its false-alarm rate on the benign reference envelope,
reported as false alarms per benign hour (FPR_h). A lone accuracy number is
not a result.

Deliberately lightweight (50 trees, depth 8): this is the baseline the
Phase 2 INT8 TinyML port must beat or match on the MCU. Saves model_window.pkl
for `gateway_bridge.py --model`.
"""
import argparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from window_features import FEATURE_COLS, WINDOW_S


def load(path, label):
    df = pd.read_csv(path)
    df["label"] = label
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--normal", nargs="+", default=["data/win_normal.csv"])
    ap.add_argument("--attack", nargs="+", default=["data/win_attack.csv"])
    ap.add_argument("--relabel-threshold", type=float, default=5.0,
                    help="attack-run windows with baro_dalt_max_m above this (m per "
                         "100 ms) are the true event windows, the rest relabel to 0; "
                         "0 keeps the raw run-level labels")
    ap.add_argument("--out", default="model_window.pkl")
    args = ap.parse_args()

    benign = pd.concat([load(f, 0) for f in args.normal], ignore_index=True)
    attack = pd.concat([load(f, 1) for f in args.attack], ignore_index=True)
    if args.relabel_threshold > 0:
        events = (attack["baro_dalt_max_m"] > args.relabel_threshold).astype(int)
        attack["label"] = events
        print(f"[relabel] {int(events.sum())}/{len(attack)} attack-run windows carry an "
              f"impossible baro jump (>{args.relabel_threshold:.0f} m per 100 ms); the rest "
              f"are honest-by-construction and train as normal.")

    df = pd.concat([benign, attack], ignore_index=True).fillna(0.0)
    print(f"Dataset: {len(df)} windows | normal={int((df.label == 0).sum())} "
          f"event={int((df.label == 1).sum())}")

    X, y = df[FEATURE_COLS].to_numpy(dtype="float32"), df["label"].to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)

    clf = RandomForestClassifier(n_estimators=50, max_depth=8, n_jobs=-1, random_state=42)
    clf.fit(X_tr, y_tr)

    pred = clf.predict(X_te)
    print(classification_report(y_te, pred, target_names=["normal", "event"], digits=4))
    print("Confusion matrix (rows=truth, cols=pred) [normal, event]:")
    print(confusion_matrix(y_te, pred))

    # -- the detector PAIR (report both, or neither) --
    n_ben = int((y_te == 0).sum())
    fp = int(((y_te == 0) & (pred == 1)).sum())
    n_ev = int((y_te == 1).sum())
    hit = int(((y_te == 1) & (pred == 1)).sum())
    hours = max(n_ben * WINDOW_S / 3600.0, 1e-9)
    print("\nDetector pair (the only reportable form):")
    print(f"  event detection rate : {100.0 * hit / max(n_ev, 1):.1f}% "
          f"({hit}/{n_ev} lie-carrying windows caught)")
    print(f"  false alarms         : {fp}/{n_ben} benign windows -> "
          f"{fp / hours:.1f} per benign hour "
          f"(benign envelope {n_ben * WINDOW_S:.0f}s here - run the full envelope on the Pi)")

    print("\nTop features (what separates the masquerade from normal traffic):")
    for name, imp in sorted(zip(FEATURE_COLS, clf.feature_importances_),
                            key=lambda kv: -kv[1])[:8]:
        print(f"  {imp:5.3f}  {name}")

    joblib.dump(clf, args.out)
    print(f"\nSaved model -> {args.out}   (live: python gateway_bridge.py --model {args.out})")
    print("Rules-only baseline for the results table: forwarded 100% of masquerade "
          "frames (masquerade_failure.log) - the AI is what closes that gap.")


if __name__ == "__main__":
    main()
