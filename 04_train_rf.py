#!/usr/bin/env python3
"""Phase 1 - Task 1.4: train a Random Forest on labelled captures.

  python 04_train_rf.py --normal data/normal.csv --attack data/attack_dos.csv data/attack_spoof.csv

Saves model.pkl for 05_live_detect.py. Prints a classification report -
expect near-perfect scores on vcan; see README for how to make the
evaluation honest enough for a thesis committee.
"""
import argparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from features import add_dt, feature_matrix


def load(path, label):
    df = add_dt(pd.read_csv(path))
    df["label"] = label
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--normal", nargs="+", default=["data/normal.csv"])
    ap.add_argument("--attack", nargs="+", default=["data/attack_dos.csv"])
    ap.add_argument("--out", default="model.pkl")
    args = ap.parse_args()

    parts = [load(f, 0) for f in args.normal] + [load(f, 1) for f in args.attack]
    df = pd.concat(parts, ignore_index=True)
    print(f"Dataset: {len(df)} frames | normal={int((df.label == 0).sum())} attack={int((df.label == 1).sum())}")

    X, y = feature_matrix(df), df["label"].to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)

    clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)
    clf.fit(X_tr, y_tr)

    pred = clf.predict(X_te)
    print(classification_report(y_te, pred, target_names=["normal", "attack"], digits=4))
    print("Confusion matrix (rows=truth, cols=pred) [normal, attack]:")
    print(confusion_matrix(y_te, pred))

    joblib.dump(clf, args.out)
    print(f"Saved model -> {args.out}")


if __name__ == "__main__":
    main()
