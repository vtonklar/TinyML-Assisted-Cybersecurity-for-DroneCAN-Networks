"""Shared feature engineering - imported by 04_train_rf.py and 05_live_detect.py.

One row = one CAN frame. Features are simple on purpose (Phase 1):
identifier, flags, payload bytes, and inter-arrival time on the whole bus.
"""
import numpy as np

# Columns written by 03_sniff_to_csv.py (before the dt column is added)
RAW_COLS = ["ts", "can_id", "is_ext", "dlc"] + [f"b{i}" for i in range(8)]

# Columns the model actually sees
FEATURE_COLS = ["can_id", "is_ext", "dlc"] + [f"b{i}" for i in range(8)] + ["dt"]


def add_dt(df):
    """Inter-arrival time between consecutive frames on the bus (first frame: 1.0s)."""
    df = df.sort_values("ts").copy()
    df["dt"] = df["ts"].diff().fillna(1.0)
    return df


def feature_matrix(df):
    return df[FEATURE_COLS].to_numpy(dtype=np.float32)


def row_features(can_id, is_ext, dlc, data8, dt):
    """Single-row feature vector for live inference, no pandas needed per frame."""
    return np.array([[can_id, is_ext, dlc, *data8, dt]], dtype=np.float32)
