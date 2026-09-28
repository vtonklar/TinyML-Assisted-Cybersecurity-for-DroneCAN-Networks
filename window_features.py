"""Temporal feature engineering over a fixed 100 ms window of CAN frames.

Imported by gateway_bridge.py (live) and 08_train_baseline.py / 09_baseline.ipynb
(training). Pure functions - no python-can dependency - so the same code can be
unit-tested off the bus and ported to C later (Phase 2 argument).

One row = one 100 ms window. Three feature families (per the proposal):

  1. inter-arrival deviations   dt_mean/dt_std per sensor vs its nominal period
  2. payload deltas             byte-wise max delta + decoded physics deltas
  3. cross-message consistency  baro altitude delta vs rpm/speed/gps deltas,
                               left as raw features so the model learns the
                               "altitude spike while motors stay flat" relation
"""
import math
import struct

WINDOW_S = 0.100  # exactly 100 ms of traffic per row

# Must match 01_make_traffic.py (names become feature suffixes)
NOMINAL = {  # can_id: (name, period_s)
    0x10040405: ("baro", 0.020),
    0x18FF1201: ("speed", 0.050),
    0x18FF1101: ("gps", 0.100),
    0x18FF1301: ("rpm", 0.200),
}

# Column order for CSV / model (t and label are metadata, not features)
WINDOW_COLS = (
    ["t", "n_frames", "bus_dt_mean", "bus_dt_std"]
    + [f"{f}_{n}" for n, _ in NOMINAL.values()
       for f in ("cnt", "dt_mean", "dt_std", "pdelta_max")]
    + ["baro_dalt_max_m", "baro_climb_mps", "gps_dlat_max", "speed_dmax", "rpm_dmax"]
)
FEATURE_COLS = [c for c in WINDOW_COLS if c != "t"]


def isa_alt_m(pressure_pa: float) -> float:
    """ISA: h = 44330 * (1 - (P/P0)^(1/5.255))."""
    return 44330.0 * (1.0 - (pressure_pa / 101325.0) ** (1.0 / 5.255))


def _byte_delta_max(prev: bytes, cur: bytes) -> int:
    return max((abs(a - b) for a, b in zip(prev, cur)), default=0)


def build_window_rows(frames, t_start=0.0):
    """frames -> feature rows. One row per 100 ms window.

    frames: iterable of (ts, can_id, data_bytes) that PASSED the rule engine -
            windows analyse exactly what Tier 1 let through (that is the point).
    Returns a list of dicts with keys = WINDOW_COLS.
    """
    frames = sorted(frames)
    if not frames:
        return []

    rows = []
    w_start = frames[0][0]
    w_frames = []

    def flush():
        if w_frames:
            rows.append(_features_for(w_frames, w_start))

    for ts, cid, data in frames:
        while ts - w_start >= WINDOW_S:
            flush()
            w_start += WINDOW_S
            w_frames.clear()
        w_frames.append((ts, cid, data))
    flush()
    return rows


def _features_for(w_frames, w_start):
    row = {c: 0.0 for c in WINDOW_COLS}
    row["t"] = round(w_start, 3)

    ts = [f[0] for f in w_frames]
    row["n_frames"] = len(ts)
    dts = [b - a for a, b in zip(ts, ts[1:])]
    if dts:
        row["bus_dt_mean"] = sum(dts) / len(dts)
        row["bus_dt_std"] = _std(dts)

    per_id = {cid: [] for cid in NOMINAL}
    for ts, cid, data in w_frames:
        per_id.setdefault(cid, []).append((ts, data))

    for cid, items in per_id.items():
        if cid not in NOMINAL:
            continue
        name, period = NOMINAL[cid]
        row[f"cnt_{name}"] = len(items)
        if len(items) >= 2:
            idts = [t for t, _ in items]
            d = [b - a for a, b in zip(idts, idts[1:])]
            row[f"dt_mean_{name}"] = sum(d) / len(d)
            row[f"dt_std_{name}"] = _std(d)
        row[f"pdelta_max_{name}"] = max(
            (_byte_delta_max(p, c) for (_, p), (_, c) in zip(items, items[1:])), default=0
        )

    _decode_baro(row, per_id.get(0x10040405, []))
    _decode_gps(row, per_id.get(0x18FF1101, []))
    _decode_speed(row, per_id.get(0x18FF1201, []))
    _decode_rpm(row, per_id.get(0x18FF1301, []))
    return row


def _std(xs):
    if len(xs) < 2:
        return 0.0
    m = sum(xs) / len(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))


def _decode_baro(row, items):
    """float32 Pa (LE) + float16 variance + UAVCAN tail byte."""
    alts = []
    for _, data in items:
        try:
            alts.append(isa_alt_m(struct.unpack("<f", bytes(data[:4]))[0]))
        except (struct.error, OverflowError, ValueError):
            pass
    if len(alts) >= 2:
        deltas = [abs(b - a) for a, b in zip(alts, alts[1:])]
        row["baro_dalt_max_m"] = max(deltas)
        row["baro_climb_mps"] = max(deltas) / WINDOW_S


def _decode_gps(row, items):
    """GPS lat/lon: >ff floats (see 01_make_traffic.py)."""
    lats = []
    for _, data in items:
        try:
            lats.append(struct.unpack(">f", bytes(data[:4]))[0])
        except (struct.error, ValueError):
            pass
    if len(lats) >= 2:
        row["gps_dlat_max"] = max(abs(b - a) for a, b in zip(lats, lats[1:]))


def _decode_speed(row, items):
    """Speed: >Hf -> (flags, m/s)."""
    vals = []
    for _, data in items:
        try:
            vals.append(struct.unpack(">f", bytes(data[2:6]))[0])
        except (struct.error, ValueError):
            pass
    if len(vals) >= 2:
        row["speed_dmax"] = max(abs(b - a) for a, b in zip(vals, vals[1:]))


def _decode_rpm(row, items):
    """RPM/load: >HH."""
    vals = []
    for _, data in items:
        try:
            vals.append(struct.unpack(">H", bytes(data[:2]))[0])
        except (struct.error, ValueError):
            pass
    if len(vals) >= 2:
        row["rpm_dmax"] = max(abs(b - a) for a, b in zip(vals, vals[1:]))


def window_summary(row) -> str:
    """One-line human view of a window (for gateway logs / the report)."""
    parts = [f"n={row['n_frames']:.0f}"]
    for name, _ in NOMINAL.values():
        parts.append(
            f"{name} {row[f'cnt_{name}']:.0f}f dt={row[f'dt_mean_{name}'] * 1000:.1f}ms"
        )
    parts.append(f"dAlt={row['baro_dalt_max_m']:.1f}m")
    return " ".join(parts)
