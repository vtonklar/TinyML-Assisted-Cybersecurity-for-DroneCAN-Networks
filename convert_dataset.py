#!/usr/bin/env python3
"""Convert a downloaded CAN dataset into this lab's two formats.

  python convert_dataset.py FILE --csv data/attack_uav.csv --log data/attack_uav.log

  --csv  -> rows in the kit's RAW_COLS format, fed straight into 04_train_rf.py
  --log  -> candump-format log, replayed with:  canplayer < data/attack_uav.log

Auto-detects three common line styles:
  1) candump log:    (1700000000.123456) can0 18FF1101#0011223344556677
  2) candump stdout:    can0  18FF1101   [8]  00 11 22 33 44 55 66 77
  3) plain CSV:      timestamp,id,dlc,b0,...,b7(,extra columns ignored)

Rules: hex IDs of 4+ digits -> 29-bit extended; IDs > 0x7FF also extended.
Non-hex payload placeholders ('**') become 0x00 and are counted.
"""
import argparse
import csv
import re
import sys
from datetime import datetime

RE_LOG = re.compile(r"^\((\d+(?:\.\d+)?)\)\s+\S+\s+([0-9A-Fa-f]+)#([0-9A-Fa-f*]*)\s*$")
RE_OUT = re.compile(r"^\s*\S+\s+([0-9A-Fa-f]+)\s+\[(\d+)\]\s+(.+?)\s*$")
HEXPAIR = re.compile(r"[0-9A-Fa-f*?]{2}")


def to_ts(tok):
    try:
        return float(tok)
    except ValueError:
        try:
            return datetime.fromisoformat(tok.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None


def to_id(tok):
    tok = tok.strip()
    try:
        if re.fullmatch(r"0[xX][0-9A-Fa-f]+", tok):
            return int(tok, 16)
        if re.fullmatch(r"[0-9A-Fa-f]{2,}", tok) and (
            any(c in "abcdefABCDEF" for c in tok) or (len(tok) >= 3 and tok[0] == "0")
        ):
            return int(tok, 16)  # hex-ish token: letters, or leading zero + 3+ digits
        v = int(float(tok))  # plain decimal
    except ValueError:
        return None
    return v if 0 <= v <= 0x1FFFFFFF else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--csv", help="output CSV for 04_train_rf.py")
    ap.add_argument("--log", help="output candump log for canplayer")
    ap.add_argument("--format", choices=["auto", "log", "stdout", "csv"], default="auto")
    ap.add_argument("--data-decimal", action="store_true",
                    help="CSV data columns are DECIMAL bytes (OTIDS / Car-Hacking "
                         "from HCRL), not hex pairs")
    args = ap.parse_args()

    parsed = skipped = wild = 0
    ts_first = ts_last = None
    out_csv = open(args.csv, "w", newline="") if args.csv else None
    out_log = open(args.log, "w") if args.log else None
    wr = csv.writer(out_csv) if out_csv else None
    if wr:
        wr.writerow(["ts", "can_id", "is_ext", "dlc"] + [f"b{i}" for i in range(8)])

    def emit(ts, cid, ext, data):
        nonlocal parsed, ts_first, ts_last
        data8 = (data + [0] * 8)[:8]
        dlc = len(data)
        if wr:
            wr.writerow([f"{ts:.6f}", cid, int(ext), dlc, *data8])
        if out_log:
            hexid = f"{cid:08X}" if ext else f"{cid:03X}"
            out_log.write(f"({ts:.6f}) vcan0 {hexid}#{''.join(f'{b:02X}' for b in data8[:dlc])}\n")
        parsed += 1
        ts_first = ts if ts_first is None else ts_first
        ts_last = ts

    def parse_bytes(rest):
        nonlocal wild
        out = []
        for tok in HEXPAIR.findall(rest):
            if "*" in tok or "?" in tok:
                out.append(0)
                wild += 1
            else:
                out.append(int(tok, 16))
        return out

    with open(args.file, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            style = args.format
            if style in ("auto", "log"):
                m = RE_LOG.match(line)
                if m:
                    ts = to_ts(m.group(1))
                    cid = int(m.group(2), 16)
                    if ts is not None:
                        emit(ts, cid, cid > 0x7FF or len(m.group(2)) > 3, parse_bytes(m.group(3)))
                        continue
            if style in ("auto", "stdout"):
                m = RE_OUT.match(line)
                if m:
                    cid = int(m.group(1), 16)
                    # stdout lines carry no timestamp; synthesise one from line order
                    emit(parsed * 0.001, cid, cid > 0x7FF or len(m.group(1)) > 3, parse_bytes(m.group(3)))
                    continue
            if style in ("auto", "csv"):
                cells = [c.strip() for c in line.split(",")]
                if len(cells) >= 4:
                    ts = to_ts(cells[0])
                    off = 0
                    if ts is None and len(cells) >= 5:
                        # label column first (LUMI/UAVCAN sets): Label,Timestamp,ID,DLC,Data
                        ts, off = to_ts(cells[1]), 1
                    if ts is not None:
                        cid = to_id(cells[1 + off])
                        if cid is not None:
                            try:
                                dlc = int(float(cells[2 + off]))
                            except ValueError:
                                dlc = 8
                            dlc = max(0, min(dlc, 8))
                            if args.data_decimal:  # OTIDS/HCRL: one decimal byte per cell
                                data = [int(float(c)) & 0xFF for c in cells[3 + off:3 + off + dlc]]
                            else:
                                data = parse_bytes(" ".join(cells[3 + off:]))[:dlc]
                            emit(ts, cid, cid > 0x7FF, data)
                            continue
            skipped += 1

    if out_csv:
        out_csv.close()
    if out_log:
        out_log.close()

    if parsed == 0:
        print(f"Parsed 0 frames from {args.file}. Paste `head -3 {args.file}` back to me "
              f"and I'll adjust the parser (if it is .pcap, that needs a different path).")
        sys.exit(1)

    span = f"{ts_last - ts_first:.1f}s span" if ts_first is not None and ts_last else "n/a"
    print(f"Parsed {parsed} frames ({skipped} skipped, {wild} wildcard bytes) - {span}")
    if args.csv:
        print(f"  CSV -> {args.csv}   (train: 04_train_rf.py --attack/--normal {args.csv})")
    if args.log:
        print(f"  LOG -> {args.log}   (replay: canplayer -t -g 1 < {args.log})")


if __name__ == "__main__":
    main()
