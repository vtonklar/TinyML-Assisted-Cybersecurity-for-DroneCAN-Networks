#!/usr/bin/env python3
"""Convert a SocketCAN pcap to a candump log for canplayer.

  python pcap2log.py uavcan_dos.pcap --log data/uavcan_dos.log
  canplayer < data/uavcan_dos.log

Handles pcap link type 228 (LINKTYPE_CAN_SOCKETCAN - what candump -w and most
CAN hardware captures produce): each packet is a 4-byte big-endian pseudo-header
(flags in the top 3 bits, 29-bit CAN ID below) followed by the payload bytes.
For Ethernet/SLL captures of a CAN adapter, use the dataset's CSV/candump
export with convert_dataset.py instead.
"""
import argparse
import struct
import sys

MAGICS = {
    b"\xa1\xb2\xc3\xd4": (">", 1e6),  # pcap, microseconds
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),  # pcap nanosecond
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
}
LINKTYPE_SOCKETCAN = 228


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--log", required=True, help="candump log out (replay: canplayer < LOG)")
    args = ap.parse_args()

    data = open(args.pcap, "rb").read()
    if len(data) < 24:
        sys.exit("not a pcap (too short)")
    if data[:4] not in MAGICS:
        sys.exit(f"not a pcap (magic {data[:4].hex()})")
    endian, scale = MAGICS[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != LINKTYPE_SOCKETCAN:
        sys.exit(f"linktype {linktype} != SocketCAN(228) - use the CSV/candump export instead")

    n = off = 0
    t0 = None
    with open(args.log, "w") as out:
        while off + 16 <= len(data):
            ts_sec, ts_frac, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
            off += 16
            pkt = data[off:off + incl]
            off += incl
            if len(pkt) < 5:  # need pseudo-header + >=1 payload byte
                continue
            raw_id = struct.unpack(">I", pkt[:4])[0]
            cid = raw_id & 0x1FFFFFFF
            ext = bool(raw_id & 0x80000000)
            payload = pkt[4:12]  # classic CAN: up to 8 bytes
            ts = ts_sec + ts_frac / scale
            t0 = ts if t0 is None else t0
            hexid = f"{cid:08X}" if ext else f"{cid:03X}"
            out.write(f"({ts - t0:.6f}) vcan0 {hexid}#{payload.hex().upper()}\n")
            n += 1
    print(f"wrote {n} frames -> {args.log}   (replay: canplayer < {args.log})")


if __name__ == "__main__":
    main()
