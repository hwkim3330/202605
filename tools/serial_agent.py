#!/usr/bin/env python3
"""Bidirectional serial console agent.

Uses only Python stdlib termios so no pyserial dependency. Driven by NDJSON
on stdin/stdout: the first line on stdin is the open config; subsequent lines
are commands; stdout emits one JSON event per line.

Stdin commands:
    {"type":"tx","hex":"abcd..."}     — bytes to write to the TTY
    {"type":"break"}                   — send a serial break
    {"type":"setRts","value":true}     — RTS line state
    {"type":"setDtr","value":true}     — DTR line state
    {"type":"close"}                   — close and exit

Stdout events:
    {"type":"open","path":"/dev/ttyUSB0","baudRate":115200}
    {"type":"rx","hex":"...","len":N}
    {"type":"error","message":"..."}
    {"type":"closed"}
"""
from __future__ import annotations

import fcntl
import json
import os
import select
import struct
import sys
import termios
import threading


BAUDRATES = {
    300: termios.B300, 600: termios.B600, 1200: termios.B1200,
    2400: termios.B2400, 4800: termios.B4800, 9600: termios.B9600,
    19200: termios.B19200, 38400: termios.B38400, 57600: termios.B57600,
    115200: termios.B115200, 230400: termios.B230400, 460800: termios.B460800,
    500000: termios.B500000, 921600: termios.B921600,
    1000000: termios.B1000000, 1500000: termios.B1500000,
    2000000: termios.B2000000, 3000000: termios.B3000000,
    4000000: termios.B4000000,
}

TIOCMBIS = 0x5416
TIOCMBIC = 0x5417
TIOCM_RTS = 0x004
TIOCM_DTR = 0x002


def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def configure_tty(fd, baud_rate, data_bits, parity, stop_bits, hw_flow):
    attrs = termios.tcgetattr(fd)
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs

    # raw mode — no canonical, no echo, no signals
    iflag = 0
    oflag = 0
    lflag = 0

    cflag |= termios.CLOCAL | termios.CREAD
    cflag &= ~termios.CSIZE
    cflag |= {5: termios.CS5, 6: termios.CS6, 7: termios.CS7, 8: termios.CS8}[data_bits]
    if parity == "N":
        cflag &= ~termios.PARENB
    elif parity == "E":
        cflag |= termios.PARENB
        cflag &= ~termios.PARODD
    elif parity == "O":
        cflag |= termios.PARENB | termios.PARODD
    if stop_bits == 1:
        cflag &= ~termios.CSTOPB
    else:
        cflag |= termios.CSTOPB

    if hasattr(termios, "CRTSCTS"):
        if hw_flow:
            cflag |= termios.CRTSCTS
        else:
            cflag &= ~termios.CRTSCTS

    speed = BAUDRATES.get(int(baud_rate), termios.B115200)
    cc[termios.VMIN] = 0
    cc[termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, [iflag, oflag, cflag, lflag, speed, speed, cc])


def set_modem_line(fd, mask, value):
    op = TIOCMBIS if value else TIOCMBIC
    fcntl.ioctl(fd, op, struct.pack("I", mask))


def main() -> None:
    raw = sys.stdin.readline()
    if not raw.strip():
        emit({"type": "error", "message": "missing config"})
        return
    cfg = json.loads(raw)
    path = cfg["path"]
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as exc:
        emit({"type": "error", "message": f"open failed: {exc}"})
        return
    try:
        configure_tty(
            fd,
            cfg.get("baudRate", 115200),
            int(cfg.get("dataBits", 8)),
            cfg.get("parity", "N"),
            int(cfg.get("stopBits", 1)),
            bool(cfg.get("hwFlow", False)),
        )
    except Exception as exc:
        os.close(fd)
        emit({"type": "error", "message": f"configure failed: {exc}"})
        return

    emit({"type": "open", "path": path, "baudRate": int(cfg.get("baudRate", 115200))})

    stop_event = threading.Event()

    def reader():
        try:
            while not stop_event.is_set():
                r, _, _ = select.select([fd], [], [], 0.2)
                if not r:
                    continue
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    continue
                if data:
                    emit({"type": "rx", "hex": data.hex(), "len": len(data)})
        except Exception as exc:
            emit({"type": "error", "message": f"reader: {exc}"})

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = cmd.get("type")
            if kind == "tx":
                try:
                    data = bytes.fromhex(cmd.get("hex", ""))
                    if data:
                        os.write(fd, data)
                except (OSError, ValueError) as exc:
                    emit({"type": "error", "message": f"tx: {exc}"})
            elif kind == "break":
                try:
                    termios.tcsendbreak(fd, 0)
                except Exception as exc:
                    emit({"type": "error", "message": f"break: {exc}"})
            elif kind == "setRts":
                try:
                    set_modem_line(fd, TIOCM_RTS, bool(cmd.get("value")))
                except Exception as exc:
                    emit({"type": "error", "message": f"setRts: {exc}"})
            elif kind == "setDtr":
                try:
                    set_modem_line(fd, TIOCM_DTR, bool(cmd.get("value")))
                except Exception as exc:
                    emit({"type": "error", "message": f"setDtr: {exc}"})
            elif kind == "close":
                break
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        try:
            os.close(fd)
        except Exception:
            pass
        emit({"type": "closed"})


if __name__ == "__main__":
    main()
