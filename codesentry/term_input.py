# term_input.py
# Single-key and mouse input for the menu (clicks on menu lines and buttons, wheel to
# change page). Standard library only: termios on Linux/macOS, msvcrt + the console's
# virtual-terminal input mode on Windows. Anything that fails turns the mouse off and
# the menu keeps working with the keyboard (type, then Enter).

import os
import re
import sys
from typing import Dict, List, Optional, Tuple

Hot = Dict[int, List[Tuple[int, int, str]]]      # screen row -> [(first col, last col, command)]

_ON, _OFF = "\033[?1000h\033[?1006h", "\033[?1000l\033[?1006l"
_SGR = re.compile(r"\x1b\[<(\d+);(\d+);(\d+)([Mm])")


def parse_mouse(seq: str) -> Optional[Tuple[int, int, int, bool]]:
    """'\\x1b[<0;12;5M' -> (button, col, row, pressed). None if it is not a mouse report."""
    m = _SGR.fullmatch(seq)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4) == "M"


def decide(button: int, col: int, row: int, pressed: bool, hot: Hot,
           wheel: bool, any_click: bool) -> Optional[str]:
    """What a mouse report means: the command under a left click, or p/n for the wheel."""
    if pressed and button == 64 and wheel:
        return "p"
    if pressed and button == 65 and wheel:
        return "n"
    if pressed and button == 0:
        for first, last, cmd in hot.get(row, ()):
            if first <= col <= last:
                return cmd
        if any_click and not hot:
            return ""
    return None


class _Reader:
    """Reads one character at a time, no Enter needed."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getch(self) -> str:
        raise NotImplementedError

    def ready(self, timeout: float = 0.05) -> bool:
        """Is another character already waiting? (A lone Esc has nothing after it.)"""
        raise NotImplementedError


class _PosixReader(_Reader):
    def __enter__(self):
        import termios
        import tty
        self._fd = sys.stdin.fileno()
        self._old = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)
        return self

    def __exit__(self, *exc):
        import termios
        termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
        return False

    def ready(self, timeout: float = 0.05) -> bool:
        import select
        return bool(select.select([self._fd], [], [], timeout)[0])

    def getch(self) -> str:
        data = os.read(self._fd, 1)
        if data and data[0] >= 0xC0:                       # first byte of a multi-byte character
            need = 1 if data[0] < 0xE0 else 2 if data[0] < 0xF0 else 3
            for _ in range(need):
                data += os.read(self._fd, 1)
        return data.decode("utf-8", errors="replace") if data else ""


class _WindowsReader(_Reader):
    def __enter__(self):
        import ctypes
        self._k = ctypes.windll.kernel32
        self._h = self._k.GetStdHandle(-10)
        mode = ctypes.c_uint32()
        if not self._k.GetConsoleMode(self._h, ctypes.byref(mode)):
            raise OSError("no console")
        self._old = mode.value
        # + ENABLE_VIRTUAL_TERMINAL_INPUT (0x200); - line input (2), echo (4)
        if not self._k.SetConsoleMode(self._h, (mode.value | 0x0200) & ~0x0006):
            raise OSError("console does not support virtual terminal input")
        return self

    def __exit__(self, *exc):
        self._k.SetConsoleMode(self._h, self._old)
        return False

    def ready(self, timeout: float = 0.05) -> bool:
        import msvcrt
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if msvcrt.kbhit():
                return True
            time.sleep(0.005)
        return bool(msvcrt.kbhit())

    def getch(self) -> str:
        import msvcrt
        return msvcrt.getwch()


class Mouse:
    """choose() waits for one key or one click and returns the command it stands for."""

    def __init__(self):
        self.enabled = sys.stdin.isatty() and sys.stdout.isatty()

    def _reader(self) -> _Reader:
        return _WindowsReader() if os.name == "nt" else _PosixReader()

    def choose(self, prompt: str, hot: Hot, wheel: bool = False, any_click: bool = False) -> Optional[str]:
        """The command, "" for Enter, or None if raw input is not available (use input())."""
        if not self.enabled:
            return None
        try:
            with self._reader() as rd:
                sys.stdout.write(prompt + _ON)
                sys.stdout.flush()
                try:
                    return self._loop(rd, hot, wheel, any_click)
                finally:
                    sys.stdout.write(_OFF + "\n")
                    sys.stdout.flush()
        except (OSError, ImportError, AttributeError, ValueError):
            self.enabled = False            # fall back to typing for the rest of the session
            return None

    def _loop(self, rd: _Reader, hot: Hot, wheel: bool, any_click: bool) -> str:
        while True:
            ch = rd.getch()
            if ch in ("\x03", "\x04", "\x1a", ""):
                raise KeyboardInterrupt
            if ch in ("\r", "\n"):
                return ""
            if ch == "\x1b":
                if not rd.ready():
                    return "b"               # a lone Esc goes back
                seq = ch
                while True:                  # read the rest of a report: ESC [ < b ; x ; y M|m
                    nxt = rd.getch()
                    seq += nxt
                    if nxt in ("M", "m") or len(seq) > 24 or not nxt:
                        break
                    if len(seq) == 2 and nxt != "[":
                        break
                mouse = parse_mouse(seq)
                if mouse:
                    cmd = decide(*mouse, hot, wheel, any_click)
                    if cmd is not None:
                        return cmd
                continue
            if ch.isprintable() and not ch.isspace():
                return ch.lower()
