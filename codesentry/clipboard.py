# clipboard.py
# Copy text to the system clipboard without extra packages.

import base64
import os
import shutil
import subprocess
import sys


class ClipboardError(Exception):
    pass


def _copy_windows(text: str) -> None:
    import ctypes
    from ctypes import wintypes
    k, u = ctypes.windll.kernel32, ctypes.windll.user32
    k.GlobalAlloc.restype = wintypes.HGLOBAL
    k.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    k.GlobalLock.restype = ctypes.c_void_p
    k.GlobalLock.argtypes = [wintypes.HGLOBAL]
    k.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    u.OpenClipboard.argtypes = [wintypes.HWND]
    u.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    data = (text + "\0").encode("utf-16le")
    handle = k.GlobalAlloc(0x0002, len(data))               # GMEM_MOVEABLE
    if not handle:
        raise OSError("out of memory")
    ptr = k.GlobalLock(handle)
    ctypes.memmove(ptr, data, len(data))
    k.GlobalUnlock(handle)
    if not u.OpenClipboard(None):
        raise OSError("the clipboard is busy")
    try:
        u.EmptyClipboard()
        if not u.SetClipboardData(13, handle):              # CF_UNICODETEXT
            raise OSError("could not set the clipboard")
    finally:
        u.CloseClipboard()


def _copy_with_tool(text: str) -> bool:
    for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode("utf-8"), check=True, timeout=10,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except (OSError, subprocess.SubprocessError):
                continue
    return False


def copy_text(text: str) -> None:
    """Put `text` on the clipboard or raise ClipboardError."""
    try:
        if os.name == "nt":
            _copy_windows(text)
            return
        if _copy_with_tool(text):
            return
    except OSError as exc:
        raise ClipboardError(str(exc)) from exc
    if sys.stdout.isatty() and len(text) <= 70_000:           # terminal escape: works over SSH too
        sys.stdout.write("\033]52;c;" + base64.b64encode(text.encode("utf-8")).decode("ascii") + "\a")
        sys.stdout.flush()
        return
    raise ClipboardError("no clipboard tool found (install xclip, xsel or wl-clipboard)")
