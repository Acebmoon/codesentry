# test_term_input.py
import os
import sys

import pytest

from codesentry import term_input as ti
from codesentry.menu_ui import run_menu


def test_parse_mouse_reports():
    assert ti.parse_mouse("\x1b[<0;12;5M") == (0, 12, 5, True)
    assert ti.parse_mouse("\x1b[<0;12;5m") == (0, 12, 5, False)
    assert ti.parse_mouse("\x1b[<65;1;1M") == (65, 1, 1, True)
    assert ti.parse_mouse("\x1b[A") is None


def test_click_on_a_line_or_a_button_gives_its_command():
    hot = {4: [(1, 14, "1")], 9: [(1, 6, "n"), (9, 14, "p")]}
    assert ti.decide(0, 3, 4, True, hot, False, False) == "1"
    assert ti.decide(0, 10, 9, True, hot, False, False) == "p"
    assert ti.decide(0, 7, 9, True, hot, False, False) is None      # between the buttons
    assert ti.decide(0, 3, 4, False, hot, False, False) is None     # release is not a click
    assert ti.decide(2, 3, 4, True, hot, False, False) is None      # right button


def test_wheel_changes_pages_only_where_allowed():
    assert ti.decide(64, 1, 1, True, {}, True, False) == "p"
    assert ti.decide(65, 1, 1, True, {}, True, False) == "n"
    assert ti.decide(65, 1, 1, True, {}, False, False) is None


def test_any_click_goes_back_on_message_screens():
    assert ti.decide(0, 30, 7, True, {}, False, True) == ""


class FakeMouse:
    """Answers the menu's choose() calls from a script, like clicks and key presses would."""

    def __init__(self, answers):
        self.answers, self.calls = iter(answers), []

    def choose(self, prompt, hot, wheel=False, any_click=False):
        self.calls.append((prompt, dict(hot), wheel, any_click))
        return next(self.answers)


def test_menu_registers_clickable_lines_and_reads_choices_from_the_mouse(tmp_path):
    src = tmp_path / "a.py"
    src.write_text("x = 1\n")
    mouse = FakeMouse(["7"])
    typed = iter([])
    run_menu(lambda p="": next(typed), lambda s: None, mouse=mouse)
    prompt, hot, wheel, _ = mouse.calls[0]
    assert prompt == "[+] Option: "
    cmds = sorted(c for segs in hot.values() for _, _, c in segs)
    assert cmds == ["1", "2", "3", "4", "5", "6", "7"]
    rows = sorted(hot)
    assert rows == list(range(rows[0], rows[0] + 7))                  # seven consecutive lines


def test_results_screen_buttons_and_wheel(tmp_path):
    src = tmp_path / "a.py"
    src.write_text('password = "hunter2hunter2"\n')
    # menu: 1 (scan), then in results: wheel down ('n'), 'b' back, menu: 7 exit
    mouse = FakeMouse(["1", "n", "b", "7"])
    typed = iter([str(src)])
    run_menu(lambda p="": next(typed), lambda s: None, mouse=mouse)
    results = [c for c in mouse.calls if c[0] == "[+] Command: "]
    assert results and results[0][2] is True                          # wheel allowed here
    footer = [seg for segs in results[0][1].values() for seg in segs]
    assert {c for _, _, c in footer} == {"n", "p", "h", "m", "l", "a", "c", "r", "s", "b"}


@pytest.mark.skipif(os.name == "nt", reason="uses a pseudo-terminal")
def test_real_terminal_reads_keys_and_clicks():
    import pty
    import subprocess
    import time
    code = ("from codesentry.term_input import Mouse\n"
            "m = Mouse()\n"
            "hot = {3: [(1, 10, 'x')]}\n"
            "print('GOT', repr(m.choose('? ', hot)), repr(m.choose('? ', hot)), repr(m.choose('? ', hot)))\n")
    master, slave = pty.openpty()
    proc = subprocess.Popen([sys.executable, "-c", code], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    out = b""

    def wait_for(marker, start):
        nonlocal out
        deadline = time.time() + 20
        while time.time() < deadline and out.count(marker) <= start:
            try:
                out += os.read(master, 4096)
            except OSError:
                break

    wait_for(b"\x1b[?1000h", 0)               # the first prompt is up and the mouse is on
    os.write(master, b"Q")                      # a key
    wait_for(b"\x1b[?1000h", 1)
    os.write(master, b"\x1b[<0;4;3M")           # a click on the hot line
    wait_for(b"\x1b[?1000h", 2)
    os.write(master, b"\r")                     # Enter
    proc.wait(timeout=20)
    import select
    while select.select([master], [], [], 0.5)[0]:           # whatever is left after the child exits
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    assert b"GOT 'q' 'x' ''" in out
