"""Frozen entry point for the Fily desktop backend sidecar."""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from typing import List, Optional

from fily.cli import main


def _parent_pid(arguments: List[str]) -> Optional[int]:
    try:
        index = arguments.index("--parent-pid")
        value = int(arguments[index + 1])
    except (ValueError, IndexError):
        return None
    del arguments[index : index + 2]
    return value


def _parent_alive(pid: int) -> bool:
    if sys.platform == "win32":
        synchronize = 0x00100000
        wait_timeout = 0x00000102
        handle = ctypes.windll.kernel32.OpenProcess(synchronize, False, pid)
        if not handle:
            return False
        try:
            return ctypes.windll.kernel32.WaitForSingleObject(handle, 0) == wait_timeout
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _watch_parent(pid: int) -> None:
    while _parent_alive(pid):
        time.sleep(1)
    os._exit(0)


if __name__ == "__main__":
    parent_pid = _parent_pid(sys.argv)
    if parent_pid is not None:
        threading.Thread(target=_watch_parent, args=(parent_pid,), daemon=True).start()
    raise SystemExit(main())
