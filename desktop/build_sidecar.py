"""Build the Fily Python backend as a Tauri sidecar for the current host."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TAURI_BINARIES = ROOT / "frontend" / "src-tauri" / "binaries"
BUILD_ROOT = ROOT / ".desktop-build"


def main() -> int:
    target = subprocess.run(
        ["rustc", "--print", "host-tuple"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not target:
        raise RuntimeError("rustc did not report a host target triple")

    extension = ".exe" if sys.platform == "win32" else ""
    raw_name = "fily-backend%s" % extension
    destination = TAURI_BINARIES / ("fily-backend-%s%s" % (target, extension))
    TAURI_BINARIES.mkdir(parents=True, exist_ok=True)
    BUILD_ROOT.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            "--onefile",
            "--name",
            "fily-backend",
            "--distpath",
            str(BUILD_ROOT / "dist"),
            "--workpath",
            str(BUILD_ROOT / "work"),
            "--specpath",
            str(BUILD_ROOT),
            str(ROOT / "desktop" / "backend_main.py"),
        ],
        cwd=str(ROOT),
        check=True,
    )
    shutil.copy2(BUILD_ROOT / "dist" / raw_name, destination)
    destination.chmod(0o755)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
