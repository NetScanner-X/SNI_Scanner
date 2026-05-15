"""Dependency checker for SNI Scanner.
Installs requirements only when a package is missing.
"""
from __future__ import annotations

import importlib.metadata as metadata
import re
import subprocess
import sys
from pathlib import Path

REQ_FILE = Path(__file__).with_name("requirements.txt")

# Some PyPI package names differ from import names, but metadata uses PyPI names.
# This checker intentionally uses package metadata, not imports.


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirement_name(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Strip inline comments and environment markers/extras/version specifiers.
    line = line.split("#", 1)[0].strip()
    line = line.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)", line)
    return match.group(1) if match else None


def _installed_packages() -> set[str]:
    return {_normalize_name(dist.metadata.get("Name", dist.metadata["Name"])) for dist in metadata.distributions()}


def main() -> int:
    if not REQ_FILE.exists():
        print("[WARN] requirements.txt not found, skipping dependency check.")
        return 0

    required = []
    for line in REQ_FILE.read_text(encoding="utf-8").splitlines():
        name = _parse_requirement_name(line)
        if name:
            required.append(name)

    installed = _installed_packages()
    missing = [name for name in required if _normalize_name(name) not in installed]

    if not missing:
        print("[INFO] Requirements already installed. Skipping install.")
        return 0

    print("[INFO] Missing packages: " + ", ".join(missing))
    print("[INFO] Installing requirements (first run / missing packages only)...")
    cmd = [sys.executable, "-m", "pip", "install", "-r", str(REQ_FILE), "--quiet"]
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("[WARN] Some packages failed to install. Continuing...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
