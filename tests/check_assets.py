#!/usr/bin/env python3
"""Fast, dependency-free checks for data shipped in the FAP assets."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "files"
IDENTIFIER = re.compile(r"^[0-9A-Fa-f]{16}$")


def fail(message: str) -> None:
    print(f"asset check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_amiibo_ids() -> set[str]:
    asset = FILES / "amiibo.dat"
    if not asset.is_file():
        fail("missing files/amiibo.dat")

    entries: set[str] = set()
    for number, line in enumerate(asset.read_text(encoding="utf-8").splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        identifier = line.split(":", 1)[0].strip()
        if identifier in {"Filetype", "Version", "AmiiboCount"}:
            continue
        if not IDENTIFIER.fullmatch(identifier):
            fail(f"amiibo.dat:{number} has invalid identifier {identifier!r}")
        entries.add(identifier.lower())
    if not entries:
        fail("amiibo.dat contains no entries")
    return entries


def validate_switch2_assets(amiibo_ids: set[str]) -> None:
    games = FILES / "game_switch2.dat"
    mapping = FILES / "game_switch2_mapping.dat"
    for path in (games, mapping):
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"missing or empty {path.relative_to(ROOT)}")

    game_names = {
        line.strip()
        for line in games.read_text(encoding="utf-8").splitlines()
        if line and ":" not in line
    }
    mapping_names: set[str] = set()
    for number, line in enumerate(mapping.read_text(encoding="utf-8").splitlines(), start=1):
        if ":" not in line or line.startswith(("Filetype:", "Version:", "Console:", "GameCount:")):
            continue
        name, identifiers = line.split(":", 1)
        mapping_names.add(name.strip())
        for identifier in identifiers.split("|"):
            identifier = identifier.strip().lower()
            if not IDENTIFIER.fullmatch(identifier):
                fail(f"game_switch2_mapping.dat:{number} has invalid identifier {identifier!r}")
            if identifier not in amiibo_ids:
                fail(f"game_switch2_mapping.dat:{number} references unknown identifier {identifier}")
    if game_names != mapping_names:
        fail("Switch 2 game list and mapping names differ")


if __name__ == "__main__":
    validate_switch2_assets(validate_amiibo_ids())
    print("asset checks passed")
