"""Verify that a packaged FAP still carries its application icon.

The release FAP is rewritten by objcopy in check_symbol_gate.optimize_fap_exports,
so checking the source PNG is not enough: this inspects the shipped artifact.
It dumps the .fapmeta section, locates the application manifest, and asserts the
manifest's has_icon flag and icon payload survived packaging.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

import check_symbol_gate

MANIFEST_MAGIC = b"\x48\x44\x47\x52"  # 0x52474448, little endian
MANIFEST_SECTION = ".fapmeta"
NAME_FIELD_SIZE = 32
ICON_FIELD_SIZE = 32
DEFAULT_NAME_PREFIX = "ZeroFIDO"


def dump_section(objcopy: str, fap_path: Path, section: str, destination: Path) -> bytes:
    """Extract one ELF section from the FAP into destination and return its bytes."""
    subprocess.run(
        [objcopy, f"--dump-section={section}={destination}", str(fap_path)],
        check=True,
    )
    if not destination.exists():
        raise RuntimeError(f"{fap_path} has no {section} section")
    return destination.read_bytes()


def parse_manifest_icon(data: bytes, name_prefix: str) -> tuple[str, int, bytes]:
    """Return (app name, has_icon flag, icon payload) from a .fapmeta blob."""
    start = data.find(MANIFEST_MAGIC)
    if start < 0:
        raise ValueError(f"no FAP manifest magic in {MANIFEST_SECTION}")
    body = data[start:]

    name_offset = body.find(name_prefix.encode("ascii"))
    if name_offset < 0:
        raise ValueError(f"manifest name field does not start with {name_prefix!r}")

    name_field = body[name_offset : name_offset + NAME_FIELD_SIZE]
    name = name_field.split(b"\x00", 1)[0].decode("ascii", errors="replace")

    icon_offset = name_offset + NAME_FIELD_SIZE
    if icon_offset + 1 + ICON_FIELD_SIZE > len(body):
        raise ValueError("manifest is truncated before the icon field")

    has_icon = body[icon_offset]
    icon = body[icon_offset + 1 : icon_offset + 1 + ICON_FIELD_SIZE]
    return name, has_icon, icon


def check_fap_icon(fap_path: Path, *, name_prefix: str) -> int:
    """Fail when the packaged FAP lost its icon during release packaging."""
    if not fap_path.exists():
        print(f"missing {fap_path}")
        return 2

    try:
        objcopy = check_symbol_gate._find_tool(
            "arm-none-eabi-objcopy", "ARM_NONE_EABI_OBJCOPY"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            blob = dump_section(
                objcopy, fap_path, MANIFEST_SECTION, Path(temp_dir) / "fapmeta.bin"
            )
        name, has_icon, icon = parse_manifest_icon(blob, name_prefix)
    except (FileNotFoundError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"FAP icon gate failed: {exc}")
        return 2

    violations: list[str] = []
    if not has_icon:
        violations.append("manifest has_icon flag is 0 - fap_icon was dropped at build time")
    if not any(icon):
        violations.append("manifest icon payload is empty")

    if violations:
        print("FAP icon gate failed")
        for violation in violations:
            print(f"  - {violation}")
        return 1

    print("FAP icon gate passed")
    print(f"checked {fap_path}")
    print(f"app name: {name}")
    print(f"has_icon: {has_icon}")
    print(f"icon payload: {icon.hex()}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse icon gate options without touching the filesystem."""
    parser = argparse.ArgumentParser(description="Check that a packaged FAP carries its icon")
    parser.add_argument("--fap", type=Path, required=True, help="packaged .fap to inspect")
    parser.add_argument(
        "--name-prefix",
        default=DEFAULT_NAME_PREFIX,
        help="expected start of the manifest app name field",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point used by CI and manual release packaging."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    return check_fap_icon(args.fap, name_prefix=args.name_prefix)


if __name__ == "__main__":
    raise SystemExit(main())
