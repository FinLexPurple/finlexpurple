"""Small parsers for native GPU command output, separated for fixture testing."""

from __future__ import annotations

import csv
import io
import re

_GIB = 1024**3
_MIB = 1024**2


def parse_nvidia_smi(output: str) -> tuple[str, float] | None:
    """Parse CSV from nvidia-smi's name,memory.total query."""

    rows: list[tuple[str, float]] = []
    for row in csv.reader(io.StringIO(output)):
        if len(row) != 2 or not row[0].strip():
            continue
        try:
            rows.append((row[0].strip(), float(row[1].strip()) * _MIB / _GIB))
        except ValueError:
            continue
    return max(rows, key=lambda item: item[1], default=None)


def parse_rocm_smi(output: str) -> tuple[str, float] | None:
    """Parse key/value rows from the ROCm SMI human-readable report."""

    name = None
    memory_bytes = None
    for line in output.splitlines():
        if "Card series:" in line:
            name = line.split("Card series:", 1)[1].strip()
        elif "VRAM Total Memory (B):" in line:
            value = line.split("VRAM Total Memory (B):", 1)[1].strip()
            try:
                memory_bytes = int(value)
            except ValueError:
                pass
    if name and memory_bytes and memory_bytes > 0:
        return name, memory_bytes / _GIB
    return None


def parse_system_profiler(output: str) -> tuple[str, float] | None:
    """Parse a display section containing the GPU model and unified memory."""

    name_match = re.search(r"^\s*Chipset Model:\s*(.+?)\s*$", output, re.MULTILINE)
    memory_match = re.search(r"^\s*Memory:\s*([0-9.]+)\s*(GB|MB)\s*$", output, re.MULTILINE)
    if not name_match or not memory_match:
        return None
    memory = float(memory_match.group(1))
    if memory_match.group(2) == "MB":
        memory /= 1024
    return name_match.group(1), memory


def parse_windows_video_controller_csv(output: str) -> tuple[str, float] | None:
    """Parse CSV from a Windows Win32_VideoController query."""

    reader = csv.DictReader(io.StringIO(output))
    rows: list[tuple[str, float]] = []
    for row in reader:
        name = (row.get("Name") or "").strip()
        try:
            memory = int(row.get("AdapterRAM") or "") / _GIB
        except ValueError:
            continue
        if name and memory > 0:
            rows.append((name, memory))
    return max(rows, key=lambda item: item[1], default=None)
