"""Cross-platform host hardware and Ollama model-directory detection."""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from finlexpurple.hardware.parsers import parse_nvidia_smi

_GIB = 1024**3


@dataclass(frozen=True)
class HardwareFacts:
    """Hardware information used by tier recommendation and setup display."""

    total_ram_gb: float
    model_directory: Path
    disk_checked_path: Path
    free_disk_gb: float
    gpu_kind: str
    gpu_name: str | None
    gpu_memory_gb: float | None
    operating_system: str
    warnings: tuple[str, ...] = ()


def _windows_total_memory() -> int:
    """Return physical memory bytes using the Windows GlobalMemoryStatusEx API."""

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    windows_api = getattr(ctypes, "windll", None)
    if windows_api is None:
        raise OSError("GlobalMemoryStatusEx is unavailable")
    memory_status_ex = windows_api.kernel32.GlobalMemoryStatusEx
    memory_status_ex.argtypes = [ctypes.POINTER(MemoryStatus)]
    memory_status_ex.restype = ctypes.c_int
    if not memory_status_ex(ctypes.byref(status)):
        raise OSError("GlobalMemoryStatusEx failed")
    return int(status.ullTotalPhys)


def _apple_silicon_unified_memory() -> int:
    """Return Apple Silicon unified memory bytes through macOS sysctl."""

    value = ctypes.c_uint64()
    size = ctypes.c_size_t(ctypes.sizeof(value))
    sysctlbyname = ctypes.CDLL(None).sysctlbyname
    sysctlbyname.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    sysctlbyname.restype = ctypes.c_int
    result = sysctlbyname(
        b"hw.memsize", ctypes.byref(value), ctypes.byref(size), None, 0
    )
    if result != 0:
        raise OSError("sysctlbyname(hw.memsize) failed")
    return int(value.value)


def _total_memory_bytes(system: str) -> int:
    if sys.platform == "win32":
        return _windows_total_memory()
    if system == "Windows":
        return _windows_total_memory()
    page_size = os.sysconf("SC_PAGE_SIZE")
    physical_pages = os.sysconf("SC_PHYS_PAGES")
    return int(page_size * physical_pages)


def _operating_system_label() -> str:
    system = platform.system()
    if system == "Windows":
        get_windows_version = getattr(sys, "getwindowsversion", None)
        if get_windows_version is None:
            return "Windows (build unavailable)"
        version = get_windows_version()
        name = "Windows 11" if version.build >= 22000 else f"Windows {version.major}"
        return f"{name} (build {version.build})"
    return platform.platform()


def _model_directory() -> Path:
    configured = os.environ.get("OLLAMA_MODELS", "").strip()
    if configured:
        return Path(os.path.expandvars(configured)).expanduser()
    if platform.system() == "Windows":
        profile = os.environ.get("USERPROFILE")
        base = Path(profile).expanduser() if profile else Path.home()
        return base / ".ollama" / "models"
    return Path.home() / ".ollama" / "models"


def _existing_disk_path(model_directory: Path) -> Path:
    candidate = model_directory
    while not candidate.exists() or not candidate.is_dir():
        parent = candidate.parent
        if parent == candidate:
            raise OSError(f"no existing parent directory for {model_directory}")
        candidate = parent
    return candidate


def _probe_nvidia_gpu() -> tuple[tuple[str, float] | None, str | None]:
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total",
                "--format=csv,noheader,nounits",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except FileNotFoundError:
        return None, "nvidia-smi is unavailable; no NVIDIA GPU could be verified."
    except subprocess.TimeoutExpired:
        return None, "nvidia-smi timed out; no NVIDIA GPU could be verified."
    except (OSError, subprocess.SubprocessError):
        return None, "nvidia-smi failed; no NVIDIA GPU could be verified."
    if result.returncode != 0:
        return None, "nvidia-smi returned an error; no NVIDIA GPU could be verified."
    parsed = parse_nvidia_smi(result.stdout)
    if parsed is None:
        return None, "nvidia-smi returned no usable GPU facts; cloud is the safe recommendation."
    return parsed, None

def detect_hardware() -> HardwareFacts:
    """Detect system RAM, GPU memory, OS, and free space for Ollama models."""

    system = platform.system()
    warnings: list[str] = []
    try:
        total_memory = _total_memory_bytes(system)
    except (AttributeError, OSError, subprocess.SubprocessError):
        total_memory = 0
        warnings.append("System memory detection failed; cloud is the safe recommendation.")
    is_apple_silicon = system == "Darwin" and platform.machine().lower() in {
        "arm64",
        "aarch64",
    }

    gpu_kind = "none"
    gpu_name = None
    gpu_memory = None
    nvidia, nvidia_warning = _probe_nvidia_gpu()
    if nvidia_warning and system != "Darwin":
        warnings.append(nvidia_warning)
    if nvidia is not None:
        gpu_kind = "nvidia"
        gpu_name, gpu_memory = nvidia
    elif is_apple_silicon:
        try:
            total_memory = _apple_silicon_unified_memory()
        except (AttributeError, OSError):
            # Physical-memory detection above remains available if sysctl fails.
            pass
        gpu_kind = "apple_silicon"
        gpu_name = "Apple Silicon unified memory"
        gpu_memory = total_memory / _GIB

    model_directory = _model_directory()
    try:
        disk_checked_path = _existing_disk_path(model_directory)
        free_disk = shutil.disk_usage(disk_checked_path).free / _GIB
    except OSError:
        disk_checked_path = Path.cwd()
        free_disk = 0
        warnings.append("Disk space detection failed; cloud is the safe recommendation.")
    return HardwareFacts(
        total_ram_gb=total_memory / _GIB,
        model_directory=model_directory,
        disk_checked_path=disk_checked_path,
        free_disk_gb=free_disk,
        gpu_kind=gpu_kind,
        gpu_name=gpu_name,
        gpu_memory_gb=gpu_memory,
        operating_system=_operating_system_label(),
        warnings=tuple(warnings),
    )
