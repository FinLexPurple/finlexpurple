"""Parser tests using the explicitly synthetic command-output fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from finlexpurple.hardware.parsers import (
    parse_nvidia_smi,
    parse_rocm_smi,
    parse_system_profiler,
    parse_windows_video_controller_csv,
)


@pytest.mark.parametrize(
    ("fixture_name", "parser", "expected"),
    [
        ("nvidia-smi.synthetic.txt", parse_nvidia_smi, "NVIDIA L4"),
        ("rocm-smi.synthetic.txt", parse_rocm_smi, "AMD Radeon RX 7900 XTX"),
        ("system-profiler.synthetic.txt", parse_system_profiler, "Apple M3"),
        (
            "windows-video-controller.synthetic.csv",
            parse_windows_video_controller_csv,
            "Example GPU",
        ),
    ],
)
def test_hardware_output_fixture_parsers(fixture_name, parser, expected) -> None:
    fixture = Path(__file__).parents[2] / "fixtures" / "hardware" / fixture_name
    parsed = parser(fixture.read_text(encoding="utf-8"))

    assert parsed is not None
    assert parsed[0] == expected
    assert parsed[1] > 0
