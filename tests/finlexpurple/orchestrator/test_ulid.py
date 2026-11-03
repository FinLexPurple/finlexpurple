"""Unit 1.2: the dependency-free ULID generator for run-id tails.

Proves the two properties run ids rely on: time-ordering (lexical sort ==
creation order) and global uniqueness (80 random bits, no collision across
runners), plus the Crockford encoding and input guards.
"""

from __future__ import annotations

import pytest

from finlexpurple.orchestrator.ulid import new_ulid

_CROCKFORD = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")


def test_ulid_is_26_crockford_chars() -> None:
    ulid = new_ulid()
    assert len(ulid) == 26
    assert set(ulid) <= _CROCKFORD  # no I, L, O, U; filesystem-safe


def test_ulid_is_time_ordered_lexically() -> None:
    earlier = new_ulid(now_ms=1_000_000, randomness=b"\x00" * 10)
    later = new_ulid(now_ms=2_000_000, randomness=b"\x00" * 10)
    assert earlier < later  # the timestamp is the high bits -> sort == order


def test_ulid_is_unique_across_calls_at_the_same_instant() -> None:
    now = 1_700_000_000_000
    ids = {new_ulid(now_ms=now) for _ in range(500)}
    assert len(ids) == 500  # 80 random bits -> no collision in a batch


def test_ulid_is_deterministic_given_timestamp_and_randomness() -> None:
    a = new_ulid(now_ms=1_700_000_000_000, randomness=b"\x01" * 10)
    b = new_ulid(now_ms=1_700_000_000_000, randomness=b"\x01" * 10)
    assert a == b


def test_ulid_rejects_bad_inputs() -> None:
    with pytest.raises(ValueError):
        new_ulid(now_ms=-1)
    with pytest.raises(ValueError):
        new_ulid(now_ms=1 << 48)  # out of the 48-bit range
    with pytest.raises(ValueError):
        new_ulid(randomness=b"\x00" * 9)  # must be exactly 10 bytes
