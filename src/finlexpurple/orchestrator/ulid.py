"""A small, dependency-free ULID generator for run ids (Unit 1.2).

A ULID is a 128-bit identifier — a 48-bit millisecond timestamp followed by 80
bits of randomness — rendered as 26 Crockford base32 characters. It is used for
the unique, time-ordered tail of a run id because it is:

* **time-ordered and lexically sortable** — the timestamp is the high bits, so
  string sort == creation order (what the old timestamp tail gave us), and
* **globally unique** — 80 random bits mean two machines or CI runners never
  collide, even on the same target in the same millisecond (what the old
  ``timestamp[-NN]`` tail could *not* guarantee once results meet in one
  account).

Rendered characters are filesystem-safe and the Crockford alphabet omits
``I``/``L``/``O``/``U``. ``now_ms`` and ``randomness`` are injectable so tests
can assert ordering and exact encodings deterministically.
"""

from __future__ import annotations

import os
import time

# Crockford base32 (no I, L, O, U). 26 of these encode the full 128 bits.
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ULID_LEN = 26
_TIMESTAMP_BITS = 48
_MAX_TIMESTAMP = (1 << _TIMESTAMP_BITS) - 1


def new_ulid(*, now_ms: int | None = None, randomness: bytes | None = None) -> str:
    """Return a new 26-character ULID string.

    ``now_ms`` defaults to the current UNIX time in milliseconds; ``randomness``
    defaults to 10 fresh cryptographic random bytes (80 bits). Raises
    ``ValueError`` for a timestamp outside the 48-bit range or randomness that is
    not exactly 10 bytes.
    """

    timestamp = int(time.time() * 1000) if now_ms is None else int(now_ms)
    if timestamp < 0 or timestamp > _MAX_TIMESTAMP:
        raise ValueError("ULID timestamp is out of the 48-bit range.")
    rand = os.urandom(10) if randomness is None else randomness
    if len(rand) != 10:
        raise ValueError("ULID randomness must be exactly 10 bytes (80 bits).")

    value = (timestamp << 80) | int.from_bytes(rand, "big")
    # 26 base32 chars * 5 bits = 130 bits; the top char carries the high 3 bits
    # of the 128-bit value, so the leading character is always 0-7.
    return "".join(_CROCKFORD[(value >> (5 * (_ULID_LEN - 1 - i))) & 0x1F] for i in range(_ULID_LEN))


_DECODE = {char: index for index, char in enumerate(_CROCKFORD)}


def ulid_timestamp_ms(ulid: str) -> int:
    """Return the 48-bit millisecond timestamp encoded in a ULID string.

    Used to recover an honest run-start time from a run id's ULID tail without
    storing a separate timestamp. Raises ``ValueError`` if ``ulid`` is not a
    valid 26-character Crockford-base32 ULID.
    """

    if len(ulid) != _ULID_LEN:
        raise ValueError("A ULID is exactly 26 characters.")
    value = 0
    for char in ulid.upper():
        try:
            value = (value << 5) | _DECODE[char]
        except KeyError:
            raise ValueError(f"Invalid ULID character: {char!r}.") from None
    return value >> 80  # drop the 80 randomness bits, keep the 48-bit timestamp
