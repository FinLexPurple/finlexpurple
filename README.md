# FinLexPurple

Autonomous security testing agent — placeholder release to reserve the package name.

Full release coming soon.

## Platform verification

Hardware detection has been manually verified on Linux/WSL and Windows.
macOS has not been manually verified; Apple Silicon detection and unified
memory tier boundaries are covered by synthetic unit tests.

The local-8b-hybrid fallback wizard path and live provider calls have not
been manually verified. Provider behavior and fallback configuration are
covered by automated tests using synthetic hardware and mocked clients.

Phase 4 out-of-scope blocking is verified by unit tests only. There is no
scanner yet to exercise that enforcement end to end.

## Hardware diagnostics

Run `finlexpurple doctor` to print hardware facts. The command omits full
filesystem paths and does not display configuration values or API keys. For
a synthetic what-if report, pass a named profile, for example
`finlexpurple doctor --fake-hardware-profile apple-16gb`. The same explicit
override can exercise setup with
`finlexpurple setup --fake-hardware-profile apple-16gb`; it does not alter
hardware detection for normal runs. An unknown profile is rejected with the
available profile names. The setup command still runs the regular persistence
flow: it can create `.env`, and it asks before replacing existing selections.

The four hardware output fixtures under `tests/fixtures/hardware/` are
synthetic. This environment has no `nvidia-smi`, `rocm-smi`, or
`system_profiler`, and is not Windows; real samples are still needed from
NVIDIA, AMD/ROCm, Apple Silicon, and Windows machines. The normal CI matrix
also runs host detection and scripted setup directly against its real runner
hardware, without replacing the detector.

The optional `Optional live provider smoke` workflow makes one small request
only when manually dispatched with a provider whose repository secret is
configured. It skips cleanly when that provider key is absent and never
prints the key or response text.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
