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

## License

Apache License 2.0 — see [LICENSE](LICENSE).
