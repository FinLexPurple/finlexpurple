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

The Phase 5 crawler was manually verified on Linux/WSL against the local
two-server demo site only. Windows and macOS rely on the automated CI matrix;
the crawler has not been manually verified on those platforms. No real-world
site was tested.

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

Live hardware detection currently reads RAM with `os.sysconf` on Linux and
macOS, replacing it with `sysctlbyname("hw.memsize")` for Apple Silicon; on
Windows it uses `GlobalMemoryStatusEx`. GPU/VRAM detection currently uses
`nvidia-smi` on Linux and Windows. The ROCm, `system_profiler`, and Windows
video-controller parsers are tested against synthetic fixtures only and are
not wired into live detection. Apple unified memory is read through `sysctl`,
not the `system_profiler` parser.

The optional `Optional live provider smoke` workflow makes one small request
only when manually dispatched with a provider whose repository secret is
configured. It skips cleanly when that provider key is absent and never
prints the key or response text.

## Manual recon scope check

In one terminal, start the controlled two-server test site:

```sh
python scripts/recon_demo_site.py
```

It prints the in-scope URL and starts an out-of-scope redirect canary on a
different port. In a second terminal, run the URL shown by the first command:

```sh
finlexpurple scan --target http://127.0.0.1:8765/
```

Confirm the target when prompted. The catalog should list the root, `/about`,
`/search`, `/private`, `/redirect`, and a `POST /submit` form entry. The form
must not be submitted. The default run records `/private` from robots.txt but
still fetches it. Repeat with `--respect-robots`; `/private` should then be
absent from the catalog. In the first terminal, `OUT_OF_SCOPE_REQUEST` must
never appear in either run. Query values such as `demo-secret` must not appear
in CLI output or application logs. Stop the servers with Ctrl+C.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
