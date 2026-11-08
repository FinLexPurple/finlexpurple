"""Terminal-UI building blocks for FinLexPurple's interactive surfaces.

This package holds the brand palette and (later) the interactive ``chat`` REPL. The
palette here is intentionally **dependency-free** — it is used by the always-on brand
banner on every invocation, so it must not pull in a heavier rendering library. The
richer chat UI adds its own dependencies, imported only by the ``chat`` command.
"""
