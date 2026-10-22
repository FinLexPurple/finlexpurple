"""Named stage-agent registry and direct invocation (Phase 18; §13, §14).

Every pipeline stage is exposed as a named, independently invocable agent — for
transparency (a report can say which agent found what) and cost control (run one
capability instead of the whole pipeline). The registry is deliberately generic
so the Phase 19 financial agents register into the same file alongside these
stage agents.
"""
