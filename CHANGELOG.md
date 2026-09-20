# Changelog

## [0.9.3] - 2026-09-20

- **P12 — Explicit x64/x32 debugger selection.** `start_session` and
  `connect_to_session` gain an `arch='x64'|'x32'|''` parameter (default `auto`).
  Resolution order for the `x96dbg.exe` launcher: explicit `arch` param >
  `X64DBG_ARCH` environment variable > target executable's PE bitness (`auto`
  with a target) > loud error. The previous silent 64-bit default when no
  target was given is gone — an unresolvable launcher request now raises a
  `ValueError` naming `X64DBG_ARCH` instead of guessing. Replies now echo the
  resolved bitness (`Session started with x32dbg.exe (x32). ...` /
  `Connected to session PID ... (x64). ...`). Non-launcher paths
  (`x64dbg.exe` / `x32dbg.exe`) still pass through unchanged.

## [0.9.2] - 2026-09-16

- P1–P11 (see `X64DBG_MCP_IMPROVEMENT_PLAN.md` in the enigma_unpack repo):
  5-second wait cap server-side, `enumerate_windows` text-only stage
  classification, hardware BP size + verify-after-set, HW BP conditions/
  commands/logs, `run_until`, doc/help fixes, stretch HW-slot sampling,
  `load_executable` stop-at-entry, structured error returns for no-debuggee
  states, hardware-BP size validation, `eval_sync` stale-while-running guard.