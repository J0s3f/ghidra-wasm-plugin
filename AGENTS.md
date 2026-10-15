# Agent instructions (Ghidra-WASM)

Standing rules for agents working in this repository or on this machine.

## Window control and screenshots: virtual machine only

All tests that involve **window control** (driving GUI windows: clicking, focusing, keyboard
injection) or **screenshots** (capturing the desktop or application windows) must be run inside a
**virtual machine** - never on the host's live desktop. This covers GUI-driven Ghidra checks and
any computer-use or screenshot-based verification.

Everything else in this repository's harness is headless (Ghidra `analyzeHeadless`, the emulator
harness, the probe/semantic gates) and may run directly on the host.

## Working conventions

The task prompt you were given defines your worktree, branch, pinned Ghidra install and the exact
verification commands; follow it. In short, for this repository:

- Build and test only against your own pinned Ghidra install (recorded in
  `test-scripts/.ghidra-install`); never modify the shared/live install
  (`C:\Tools\ghidra_12.1.4_PUBLIC` on the integrator's machine).
- Commit on your own branch only. Do not push, do not merge, do not rebase.
- Reports stay off `main` (they are archived on the `archive/reports` branch).
- Keep your worktree clean: no debug scripts, no stray files, no committed build outputs; scratch
  belongs under `%TEMP%`.
- Never bare-run binaryen `wasm-dis` (timeout-guarded only). Keep accepting spec-invalid modules
  (warnings are fine, new hard rejections are not).
