# Contributing

`johan-sdd` is contract-first. Changes to behavior start by updating the integration charter or a
versioned schema, then implement the smallest adapter behind that interface.

## Local workflow

1. Use Python 3.11 and `uv`.
2. Work in an isolated worktree for feature changes.
3. Do not edit another owner's files or shared resource claims.
4. Run the narrow test first, then `uv run --locked pytest`.
5. Supply a compact evidence packet with commands, exit codes, risks, and the next action.

Upstream output must remain intact. Local behavior belongs in presets, overlays, adapters, or
wrappers and must record the upstream revision and local delta. Do not commit credentials,
transcripts, host-specific absolute paths, or generated lifecycle state.

Commits, pushes, remote creation, releases, publication, and host-global application remain
separate authority gates.

