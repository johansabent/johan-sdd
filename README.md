# johan-sdd

`johan-sdd` is a public, portable integration product for spec-driven delivery. It combines a
version-pinned delivery spine with host-neutral ownership, routing, evidence, and upgrade
contracts. The product emits desired state and previews; a separately authorized host owner
applies them.

The initial supported agents are Codex and Claude. The runtime requires Python 3.11 and is managed
with [`uv`](https://docs.astral.sh/uv/).

## Contract first

The decision-complete integration charter is available in
[`docs/integration-charter.md`](docs/integration-charter.md). Machine-readable contracts live in
`manifests/` and are validated against the schemas in `schemas/`.

The important invariants are:

- Spec Kit owns the medium/large delivery spine; adapters own the delivery envelope.
- A session derives exactly one lifecycle authority decision from cutover state. It never
  dual-writes or accepts a caller-selected authority override.
- Session ownership is per worktree, with explicit claims for shared resources.
- Capture generation and promotion are distinct actors.
- Host integration is desired-state driven; the product does not write directly to agent homes.
- Upgrades use immutable pins, a fixed trust root, canaries, and exact rollback.

## Development

```powershell
uv sync --dev
uv run --locked pytest
uv run --locked johan-sdd --version
```

No remote, release, package publication, or host integration is implied by the local scaffold.

## Upstreams

- [GitHub Spec Kit](https://github.com/github/spec-kit), pinned to `v0.16.3`.
- [Matt Pocock's skills](https://github.com/mattpocock/skills), pinned to `v1.2.3`.

Both upstreams are MIT licensed. Exact tag objects, peeled commits, sources, and attribution are
recorded in [`manifests/upstreams.lock.json`](manifests/upstreams.lock.json) and
[`docs/third-party-notices.md`](docs/third-party-notices.md).

## License

MIT. See [`LICENSE`](LICENSE).
