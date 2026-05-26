# Publishing to crates.io + PyPI

This doc captures the publish order for the workspace's crates and the
Python defense library. Read this before running `cargo publish` or
`twine upload` against real registries.

## crates.io: workspace publish order

The workspace has internal `qorch-*` crates that depend on each other.
`cargo publish` must run in topological order, leaves first. Each crate
fails `--dry-run` until its `qorch-*` dependencies are actually live on
crates.io.

```
1. qorch-domain                     ← no internal deps
2. qorch-application                ← depends on domain
3. qorch-adapters                   ← depends on domain + application
4. qorch-safety-kernel-client       ← depends on application + adapters
5. qorch-transparency-store         ← depends on domain
6. qorch-safety-kernel-middleware   ← depends on domain + safety-kernel-client
7. qorch-transparency-log           ← depends on domain + adapters + transparency-store
8. qorch-safety-kernel              ← depends on domain + application + adapters
9. qorch-safety-kernel-reconciler   ← depends on domain + safety-kernel-client
```

After each step, wait ~1 minute for crates.io's index to propagate before
running the next.

### Per-step recipe

```bash
# Step 1: publish qorch-domain
cargo publish --dry-run -p qorch-domain
# (verify clean output)
cargo publish -p qorch-domain

# Wait ~60s for index propagation, then:
cargo publish --dry-run -p qorch-application
cargo publish -p qorch-application

# ...continue for each crate in order above.
```

### Verifying readiness before any publish

```bash
# Workspace builds
cargo check --workspace

# Dry-run on the leaf (no crates.io dep) — must pass
cargo publish --dry-run -p qorch-domain --allow-dirty

# Format clean
cargo fmt --all -- --check

# Clippy clean (warnings are non-blocking)
cargo clippy --workspace --all-targets -- -W warnings
```

## PyPI: py-defense publish

The `py-defense/` directory is a standalone Python package
(`safety_kernel_defense`). Stdlib-only at runtime; no httpx / requests
deps. Publish via standard `build` + `twine`:

```bash
cd py-defense
python3 -m pip install --upgrade build twine
python3 -m build           # produces dist/safety_kernel_defense-*.{whl,tar.gz}
python3 -m twine check dist/*
python3 -m twine upload dist/*
```

The PyPI long-description is `py-defense/README.md` (referenced from
`pyproject.toml`'s `[project].readme` key).

## Versioning

All workspace crates share `version = "0.1.0"` (from
`[workspace.package].version` in the root `Cargo.toml`). Bump uniformly
when cutting a release. After bumping:

1. Update the version pin in each crate's internal `qorch-*` path
   dependencies (search for `version = "0.1.0"` and update).
2. Update `CHANGELOG.md` with the new version section.
3. Tag the release: `git tag v0.2.0 && git push origin v0.2.0`.
4. Republish in topological order (above).

## What's not publishable yet

Nothing's blocked. The above order works end-to-end as of the current
state (workspace passes `cargo check --workspace`; `qorch-domain` passes
`cargo publish --dry-run`).
