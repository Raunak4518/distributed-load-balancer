## Summary

<!-- What does this change do, and why? Link the issue it resolves (e.g. "Closes #123"). -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Tests / benchmarks only
- [ ] Documentation only
- [ ] Build / CI / maintenance

## How it was tested

<!-- Which tests cover this change? For a bug fix, confirm the new test fails without the fix. -->

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --features lb-core/test-util -- -D warnings` passes
- [ ] `cargo test --workspace --features lb-core/test-util` passes
- [ ] New or changed behavior has tests that fail without the change
- [ ] Anything a client can grow (maps, queues, buffers) is bounded
- [ ] New failure paths or state transitions record a metric
- [ ] Relevant pages under `docs/` are updated
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]` (user-visible changes only)
