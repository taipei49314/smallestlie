# Security

## Design invariants

1. **Containment first** — no attack power without demonstrated isolation
2. **Disposable execution** — source repos are never mutated in place
3. **Fail-closed** — unknown state never becomes acceptance
4. **Command allowlist** — attack YAML cannot inject arbitrary shell
5. **No secrets** — real credentials must not enter sandboxes
6. **Independent oracle** — target verdict is never ground truth

## Reporting

If you discover a containment escape (path escape, network under denied policy, source mutation, secret leakage), treat it as a critical harness defect and report it to the project owner before using that path for attack development.

## Scope disclaimer

SmallestLie does not claim to make repositories secure. A campaign that finds no false acceptance only supports the bounded observation that none was observed under the declared catalog, seed, oracle, and policy.
