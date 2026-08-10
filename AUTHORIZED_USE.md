# Authorized Use

SmallestLie is an **authorized adversarial verification harness**.

## Allowed targets

A target is eligible only when at least one is true:

1. A synthetic fixture shipped with SmallestLie
2. A local repository owned by the operator (Nelson)
3. A target containing an explicit authorization file accepted by policy
4. An allowlisted local path confirmed through configuration
5. A disposable clone created from an owned repository

## Forbidden targets

SmallestLie must refuse:

- Public IP addresses and arbitrary domains
- Remote hosts and unowned repositories
- Package registries as live targets
- Production deployments
- Shared corporate environments without explicit authorization
- Home directories or filesystem roots as targets
- Paths outside the configured workspace
- Targets that cannot be copied into a disposable workspace

## Network

Default: **denied**. External egress is never enabled by attack manifests.

## Operator obligation

You may only run campaigns against repositories and fixtures you own or are explicitly authorized to test. Misuse against third-party systems is out of scope and forbidden by design.
