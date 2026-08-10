# Threat Model

## Adversary modeled

An adversary with write access to repository-controlled surfaces who wants the repository to emit an accepting verdict without satisfying underlying truth conditions.

Capabilities in scope:

- Editing code, tests, evidence, manifests, workflows, config
- Reusing historical evidence
- Path/identity confusion inside the workspace
- Composition of individually low-impact mutations

Out of scope (not granted):

- Unrestricted host control
- Remote target selection
- Credential access / exfiltration
- Persistence / lateral movement
- External network access

## Assets protected

- Correctness of repository verdicts
- Evidence integrity and freshness
- Completeness of verification coverage
- Binding between source, artifact, execution, and verdict
- Authority to issue completion
- Auditability and replayability
- Fail-closed behavior

## Primary hostile objective

Cause `target_accepts = true` while `oracle_truth = false`.

## Containment

All mutations and executions occur in disposable workspaces under path guards, command allowlists, scrubbed environments, and network-denied policy.
