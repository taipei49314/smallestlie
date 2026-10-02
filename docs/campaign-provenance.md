# Formal campaign governance provenance (M12 D1)

`GitHubPreregistrationAuthority` implements the existing preregistration
authority using independent GitHub approval sources. A configured caller can
pass it to `prepare_run()`. It has no automatic CLI activation, trust-root
discovery, or fallback to a declaration. The v2 campaign gates remain closed.

The governance process supplies a `GovernanceTrustRoot`: separate product and
request-governance repository identities, exact numeric repository IDs,
approved destination branches and allowed **human numeric merger IDs** for each
role, plus exact `HumanMergeApproval` records from a separately trusted human
input or governance process. Each approval binds repository ID, PR number,
merge SHA, merger ID and the independent human approval reference. Configure
these outside the product checkout, runner workspace and replay
bundle. A caller-supplied root is an integration trust boundary, not a claim
that arbitrary Python callers are isolated. No repository/user is implicitly
trusted. GitHub's `User` account type cannot distinguish a person from an agent
using that person's PAT. The external approval registry must attest the actual
required human approval/merge; it cannot be generated merely by discovering a
merged PR or reading a product-written record. This module checks the exact
registry grant against GitHub and retains its reference; authenticating the
human input channel is the trusted caller's responsibility. Missing registry
approval fails closed even for an allowed User account.

A private governance repository needs an explicitly supplied read-only
GitHub credential; the transport does not discover tokens in product files or
environment variables.

An authorization reference is a PR and path:

```
github-pr://OWNER/GOVERNANCE_REPO/123/requests/formal-run.json
```

The PR number can exist before the request is written. Its record contains the
full `RunRequest.payload()` and a Phase-1 PR reference, avoiding a request digest
that must include the commit containing itself:

```json
{
  "schema_version": "smallestlie.governance-request/v1",
  "kind": "formal-run-authorization",
  "request": {
    "campaign_id": "W3",
    "request_id": "formal-request-id",
    "run_id": "formal-run-id",
    "phase1_commit": "EXACT_HUMAN_MERGED_PHASE1_COMMIT",
    "source_commit": "EXACT_AUTHORIZED_EXECUTION_SOURCE",
    "manifest_sha256": "RAW_PHASE1_MANIFEST_SHA256",
    "authorization_ref": "github-pr://OWNER/GOVERNANCE_REPO/123/requests/formal-run.json"
  },
  "phase1": {
    "pull_request": 456,
    "manifest_path": "campaigns/W3/manifest.json"
  }
}
```

This is a shape illustration, not an actual approval or runnable request.
Creating or merging such a governance record still requires the relevant human
authorization; this code grants none and writes nothing to GitHub.

For each role, the store requires GitHub's merged PR state, exact destination
repository ID/name/branch and an allowed merger with `type=User`. Login strings,
commit authors, timestamps and record fields such as `approved=true` cannot
authorize. It resolves the PR's exact merge commit and traverses nonrecursive
Git trees without following branch names, response URLs, symlinks or submodules.
The selected regular blob must be an added/modified file approved in that PR,
with the same blob SHA at the merge commit. An unrelated later PR cannot lend
its merger identity to an inherited record. Complete changed-file enumeration
is required; incomplete or oversized API responses fail closed.

The reader checks the raw decoded bytes against the blob size and Git object
SHA-1, and hashes those bytes with SHA-256. It preserves CRLF and invalid text
bytes at the blob layer; UTF-8 JSON parsing is a separate strict step. Both the
approved request and the raw Phase-1 manifest must match the formal request.
`prepare_run()` then retains responsibility for clean exact source, ancestry,
complete frozen assets, published engine pin and every case/twin binding.

Production reads use only GET at `https://api.github.com`, with bounded responses
and timeouts. Redirects and API errors fail closed without returning credential
or response-body details. Transport injection is for configured integration and
synthetic tests, never a value loaded from a manifest or receipt. See GitHub's
[PR API](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request),
[tree API](https://docs.github.com/en/rest/git/trees) and
[raw blob contract](https://docs.github.com/en/rest/git/blobs#get-a-blob).

This subcut authenticates **preregistration approval only**. It does not prove
an actual EC dispatch, job host, lock-before-command, runner exit, effective
verifier configuration or semantic review. Execution/verifier/review providers
remain unconfigured until separate trustworthy supervisor and human-review
sources are implemented. Their missing provenance continues to produce unknown.
Ordinary pool regression receipts cannot stand in for formal W3 receipts.

Subsequent D work must add raw capture and actual facts, formal ledger/campaign
ordering, complete-case second-pass adjudication, reports and evidence replay.
No formal W3 result, runner adoption, engine re-pin or product merge is performed
by this change. Synthetic API tests exercise identity/role/request mismatches,
raw-byte corruption, inherited approvals and API failure; they mint no real
approval and make no network calls.
