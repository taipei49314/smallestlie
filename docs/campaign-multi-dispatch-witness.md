# Portable multi-dispatch witness

`export_multi_dispatch_witness` takes the original frozen `PreparedRun` and
independently configured J, source and optional review authorities. It freshly
verifies their original immutable publications through the published J reader,
then copies the raw journal and its exact referenced artifact closure from that
same acquisition. It accepts no saved recording/report or caller acquisition
callback. There is no second GET of J between verification and copying.

The output is a plain directory containing `journal.jsonl`, `artifacts/<sha256>`,
`manifest.json` and a fixed `README.md`. Raw bytes are retained exactly. The
manifest contains their sizes and SHA-256 values, a complete ordered case roster,
an optional selected case, and unverified publication/location hints. It includes
no acceptance references, approval registry, source resolver or executable replay
helper. The manifest schema belongs to this container; original J is unchanged.

A selected D or control is only a view. Every case, control, raw review (including
explicit missing review refs), review validation, saved observation snapshot,
adjudicated row and final report remains in the bundle. Genuine kills and unknown
rows stay visible, with candidate and qualified paired counts kept separately.

`inspect_multi_dispatch_witness` returns `UnverifiedMultiDispatchWitness`, whose
`verification_status` is always `unverified`. It checks bounded native J syntax,
order, chain, the exact inventory and raw sizes/digests, plus structural case
identities and the same complete roster/denominator across saved payloads. It
does not GET sources,
recompute adjudication or construct accepted recording/observation objects.
All returned snapshots, reviews, rows, provenance, verdicts and counts are saved
claims. Coherently edited data can remain structurally consistent; consistency
does not establish authenticity or fresh source/human/semantic authority.
Online verification still needs the original independent authorities, external
J location and full frozen preparation. An offline object cannot supply them.

Both readers use the existing per-artifact byte bound; the complete bundle also
has the existing evidence file-count and total-byte bounds. Only the fixed files
and flat lowercase content-addressed artifact names are allowed. Duplicate,
missing, extra, linked, reparse, nested or special paths reject the bundle.
Hints reject unknown grant fields and boolean numeric identities.

Export requires a fresh output root and caller-controlled parents. All raw
contents are bounded before creation, written exclusively, synchronized and read
back; the manifest is written last and the completed tree is inspected again.
Interrupted output remains intact and cannot be overwritten or resumed. This is
not an OS isolation guarantee against hostile concurrent filesystem writers.
Windows directory-entry power-loss durability still requires separate host and
storage adoption; file synchronization alone does not supply that guarantee.

This cut does not activate legacy CLI run/replay/minimize gates, execute bundle
contents, publish J or change workloads, dependencies, runners, pins or catalogs.
Actual human Phase1, independent semantic approval, live publisher and runner/
collector/coordinator/storage adoption, formal W3 and full M12 D remain pending.

Validation is `NOT_RUN: POLICY work-machine-local`; source and synthetic tests
need a new exact-source pool authorization. PR40's grant covers only its frozen
published-reader source and cannot be reused for this witness change.
