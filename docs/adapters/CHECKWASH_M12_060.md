# M12: migrate existing Checkwash W3 work to published v0.6.0

Status: PINNED / VALIDATION_PENDING. Formal W3: NOT_STARTED.

Nelson's exact instruction on 2026-10-06 Asia/Taipei is:

> 已發佈 套過去繼續

This is the one-time named grant to replace the SmallestLie Checkwash pin with
the newly published v0.6.0 release and continue the existing readiness work.
Earlier delegated ordinary merges remain applicable. The final human decision
to start formal W3 remains separate; final_start is null. This document does
not authenticate a Phase-1 merge, an external source adoption or a formal run.

## Published artifact and source provenance

| Fact | Immutable identity |
| --- | --- |
| Repository / release | taipei49314/checkwash; release 403905268 |
| Published at | 2026-10-05T16:14:38Z |
| Annotated tag | v0.6.0; tag object 64f62061996eca1e0830113e02e34a9484ce000b |
| Source commit | 8c70efbf93975bf3210acb8eafbaf4b38044a770 |
| Release asset | checkwash.pyz; asset 613073648; 655217 bytes |
| Downloaded artifact SHA-256 | 4f9c7b836d1e1c40dc0a7b88ef6d63f25d482c8eafda18c05eb5a4fbac9ad949 |
| SPEC Git blob / SHA-256 | 4f2650753b2887c6dd3c3cdaf3d47b1c7ead8f23 / ca1069c7e84e90142b144286476d6e1403aefef877b8864fc16a2e998259a3b1 |
| THREATMODEL Git blob / SHA-256 | 0055a4d91ad5fe5981e71f661d9d2f704db3cac3 / d4733228195f552baf690398298f5024d03c44dd329622768b26a85c14cf472c |
| Reviewed residual index SHA-256 | eff583bd2f0ef9e4e77527f410a07d5f35e16667f9e8ca21d4ce55ea292661aa |

The raw downloaded pyz SHA-256 agrees with GitHub's asset digest. Both source
snapshots were read at the exact release commit and retain their native Git
blob bytes. The annotated tag is unsigned; signature verification is not
claimed. The source/API observations and asset download are read-only.

## Reuse and new source epoch

Keep the six ordered W3 cases, their DEF/BND/CTL hypotheses, detectable cheating
controls, fixture variants, profiles, collector, locks and prepared runner
images. Keep the original 0.5.0 residual index, source snapshots and Phase-1
manifest as historical inputs. Their observations are not 0.6.0 results.

The new residual index remains partial. Row 108 describes the suite-wide
Mocha focus closure, row 117 includes pytestmark.append/extend/insert, and
row 109 retains subject-mock limitations. These source statements guide
reconciliation; they do not prove any W3 row's actual behavior. The existing
adjudicator retains execution-refuted DEF as killed_candidate and a valid
verifier block as attack_rejected, with effectiveness recorded separately.

A versioned results-free Phase-1 amendment will bind the same cases to the
new catalog, engine, residual sources and updated closed SmallestLie package.
The original f673f07110ba6e0b592e6e3ee1e69278ba05e731 Phase-1 merge and manifest
SHA-256 daf4497f252e141a5d13e2b1e8d461aa590b8089c3006b69703081b24c37c432
remain historical lineage. The new amendment requires its own actual approval
provenance; the old approval cannot authenticate changed source bytes.

## Catalog measurement after a re-pin

The structural catalog meter recognizes only the original W3 catalog at its
exact path/raw digest, together with the exact historical manifest, residual
index and both snapshots. It retains that input as NOT_MEASURED under the new
pin and excludes it from loaded count. The aggregate meter is MEASURED_WARN,
never PASS, when historical inputs are retained. A changed or renamed old
catalog and every malformed/current catalog still enter the unchanged loader
and fail normally. This exception authenticates retained source bytes only;
it supplies no approval, replay authority or case result.

## Validation

NOT_RUN：工作機規則（POLICY work-machine-local），本機只完成來源與發布
資產核對、文件及 pin 編輯；未執行 pyz、產品、測試、parser、編譯或 probe。

Required next evidence: SmallestLie PR CI for pin/adapter/residual/contract
regression; any HOST50 workload must use a separately accounted exact source
and immutable receipt. Checkwash's own release CI is not SmallestLie validation.
Formal six-case runner/verifier observations remain absent and must not be
borrowed from old rt4 runs or another fixture arm.