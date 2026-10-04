# Immutable multi-dispatch J source

`verify_published_multi_dispatch_recording` reads one externally accepted J
publication through a separately configured exact `EcReceiptStore`. Its
`MultiDispatchRecordingLocation` pins the raw journal path and SHA-256 and the
content-addressed artifacts prefix. J and F use separate publication registries;
the existing duplicate request/lock prohibition is retained.

Invalid paths and raw digest declarations at this configuration boundary raise
`ProvenanceError` (a `PreregistrationError`), preserving the underlying lexical
`DeclarationError` as the cause. Rejected traversal stays rejected; callers can
handle both lexical and role separation failures through the same public error
family.

The reader calls the fresh original class implementation of `EcReceiptStore.read`,
which verifies immutable Git bytes, the complete publication inventory and J's
own run/attempt/job, source, workflow, collector, host, generation and workload
pins. J may have a different accepted dispatch from F and may share its EC code
pin. No outer supervisor is requested; outer success/failure/cancellation/timeout
is not a native action fact or semantic approval.

The filesystem reader and published reader share one private raw verifier. It
checks the externally addressed complete journal, reads the original reviews,
reacquires source and review authorities, reruns the existing adjudication
calculation and compares the whole journal and every artifact byte for byte.
There is no second replay engine, new journal schema or saved PASS authority.
The dedicated J artifacts prefix must contain exactly the referenced artifacts;
missing review refs stay explicit, while missing required artifacts reject J.
Other receipt files remain authenticated by the exact EC inventory.

J cannot reuse a known product/Phase1/anchor/F/map/action/admission/EC-source/
human/review input commit as its output. Configured roles are checked before
acquisition; fresh full snapshot roles also include unobserved recorded receipt
claims. Repository names and known numeric identities separate J from product,
request and review repositories. J may use the same EC repository as F, with a
separate output commit. Publication acceptance cannot lend source, human or
semantic approval. Imported J/source/review configuration is checked for changes
during acquisition; instance reader hooks and returned carriers grant nothing.
The explicitly configured transport retains its existing trust boundary.

A matching J can preserve unknown rows, missing sources/reviews, genuine DEF
refutations, and separate candidate/qualified paired headline counts. An old
closed J fails fresh verification if its sources or independent review grants
change. Publication acceptance does not promote unknown evidence to confirmed.

This API performs GETs and computations only. It writes no local recording,
launches no work, creates no tickets, and appends no F/coordinator/legacy journal.
Portable witnesses and public verify/report integration remain later cuts;
legacy run/replay/minimize gates remain closed under their existing contracts.
Actual human Phase1, semantic approval, runner/collector/coordinator/storage
adoption, live J publisher admission, formal W3 and full M12 D remain unfinished.

Validation is `NOT_RUN: POLICY work-machine-local`; this source requires a new
exact-source pool authorization. PR39's single grant does not cover this change.
