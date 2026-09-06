# Release Candidate Readiness

Use this checklist when preparing the next release. It is a procedure, not a
claim that the current checkout has passed. The filename retains the older
`engineering-mvp` name for script compatibility.

1. Run `scripts/check.sh` against the candidate commit and retain the result.
2. Run `scripts/engineering-mvp-evidence.sh` when a bounded local preflight
   profile is needed. Review its `deferred-not-run.txt` before treating the
   snapshot as evidence for a particular claim.
3. Select focused interoperability, fuzz, resource, and performance checks for
   the changes. Review failures and explain reuse of earlier evidence.
4. Rehearse packaging with `scripts/release-preflight-container.sh` from a clean,
   committed checkout. This includes installation and upgrade/removal checks.
5. Check user-facing changes, configuration examples, compatibility, and release
   notes. Resolve release blockers or explicitly record the release decision.
6. Create the signed tag only after the pre-tag checks pass. The hosted workflow
   builds, checks packages, signs the checksum manifest, and publishes artifacts;
   it does not run the full local quality gate.

This checklist does not itself establish `BDS-VER-008` milestone acceptance. The
[acceptance register](release-acceptance-gap-register.md) and
[verification ledger](verification-ledger.md) record remaining SRS acceptance
gaps and the evidence supporting each release.

Do not call the release candidate ready if a required check fails, a claimed
result has no retained evidence, or a release-blocking finding is unresolved.
Missing optional review or unselected long-running work is not a failure by
itself; it must not be reported as passed.

## Reference Documents

| Question | Reference |
| --- | --- |
| What is in the product? | `docs/engineering-mvp-scope.md`; `docs/implemented-feature-scope.md` |
| Which commands collect evidence? | `docs/evidence-command-catalog.md` |
| What remains open? | `docs/release-acceptance-gap-register.md` |
| What comes next? | `docs/implementation-plan.md` |
| Are startup instructions accurate? | `docs/operator-deployment-guide.md`; `config/borondns.example.toml` |
