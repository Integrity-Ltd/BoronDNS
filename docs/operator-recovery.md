# Recover retained campaign and packaging state

This reference is for maintainers running test campaigns or package builders.
Ordinary DNS service recovery is covered in the
[operator guide](operator-deployment-guide.md#restart-upgrade-and-recover).

## Why a completed job can leave files behind

Campaign helpers assume another process with the campaign UID may rename
entries in a user-writable directory. When they cannot prove that recursive
deletion is safe, they move the exact object to a unique, no-replace quarantine
and report it. Names such as `*.borondns-remove.*` are retained state, not
active campaign generations.

A later run uses fresh names. It does not adopt an older journal as authority
to delete, overwrite, restore, or promote files. Do not delete hidden paths
solely because their names resemble a completed campaign.

## Reconcile a retained object

1. Retain the helper's diagnostic output and journal mapping separately from
   the campaign-writable directory.
2. Establish a privileged or dedicated-UID namespace that the campaign UID
   cannot mutate, including through previously opened directory descriptors.
3. Verify both the current parent and the object against their recorded
   device, inode, owner, and type. A path match alone is insufficient.
4. If either identity differs, preserve the current path as foreign state and
   locate the recorded inode separately.
5. After both identities match, inspect the retained content, then archive or
   remove it from the protected namespace.

Using sudo on a campaign-owned tree does not by itself establish namespace
authority. Root ownership is also insufficient when a recursive directory
boundary is group/world-writable or has a POSIX access ACL. Until the namespace
can be protected and validated, retain the object.

## Publication-recovery records

Package builders apply the same quarantine policy to private run roots,
rollback outputs, and prior artifact backups. Their diagnostics identify the
retained object and its immediate parent using `device:inode:owner:type`.

| Journal field | Meaning |
| --- | --- |
| `retained_removal_quarantine_N` | Recorded retained path. |
| `retained_removal_quarantine_N_identity` | Captured object identity. |
| `retained_removal_quarantine_N_parent` | Recorded parent path. |
| `retained_removal_quarantine_N_parent_identity` | Captured parent identity. |
| `publication_recovery_root_identity` | Identity of the original private run root. |
| `publication_recovery_root_binding=journal-parent-directory` | The journal's current parent is the root binding. |
| Indexed `_root_relative` and `_parent_root_relative` | Paths to resolve beneath that validated root. |

A successful same-process cleanup retry may move the whole run root into a
terminal quarantine. In that case, verify the journal's current parent against
`publication_recovery_root_identity` before resolving the relative fields.
The original absolute paths remain historical evidence.

If post-move identity cannot be validated, the diagnostic reports an
`unverified parent namespace`, not a verified retained inode. Failed diagnostic
writes may leave `.publication-recovery-incomplete-*` files under the private
run root. Treat those files as evidence, not as active or trusted recovery
journals.

SBOM generation quarantines fixed cargo-cyclonedx outputs under the locked Git
metadata root so they do not dirty later source verification. If that move
would cross filesystems, the source path is retained; the helper does not copy
and then unlink it.

## Two-host cleanup journals

Fuzz and large-surface cleanup write
`.borondns-retained-cleanup-<root>.<pid>.<nonce>.env` before removing the
canonical name. Each retry creates a new journal rather than replacing an older
mapping.

| Phase | Interpretation |
| --- | --- |
| `phase=prepared` | The rename may have happened before the process stopped. Reconcile identities before deciding. |
| `phase=retained` | The completed journal records the retained object. |

Both phases contain original/quarantine paths and parent/target identity
triples. Source the authenticated campaign helper and run
`campaign_verify_retained_cleanup_journal <journal>` before inspection.
It binds a real non-symlink parent directory and resolves names relative to
that open directory. It rejects an existing original name, changed parent,
wrong type, or forged sibling inode.

`cleanup_prepared_verified` means the original is absent and the exact recorded
quarantine exists. It reconciles crash evidence; it grants no deletion
authority. The verifier does not delete, and a campaign-writable journal must
not become the sole basis for a destructive action.

## Bounded discovery failures

Automatic-tree recovery and stale-status discovery enumerate direct children
under an absolute CLOCK_BOOTTIME deadline. They retain state and return nonzero
when the deadline expires or the directory exceeds
`BORONDNS_CAMPAIGN_ENUMERATION_ENTRY_CAP` (default 4096, range 1–65536).

Inspect unexpectedly crowded directories before retrying. Increasing the cap
changes the bounded scan/sort allowance; it does not grant recovery or deletion
authority.
