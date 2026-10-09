# Reconciler entry checklist — staged schema 7

Do not invoke `mas1_reconciler_sol` unless every applicable item is satisfied by the exact frozen contract packet.

- [ ] Task is the root, not a descendant split parent.
- [ ] Root is in the required reconciliation-pending state.
- [ ] Every accepted work, integration, and reconciliation-repair descendant is complete.
- [ ] Combined artifact, deterministic verification, coverage, and integration digests are durable.
- [ ] No owner or dispatch is active or uncertain.
- [ ] Greatest unique valid immutable TaskHead is bound.
- [ ] Contract 1.6.0/schema 7 and all eleven normative snapshots match bytes, lengths, hashes, domains, schemas, and versions.
- [ ] Closed packet has no missing, extra, reordered, stale, or unlisted source.
- [ ] ReconciliationBasis is hashed before EpochIdentity; no self or reverse dependency exists.
- [ ] Invocation uses a fresh context and unique review/context IDs.
- [ ] Invocation ordinal is correct: one assessment per invocation; ordinal one before ordinal two.
- [ ] All eight lanes occur once in exact order.
- [ ] Reconciler will emit candidate findings only and modify no files or ledgers.
- [ ] Coordinator and Judge persistence/disposition responsibilities are ready.
- [ ] The staged bundle's WIP status has not been mistaken for release authorization.
