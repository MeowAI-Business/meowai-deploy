# Local Repair E2E

This fixture is intentionally local-only. It must use a temporary NewAPI
Compose project and a temporary downstream directory; it must never point at a
production source URL or target.

## Required assertions

For each scenario, capture the pre-repair observation fingerprint and the
following immutable facts: deployment id, PostgreSQL/Redis/data path identity,
and named-volume label/source fingerprints. Also capture the hash of
`data/state.json` as an operational-state marker. After repair, assert that the
deployment/data identities are unchanged; the state hash must remain unchanged
when the installation generation is unchanged, while a credential rotation is
expected to update it together with the generation and report/pull credential
hashes.

## Scenarios

1. Start an upstream NewAPI Compose project with explicit `SESSION_SECRET` and
   `CRYPTO_SECRET`, register a temporary downstream, and record a business
   row plus the admin identity.
2. Recreate the upstream container with a different crypto key. Run
   `repair --check`, then `repair --plan --json`, and finally the reviewed plan
   with `--yes --plan-fingerprint`. Assert generation advancement, preserved
   data identities, heartbeat/snapshot verification, and independent probe
   verification.
3. Remove a managed credential key and restart the local agent. Assert that
   B1 restores the complete env atomically and preserves the same data facts.
4. Remove the agent service/timer files. Assert that `repair_upgrade_agent`
   restores them and that a concurrent upgrade cannot acquire the target lock.
5. Interrupt the process during backup, target write, and after activation.
   Re-run the exact plan fingerprint and assert resume versus
   `failed_recoverable` semantics; never restore old credentials after
   activation.

The repository's fake target/updater tests cover the same transition boundaries
without Docker. A real Compose run is an operator acceptance test and must be
run only with disposable volumes and credentials.

## Automated Assertion

The disposable fixture should emit one redacted JSON snapshot before and after
each mutation. Validate the immutable deployment and data facts with:

```bash
scripts/assert-repair-e2e.sh before.json after.json 1
```

The snapshots must contain `deployment_id`, `installation_generation`,
`postgres_identity`, `redis_identity`, `newapi_data_identity`,
`kuma_data_identity`, `state_sha256`, `newapi_status_success`,
`postgres_select_1`, `redis_ping`, and `reporting_verified`. New fixtures
should also emit the boolean `public_probe_verified`; this is intentionally a
separate assertion because a local fixture may have healthy reporting but no
valid public HTTPS endpoint. Credentials and environment values must never be
placed in the snapshots.

The repository's fake target/updater executor tests cover the agent-missing
repair boundary (installer files, paused timer, and target-lock ownership),
while the source model tests cover prepare/activate/failed-recoverable resume
transitions. A disposable Compose run can combine those checks with a
controlled process termination at the backup, target-apply, and post-activation
journal points; after activation, the old credential must never be restored.
