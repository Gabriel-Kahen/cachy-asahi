# Migration-owned status integration correction

Original engine1368a1fa... is unchanged. The accepted Setup7 dependency d33c...
classifies a valid config-migration-v1 journal as unknown, then suggests setup
recover; setup recover --apply rejects the migration-prefixed identity. A real
tempfile reproduction is covered by test_delivery's genuine SIGKILL checkpoint:
activate old inert templates, kill migration after durable Fish replacement,
query setup status, attempt setup recover, then explicitly recover with the
migration CLI and original manifest/hash. The original handoff stays immutable.

The separate scripts/setup8/setup.py copy recognizes only a valid migration
header (schema/roots through the existing private loader, migration ID and raw
manifest digest). It reports migration-owned, can_resume:null and
validated_by_setup:false, with explicit migration status/recover guidance. It
does not replay, repair, discard or pretend to validate migration deltas. Invalid
headers remain unknown. Existing setup mutations continue refusing migration
journals. Existing manifest/configuration content is never printed.
