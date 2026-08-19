-- Converge ALL OpenAI OAuth accounts to session mode with a valid seed.
-- Unlike 225 (which only seeded rows already in device|session|full), this
-- covers unset / empty / off / illegal modes so client IDs cannot passthrough.
-- Idempotent: valid canonical seeds are preserved; already-session rows with
-- a valid seed are no-ops.

UPDATE accounts
SET extra = (
    COALESCE(extra, '{}'::jsonb)
    || jsonb_build_object('codex_fingerprint_mode', 'session')
    || CASE
        WHEN extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND extra->>'codex_fingerprint_seed' IS NOT NULL
          AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
        THEN '{}'::jsonb
        ELSE jsonb_build_object('codex_fingerprint_seed', gen_random_uuid()::text)
       END
)
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type = 'oauth'
  AND (
      COALESCE(extra->>'codex_fingerprint_mode', '') NOT IN ('session')
      OR extra->>'codex_fingerprint_seed' IS NULL
      OR btrim(extra->>'codex_fingerprint_seed') = ''
      OR NOT (
          extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
      )
  );
