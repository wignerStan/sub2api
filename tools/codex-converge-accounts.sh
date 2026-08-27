#!/usr/bin/env bash
# Set every OpenAI OAuth account to 设备+会话 and ensure a valid per-account seed.
# Usage:
#   tools/codex-converge-accounts.sh
#   tools/codex-converge-accounts.sh --rotate-seeds   # after cloning a DB onto a new deploy
# Set CODEX_FINGERPRINT_DEPLOY_DOMAIN to a stable, deployment-unique DNS name
# in the server service. A cloned deployment must also rotate its copied seeds.
set -euo pipefail

CONFIG="${SUB2API_CONFIG:-/opt/sub2api/data/config.yaml}"
ROTATE=0
if [[ "${1:-}" == "--rotate-seeds" ]]; then
  ROTATE=1
fi

python3 - "$CONFIG" "$ROTATE" <<'PY'
import json, os, re, subprocess, sys

def strip_yaml_comment(raw):
    quote = None
    escaped = False
    for idx, char in enumerate(raw):
        if quote == '"':
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quote = None
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char == '#' and (idx == 0 or raw[idx - 1].isspace()):
            return raw[:idx]
    return raw

def parse_yaml_scalar(raw):
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return json.loads(value)
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    return value

config_path, rotate = sys.argv[1], sys.argv[2] == "1"
text = open(config_path, encoding="utf-8").read()
host = user = password = dbname = None
port = "5432"
section = None
for raw in text.splitlines():
    line = strip_yaml_comment(raw)
    if re.match(r"^\s*database\s*:", line) and "{" not in line:
        section = "database"
        continue
    if section == "database" and re.match(r"^\S", line) and not line.startswith(" "):
        if not line.strip().startswith("database"):
            section = None
    if section != "database":
        continue
    m = re.match(r"\s*(host|port|user|password|name|dbname)\s*:\s*(.+)$", line)
    if not m:
        continue
    key, val = m.group(1), parse_yaml_scalar(m.group(2))
    if key in ("name", "dbname"):
        dbname = val
    elif key == "host":
        host = val
    elif key == "port":
        port = val
    elif key == "user":
        user = val
    elif key == "password":
        password = val

if not user or not dbname:
    raise SystemExit(f"failed to parse database user/name from {config_path}")

os.environ["PGPASSWORD"] = password or ""
psql = [
    "psql", "-h", host or "127.0.0.1", "-p", str(port),
    "-U", user or "sub2api", "-d", dbname or "sub2api", "-v", "ON_ERROR_STOP=1",
]

converge = """
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
  AND platform = 'openai' AND type = 'oauth'
  AND (
    COALESCE(extra->>'codex_fingerprint_mode', '') NOT IN ('session')
    OR extra->>'codex_fingerprint_seed' IS NULL
    OR btrim(extra->>'codex_fingerprint_seed') = ''
    OR NOT (
      extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
    )
  );
"""
rotate_sql = """
UPDATE accounts
SET extra = extra || jsonb_build_object('codex_fingerprint_seed', gen_random_uuid()::text)
WHERE deleted_at IS NULL
  AND platform = 'openai' AND type = 'oauth';
"""
count = """
SELECT
  COALESCE(extra->>'codex_fingerprint_mode', '(unset)') AS mode,
  COUNT(*)
FROM accounts
WHERE platform = 'openai' AND type = 'oauth'
GROUP BY 1
ORDER BY 2 DESC;
"""
print(subprocess.check_output(psql + ["-c", converge], text=True))
if rotate:
    print(subprocess.check_output(psql + ["-c", rotate_sql], text=True))
print(subprocess.check_output(psql + ["-c", count], text=True))
PY
