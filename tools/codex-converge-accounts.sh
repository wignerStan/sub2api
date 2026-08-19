#!/usr/bin/env bash
# Set every OpenAI OAuth account to 设备+会话 and ensure a valid per-account seed.
# Usage:
#   tools/codex-converge-accounts.sh
#   tools/codex-converge-accounts.sh --rotate-seeds   # after cloning a DB onto a new deploy
set -euo pipefail

CONFIG="${SUB2API_CONFIG:-/opt/sub2api/data/config.yaml}"
ROTATE=0
if [[ "${1:-}" == "--rotate-seeds" ]]; then
  ROTATE=1
fi

python3 - "$CONFIG" "$ROTATE" <<'PY'
import os, re, subprocess, sys

config_path, rotate = sys.argv[1], sys.argv[2] == "1"
text = open(config_path, encoding="utf-8").read()
host = user = password = dbname = None
port = "5432"
section = None
for raw in text.splitlines():
    line = raw.split("#", 1)[0]
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
    key, val = m.group(1), m.group(2).strip().strip("'\"")
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
       WHEN extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
         AND extra->>'codex_fingerprint_seed' IS NOT NULL
       THEN '{}'::jsonb
       ELSE jsonb_build_object('codex_fingerprint_seed', gen_random_uuid()::text)
     END
)
WHERE platform = 'openai' AND type = 'oauth'
  AND COALESCE(extra->>'codex_fingerprint_mode', '') NOT IN ('device', 'session', 'full');
"""
rotate_sql = """
UPDATE accounts
SET extra = extra || jsonb_build_object('codex_fingerprint_seed', gen_random_uuid()::text)
WHERE platform = 'openai' AND type = 'oauth'
  AND COALESCE(extra->>'codex_fingerprint_mode', '') IN ('device', 'session', 'full');
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
