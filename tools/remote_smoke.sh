#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: expected Linux RBE worker, got $(uname -s)" >&2
  exit 1
fi
echo "remote_smoke: kernel=$(uname -s) machine=$(uname -m) hostname=$(hostname)"
