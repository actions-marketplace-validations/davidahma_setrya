#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python_bin="${SETRYA_PYTHON:-$(command -v python3)}"
[[ "$python_bin" = /* ]] || { echo 'Set SETRYA_PYTHON to an absolute interpreter path.' >&2; exit 2; }

if [[ "$(uname -s)" == Darwin ]]; then
  exec /usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network-outbound) (allow network-outbound (remote ip "localhost:*"))' \
    /bin/bash -c '"$1" scripts/verify-loopback.py && exec "$1" -m setrya qualify "${@:2}"' bash "$python_bin" "$@"
elif [[ "$(uname -s)" == Linux ]]; then
  namespace=(unshare --net)
  if [[ "$EUID" != 0 ]]; then namespace=(sudo -n "${namespace[@]}"); fi
  exec "${namespace[@]}" bash -c 'ip link set lo up && "$1" scripts/verify-loopback.py && exec "$1" -m setrya qualify "${@:2}"' bash "$python_bin" "$@"
else
  echo 'Offline qualification harness supports Darwin and Linux.' >&2
  exit 2
fi
