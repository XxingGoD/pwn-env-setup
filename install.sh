#!/usr/bin/env bash
set -e
ROOT="$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")"
if (( EUID == 0 )) && [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
  target_uid="$(id -u -- "$SUDO_USER")" || exit 2
  if [[ "$target_uid" == 0 ]]; then echo 'SUDO_USER 必须是合法非 root 用户' >&2; exit 2; fi
  exec sudo -H -u "$SUDO_USER" -- bash "$ROOT/install.sh" "$@"
fi
if (( BASH_VERSINFO[0] < 4 )); then echo '需要 Bash 4+' >&2; exit 2; fi
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3,10))'; then
  echo '需要 Python 3.10+；Ubuntu: sudo apt install python3；Arch: sudo pacman -S python' >&2; exit 2
fi
export PYTHONPATH="$ROOT"
export PYTHONDONTWRITEBYTECODE=1
exec python3 -B -m pwn_env "$@"
