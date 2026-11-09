#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == --containers ]]; then
  docker run --rm -v "$ROOT:/src:ro" ubuntu:22.04 bash /src/tests/container-install.sh ubuntu22.04
  docker run --rm -v "$ROOT:/src:ro" ubuntu:24.04 bash /src/tests/container-install.sh ubuntu24.04
  docker run --rm -v "$ROOT:/src:ro" archlinux:base-devel bash /src/tests/container-install.sh arch
  exit 0
fi
if [[ "$#" -ne 0 ]]; then echo '用法：tests/smoke.sh [--containers]' >&2; exit 2; fi
cd "$ROOT"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
for platform in ubuntu22.04 ubuntu24.04 arch; do
  home="$(mktemp -d)"
  HOME="$home" PYTHONDONTWRITEBYTECODE=1 bash install.sh --all --dry-run --platform "$platform" --prefix "$home/pwn-env"
  rm -rf -- "$home"
done
